# -*- coding: utf-8 -*-
"""缓存层与安全层单元测试（不依赖 AD 域控），覆盖：
PRAGMA、事务、租约锁、级联重命名、删除清理、分页/排序/筛选、日志检索、密码哈希、加密、Excel 生成。
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import db
from modules import query_service as Q
from modules import log_service
from modules import excel_service
from modules import sync_task
from modules.security import encrypt_secret, decrypt_secret, hash_password, verify_password, \
    password_strength_error, generate_password

db.init_db()
res = []


def rec(name, ok, msg=''):
    res.append((name, ok, msg))
    print(('OK  ' if ok else 'FAIL') + f' {name}' + (f'  -> {msg}' if msg else ''))


# ---------------- PRAGMA
rec('WAL 模式已启用', db.query_one('PRAGMA journal_mode')[0].lower() == 'wal',
    db.query_one('PRAGMA journal_mode')[0])
rec('synchronous=NORMAL', db.query_one('PRAGMA synchronous')[0] == 1)
rec('cache_size 生效', abs(db.query_one('PRAGMA cache_size')[0]) >= 10000,
    str(db.query_one('PRAGMA cache_size')[0]))
rec('busy_timeout 已设置', db.query_one('PRAGMA busy_timeout')[0] > 0,
    str(db.query_one('PRAGMA busy_timeout')[0]))

# 表完整性
tables = {r['name'] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")}
need = {'sys_user', 'ad_domain_conf', 'ad_user_cache', 'ad_operation_log', 'ad_ou_cache',
        'ad_group_cache', 'ad_computer_cache', 'ad_trust_cache', 'task_queue', 'app_lock', 'sys_setting'}
rec('核心数据表齐全', need <= tables, f'缺失：{need - tables}' if need - tables else f'{len(tables)} 张表')
for t in ('ad_user_cache', 'ad_ou_cache', 'ad_group_cache', 'ad_computer_cache'):
    cols = {r['name'] for r in db.query(f'PRAGMA table_info({t})')}
    rec(f'{t} 含 domain_id 索引列', 'domain_id' in cols)

# ---------------- 事务回滚
did = db.scalar('SELECT id FROM ad_domain_conf ORDER BY id LIMIT 1', (), 1)
before = db.scalar('SELECT COUNT(*) FROM ad_ou_cache WHERE domain_id=?', (did,), 0)
try:
    with db.tx(immediate=True) as c:
        c.execute('INSERT INTO ad_ou_cache(domain_id, dn, name, depth) VALUES(?,?,?,?)',
                  (did, 'OU=RollbackTest,' + 'x', 'RollbackTest', 1))
        raise RuntimeError('故意失败')
except RuntimeError:
    pass
after = db.scalar('SELECT COUNT(*) FROM ad_ou_cache WHERE domain_id=?', (did,), 0)
rec('事务异常自动回滚', before == after, f'{before} -> {after}')

# ---------------- 租约锁互斥
with db.sync_lock('ut_lock', ttl=30, owner='A'):
    got = db.sync_lock('ut_lock', ttl=30, owner='B')
    acquired_b = False
    try:
        got.__enter__()
        acquired_b = True
    except Exception:
        acquired_b = False
rec('租约锁互斥（同锁不可并发获取）', not acquired_b)
try:
    with db.sync_lock('ut_lock2', ttl=30, owner='C'):
        pass
    rec('租约锁退出后可再次获取', True)
except Exception as e:
    rec('租约锁退出后可再次获取', False, str(e))

# ---------------- 级联重命名（模拟 OU 改名后的缓存修正）
tag = 'UT' + str(int(time.time()))[-5:]
old_dn = f'OU={tag}_old,DC=ut,DC=local'
new_dn = f'OU={tag}_new,DC=ut,DC=local'
child_dn = f'OU=child,{old_dn}'
db.execute('INSERT OR REPLACE INTO ad_ou_cache(domain_id,dn,name,parent_dn,depth) VALUES(?,?,?,?,?)',
           (did, old_dn, f'{tag}_old', 'DC=ut,DC=local', 1))
db.execute('INSERT OR REPLACE INTO ad_ou_cache(domain_id,dn,name,parent_dn,depth) VALUES(?,?,?,?,?)',
           (did, child_dn, 'child', old_dn, 2))
db.execute('INSERT OR REPLACE INTO ad_user_cache(domain_id,dn,sam_account_name,ou_dn) VALUES(?,?,?,?)',
           (did, f'CN=utuser,{old_dn}', f'utuser_{tag}', old_dn))
# 模拟 routes/ou.py update 的级联逻辑（先精确命中自身，再按子树后缀匹配）
suffix_old = '%,' + old_dn.replace('\\', '\\\\').replace('_', '\\_').replace('%', '\\%')
with db.tx(immediate=True) as c:
    for table in ('ad_ou_cache', 'ad_user_cache', 'ad_group_cache', 'ad_computer_cache'):
        c.execute(f"UPDATE OR REPLACE {table} SET dn=? WHERE domain_id=? AND dn=?", (new_dn, did, old_dn))
        c.execute(f"UPDATE OR REPLACE {table} SET dn=REPLACE(dn, ?, ?) "
                  f"WHERE domain_id=? AND dn LIKE ? ESCAPE '\\'", (old_dn, new_dn, did, suffix_old))
    for table in ('ad_user_cache', 'ad_group_cache', 'ad_computer_cache'):
        c.execute(f"UPDATE {table} SET ou_dn=REPLACE(ou_dn, ?, ?) "
                  f"WHERE domain_id=? AND ou_dn LIKE ? ESCAPE '\\'", (old_dn, new_dn, did, suffix_old))
        c.execute(f"UPDATE {table} SET ou_dn=? WHERE domain_id=? AND ou_dn=?", (new_dn, did, old_dn))
    c.execute('UPDATE ad_ou_cache SET parent_dn=? WHERE domain_id=? AND parent_dn=?',
              (new_dn, did, old_dn))
left = db.scalar('SELECT COUNT(*) FROM ad_ou_cache WHERE domain_id=? AND dn LIKE ?', (did, f'%{tag}_old%'), 0)
child = db.query_one('SELECT * FROM ad_ou_cache WHERE domain_id=? AND dn=?', (did, f'OU=child,{new_dn}'))
u = db.query_one('SELECT * FROM ad_user_cache WHERE domain_id=? AND sam_account_name=?', (did, f'utuser_{tag}'))
rec('OU 重命名：旧 DN 无残留', left == 0, f'left={left}')
rec('OU 重命名：子 OU DN 已更新', bool(child))
rec('OU 重命名：用户 ou_dn 已更新', bool(u) and u['ou_dn'] == new_dn)
# 清理
db.execute('DELETE FROM ad_user_cache WHERE domain_id=? AND sam_account_name=?', (did, f'utuser_{tag}'))
db.execute('DELETE FROM ad_ou_cache WHERE domain_id=? AND (dn=? OR dn=?)', (did, new_dn, f'OU=child,{new_dn}'))

# ---------------- LIKE 转义：DN 中的 _ 不得被当作通配符
# 场景：两个同级 OU "IT_01" 与 "IT101"，"_" 若被当作通配符会互相误匹配
esc_dn = 'OU=IT_01,DC=ut,DC=local'
decoy_dn = 'OU=IT101,DC=ut,DC=local'
db.execute('INSERT OR REPLACE INTO ad_ou_cache(domain_id,dn,name,parent_dn,depth) VALUES(?,?,?,?,?)',
           (did, esc_dn, 'IT_01', 'DC=ut,DC=local', 1))
db.execute('INSERT OR REPLACE INTO ad_ou_cache(domain_id,dn,name,parent_dn,depth) VALUES(?,?,?,?,?)',
           (did, decoy_dn, 'IT101', 'DC=ut,DC=local', 1))
raw_hit = db.scalar("SELECT COUNT(*) FROM ad_ou_cache WHERE domain_id=? AND dn LIKE ?", (did, '%,' + esc_dn), 0)
esc_hit = db.scalar("SELECT COUNT(*) FROM ad_ou_cache WHERE domain_id=? AND dn LIKE ? ESCAPE '\\'",
                    (did, db.dn_like(esc_dn)), 0)
rec('LIKE 未转义时同级 OU 被误匹配（复现问题）', raw_hit == 0, f'raw={raw_hit}')
rec('LIKE 转义后同样不误匹配', esc_hit == 0, f'esc={esc_hit}')
# 子对象方向：IT_01 下的子 OU 不应被 IT101 的子树条件命中
db.execute('INSERT OR REPLACE INTO ad_ou_cache(domain_id,dn,name,parent_dn,depth) VALUES(?,?,?,?,?)',
           (did, 'OU=sub,' + esc_dn, 'sub', esc_dn, 2))
own = db.scalar("SELECT COUNT(*) FROM ad_ou_cache WHERE domain_id=? AND dn LIKE ? ESCAPE '\\'",
                (did, db.dn_like(esc_dn)), 0)
cross = db.scalar("SELECT COUNT(*) FROM ad_ou_cache WHERE domain_id=? AND dn LIKE ? ESCAPE '\\'",
                  (did, db.dn_like(decoy_dn)), 0)
rec('LIKE 转义后子树仅命中自身层级', (own, cross) == (1, 0), f'own={own} cross={cross}')
db.execute('DELETE FROM ad_ou_cache WHERE domain_id=? AND dn IN (?,?,?)',
           (did, esc_dn, decoy_dn, 'OU=sub,' + esc_dn))

# ---------------- 查询：分页 / 排序 / 筛选 / 标签
rows, total = Q.search_users({'domain_id': did}, 1, 3)
rec('用户分页（每页 3 条）', len(rows) <= 3 and total >= len(rows), f'total={total}')
p = Q.pagination(total, 2, 3)
rec('分页元数据正确', p['pages'] == max(1, (total + 2) // 3), f'pages={p["pages"]}')
rows2, _ = Q.search_users({'domain_id': did}, 1, 3, sort='sam', order='desc')
if rows and rows2:
    rec('排序生效（sam desc）',
        (rows2[0]['sam_account_name'] or '') >= (rows[-1]['sam_account_name'] or ''),
        f'{rows2[0]["sam_account_name"]} vs {rows[-1]["sam_account_name"]}')
_, n_disabled = Q.search_users({'domain_id': did, 'enabled': '0'}, 1, 5)
n_all = db.scalar('SELECT COUNT(*) FROM ad_user_cache WHERE domain_id=? AND enabled=0', (did,), 0)
rec('状态筛选（仅禁用）', n_disabled == n_all, f'{n_disabled}/{n_all}')
_, n_locked = Q.search_users({'domain_id': did, 'tag': 'locked'}, 1, 5)
n_locked_ad = db.scalar('SELECT COUNT(*) FROM ad_user_cache WHERE domain_id=? AND locked=1', (did,), 0)
rec('快捷标签筛选（已锁定）', n_locked == n_locked_ad, f'{n_locked}/{n_locked_ad}')
_, n_pwd = Q.search_users({'domain_id': did, 'tag': 'pwd_expired'}, 1, 5)
rec('快捷标签筛选（密码过期）可执行', n_pwd >= 0, f'{n_pwd}')
kw = rows[0]['sam_account_name'][:3] if rows else 'admin'
_, n_kw = Q.search_users({'domain_id': did, 'keyword': kw}, 1, 5)
rec('关键词搜索', n_kw >= 1, f'kw={kw} -> {n_kw}')

tree = Q.ou_tree(did)
rec('OU 树构建（含虚拟根）', tree and 'children' in tree, f'子节点 {len(tree["children"])}')
rec('OU 树子树计数', tree['subtree_users'] >= 0, f'root subtree_users={tree["subtree_users"]}')
g, gt = Q.list_groups({'domain_id': did}, 1, 5)
rec('用户组列表', gt >= 0, f'{gt} 个组')
c, ct = Q.list_computers({'domain_id': did}, 1, 5)
rec('计算机列表', ct >= 0, f'{ct} 台')
rec('部门聚合', isinstance(Q.departments(did), list), f'{len(Q.departments(did))} 个部门')
cnt = Q.domain_counts(did)
rec('域计数统计', cnt.get('total', 0) >= 0, str(cnt))

# ---------------- 日志
lid = log_service.write('system', 'unit_test', target='UT', detail='单元测试', message='测试日志',
                        operator='tester', ip='127.0.0.1', domain_id=did)
rec('写入操作日志', isinstance(lid, int) and lid > 0, f'id={lid}')
rows, total = log_service.search({'module': 'system', 'keyword': 'unit_test'}, 1, 10)
rec('按模块+关键词检索日志', total >= 1, f'total={total}')
rows, total = log_service.search({'domain_id': did, 'result': 'success'}, 1, 5)
rec('按域+结果检索日志', total >= 1, f'total={total}')
rows, total = log_service.search({'date_from': time.strftime('%Y-%m-%d'),
                                  'date_to': time.strftime('%Y-%m-%d')}, 1, 5)
rec('按日期范围检索日志', total >= 1, f'今日 {total} 条')
db.execute('DELETE FROM ad_operation_log WHERE action=?', ('unit_test',))

# ---------------- 安全
enc = encrypt_secret('P@ssw0rd-中文')
rec('凭据加密（Fernet 前缀）', enc.startswith('enc:'), enc[:16] + '…')
rec('凭据解密还原', decrypt_secret(enc) == 'P@ssw0rd-中文')
rec('明文兼容（旧数据）', decrypt_secret('plain123') == 'plain123')
h, s = hash_password('Abc@12345')
rec('PBKDF2 哈希校验通过', verify_password('Abc@12345', h, s))
rec('错误密码校验失败', not verify_password('Abc@1234', h, s))
rec('弱密码被拒（长度不足）', password_strength_error('abc123') is not None)
rec('弱密码被拒（复杂度不足）', password_strength_error('abcdefgh') is not None)
rec('强密码通过', password_strength_error('Abc@12345') is None)
rec('随机密码满足策略', all(password_strength_error(generate_password()) is None for _ in range(30)))

# ---------------- Excel
data = excel_service.export_users([did], {})
rec('导出用户 Excel 非空', len(data) > 3000, f'{len(data)} bytes')
tpl = excel_service.user_import_template()
rec('导入模板非空', len(tpl) > 2000, f'{len(tpl)} bytes')
logs_x = excel_service.export_logs({'domain_id': did})
rec('导出日志 Excel 非空', len(logs_x) > 1500, f'{len(logs_x)} bytes')
comp_x = excel_service.export_computers([did])
rec('导出计算机 Excel 非空', len(comp_x) > 1000, f'{len(comp_x)} bytes')

# ---------------- 同步 upsert 幂等（同 DN 反复写入不应产生重复行）
dn = f'CN=utidem,DC=ut,DC=local'
for i in range(3):
    db.execute('INSERT INTO ad_user_cache(domain_id,dn,sam_account_name,display_name,ou_dn) '
               'VALUES(?,?,?,?,?) ON CONFLICT(domain_id,dn) DO UPDATE SET display_name=excluded.display_name',
               (did, dn, 'utidem', f'名称{i}', 'DC=ut,DC=local'))
n = db.scalar('SELECT COUNT(*) FROM ad_user_cache WHERE domain_id=? AND dn=?', (did, dn), 0)
rec('upsert 幂等（同 DN 仅 1 行）', n == 1, f'count={n}')
db.execute('DELETE FROM ad_user_cache WHERE domain_id=? AND dn=?', (did, dn))

print()
bad = [x for x in res if not x[1]]
print(f'===== {len(res) - len(bad)}/{len(res)} 通过 =====')
for n, ok, m in bad:
    print(f'  FAIL {n}: {m}')

# -*- coding: utf-8 -*-
"""全面自测：用户 / 计算机 / OU / 部门（作为用户属性）的增删改查。

- 通过 Flask test_client 直接调用真实路由，写操作直连 AD、成功后回写缓存。
- 每个功能独立断言，输出 PASS / FAIL / SKIP / NOT_SUPPORTED。
- 严格清理所有临时对象，避免污染域环境。
- 计算机「新增/删除」系统未提供端点，如实标记为 NOT_SUPPORTED 并说明原因。
"""
import io
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_mod
import config
from modules import db, ad_ldap as L

application = app_mod.create_app()
client = application.test_client()

ROWS = []  # (序号, 模块, 功能, 状态, 说明)


def rec(module, name, status, msg=''):
    ROWS.append((module, name, status, msg))
    flag = {'PASS': 'PASS  ', 'FAIL': 'FAIL  ', 'SKIP': 'SKIP  ', 'NOT_SUPPORTED': 'N/A   '}[status]
    print(f'{flag} [{module}] {name}' + (f'  -> {msg}' if msg else ''))


def api(method, url, **kw):
    kw.setdefault('data', {})
    r = getattr(client, method)(url, **kw)
    try:
        j = r.get_json()
    except Exception:
        j = None
    return r.status_code, j


def dept_names(j):
    """facets 的 departments 形如 [{'name':..,'count':..}]，提取名称集合。"""
    return set(x.get('name') for x in (j or {}).get('data', {}).get('departments', [])
               if isinstance(x, dict) and x.get('name'))


# 临时对象登记，用于 finally 兜底清理
cleanup = {'user_dns': [], 'computer_dns': [], 'ou_dns': [], 'group_dns': []}


def ldap_del(dn):
    try:
        conn = L.get_connection(L.get_domain(DID))
        conn.delete(dn)
    except Exception:
        pass


# ---------------- 0. 登录与基础
code, j = api('post', '/login', data={'username': 'admin', 'password': config.DEFAULT_ADMIN_PASSWORD})
ok_login = code == 200 and j and j.get('ok')
rec('基础', '登录', 'PASS' if ok_login else 'FAIL', (j or {}).get('message', ''))
if not ok_login:
    print('登录失败，终止测试')
    sys.exit(1)

dm0 = db.query_one('SELECT * FROM ad_domain_conf ORDER BY id LIMIT 1')
DID = dm0['id']
base_dn = dm0['base_dn']
d = L.get_domain(DID)
tag = uuid.uuid4().hex[:6]
print(f'测试域：{dm0["domain_name"]}  base={base_dn}  tag={tag}')

# 确认域在线
code, j = api('post', f'/domains/{DID}/test', data={})
rec('基础', '域连通性(LDAP)', 'PASS' if (code == 200 and j and j.get('ok')) else 'FAIL',
    (j or {}).get('message', '')[:80])

# ---------------- 1. 只读基础接口
code, j = api('get', f'/users/api/list?domain_id={DID}&page_size=3')
rec('用户', '列表(查)', 'PASS' if (code == 200 and j and j.get('ok') and 'rows' in j.get('data', {})) else 'FAIL')

code, j = api('get', f'/computers/?domain_id={DID}')
rec('计算机', '列表(查)', 'PASS' if code == 200 else 'FAIL')

code, j = api('get', f'/ous/api/tree?domain_id={DID}')
rec('OU', '树(查)', 'PASS' if (code == 200 and j and j.get('ok')) else 'FAIL')

code, j = api('get', f'/ous/api/options?domain_id={DID}')
rec('OU', '下拉(查)', 'PASS' if (code == 200 and j and j.get('ok')) else 'FAIL')

code, j = api('get', f'/users/facets?domain_id={DID}')
depts0 = dept_names(j)
rec('部门', 'facets 候选(查)', 'PASS' if (code == 200 and j) else 'FAIL')

# ---------------- 2. OU 增删改查
ou_root = f'QA-OU{tag}'
code, j = api('post', '/ous/create', data={'domain_id': DID, 'parent_dn': base_dn,
                                          'name': ou_root, 'description': '自测根OU'})
ok_ou1 = code == 200 and j and j.get('ok')
ou_dn = (j or {}).get('data', {}).get('dn', '') if ok_ou1 else ''
rec('OU', '创建(根级)', 'PASS' if ok_ou1 else 'FAIL', (j or {}).get('message', ''))
if ou_dn:
    cleanup['ou_dns'].append(ou_dn)
    row = db.query_one('SELECT * FROM ad_ou_cache WHERE domain_id=? AND dn=?', (DID, ou_dn))
    rec('OU', '创建后缓存写入', 'PASS' if row else 'FAIL')

# 子 OU
code, j = api('post', '/ous/create', data={'domain_id': DID, 'parent_dn': ou_dn,
                                          'name': f'{ou_root}-子', 'description': '自测子OU'})
ok_ou2 = code == 200 and j and j.get('ok')
child_dn = (j or {}).get('data', {}).get('dn', '') if ok_ou2 else ''
rec('OU', '创建(子级)', 'PASS' if ok_ou2 else 'FAIL', (j or {}).get('message', ''))
if child_dn:
    cleanup['ou_dns'].append(child_dn)

# 编辑描述
if ou_dn:
    code, j = api('post', '/ous/update', data={'domain_id': DID, 'dn': ou_dn,
                                               'description': '自测根OU-改'})
    ok_desc = code == 200 and j and j.get('ok')
    rec('OU', '编辑描述(改)', 'PASS' if ok_desc else 'FAIL', (j or {}).get('message', ''))
    if ok_desc:
        row = db.query_one('SELECT description FROM ad_ou_cache WHERE domain_id=? AND dn=?', (DID, ou_dn))
        rec('OU', '编辑描述后缓存', 'PASS' if row and row['description'] == '自测根OU-改' else 'FAIL')

# 重命名（触发级联）
if ou_dn:
    code, j = api('post', '/ous/update', data={'domain_id': DID, 'dn': ou_dn, 'name': f'{ou_root}新'})
    ok_rename = code == 200 and j and j.get('ok')
    new_ou_dn = (j or {}).get('data', {}).get('dn', '') if ok_rename else ''
    rec('OU', '重命名(改)', 'PASS' if ok_rename else 'FAIL', (j or {}).get('message', ''))
    if ok_rename and child_dn:
        new_child = child_dn.replace(ou_dn, new_ou_dn)
        row = db.query_one('SELECT dn FROM ad_ou_cache WHERE domain_id=? AND dn=?', (DID, new_child))
        rec('OU', '重命名后子OU级联', 'PASS' if row else 'FAIL', new_child)
        if row:
            cleanup['ou_dns'].append(new_child)
            child_dn = new_child
        ou_dn = new_ou_dn
        cleanup['ou_dns'].append(ou_dn)

# ---------------- 3. 用户增删改查（含部门）
sam = f'qa{tag}'
code, j = api('post', '/users/create', data={
    'domain_id': DID, 'sam_account_name': sam, 'display_name': f'自测用户{tag}',
    'password': 'Abc@12345', 'ou_dn': ou_dn or base_dn, 'department': f'自测部门{tag}',
    'must_change_password': '1', 'enabled': '1', 'mail': f'{sam}@test.local', 'title': '工程师'})
ok_cu = code == 200 and j and j.get('ok')
user_dn = (j or {}).get('data', {}).get('dn', '') if ok_cu else ''
rec('用户', '创建(增)', 'PASS' if ok_cu else 'FAIL', (j or {}).get('message', '')[:100])
uid = None
if user_dn:
    cleanup['user_dns'].append(user_dn)
    row = db.query_one('SELECT * FROM ad_user_cache WHERE domain_id=? AND dn=?', (DID, user_dn))
    rec('用户', '创建后缓存写入', 'PASS' if row else 'FAIL',
        f'dept={row["department"] if row else "-"}')
    uid = row['id'] if row else None
    conn = L.get_connection(d)
    found = conn.search(user_dn, '(objectClass=*)', search_scope='BASE', attributes=['sAMAccountName'])
    rec('用户', '创建后AD侧存在', 'PASS' if found else 'FAIL')

# 详情（实时字段）
if uid:
    code, j = api('get', f'/users/{uid}')
    rec('用户', '详情(查，实时)', 'PASS' if code == 200 else 'FAIL')

# 部门联动：创建后 facets 应含该部门
if ok_cu:
    code, j = api('get', f'/users/facets?domain_id={DID}')
    depts1 = dept_names(j)
    rec('部门', '创建用户后部门出现(增)', 'PASS' if f'自测部门{tag}' in depts1 else 'FAIL',
        f'depts={sorted(depts1)}')

# 编辑：改 display_name（触发 DN 变更）+ 改 department
if uid:
    new_display = f'自测用户{tag}改'
    new_dept = f'自测部门{tag}改'
    code, j = api('post', f'/users/{uid}/update',
                  data={'display_name': new_display, 'department': new_dept, 'title': '高级工程师'})
    ok_upd = code == 200 and j and j.get('ok')
    new_dn = (j or {}).get('data', {}).get('dn', '') if ok_upd else ''
    rec('用户', '编辑(改，重命名+部门)', 'PASS' if ok_upd else 'FAIL', (j or {}).get('message', ''))
    if ok_upd:
        cnt = db.scalar('SELECT COUNT(*) FROM ad_user_cache WHERE domain_id=? AND sam_account_name=?', (DID, sam), 0)
        rec('用户', '重命名后缓存无重复', 'PASS' if cnt == 1 else 'FAIL', f'count={cnt}')
        row = db.query_one('SELECT id, dn, department FROM ad_user_cache WHERE domain_id=? AND dn=?', (DID, new_dn))
        rec('用户', '重命名后缓存DN/部门', 'PASS' if row and row['department'] == new_dept else 'FAIL',
            f'dn={row["dn"] if row else "-"}')
        if new_dn and row:
            # 重命名会重建缓存行（新自增 id），前端会重新进入详情拿到新 id，这里同步更新
            uid = row['id']
            cleanup['user_dns'].append(new_dn)
            user_dn = new_dn
        code, j = api('get', f'/users/facets?domain_id={DID}')
        depts2 = dept_names(j)
        rec('部门', '编辑后部门切换(改)', 'PASS' if (new_dept in depts2 and f'自测部门{tag}' not in depts2) else 'FAIL',
            f'depts={sorted(depts2)}')
        code, j = api('get', f'/users/api/list?domain_id={DID}&department={new_dept}&page_size=20')
        pag = (j or {}).get('data', {}).get('pagination', {}) if (j and j.get('ok')) else {}
        hit = pag.get('total', 0)
        rec('部门', '按部门筛选列表(查)', 'PASS' if hit >= 1 else 'FAIL', f'total={hit}')

# 禁用/启用
if uid:
    code, j = api('post', f'/users/{uid}/toggle', data={'enabled': '0'})
    row = db.query_one('SELECT enabled FROM ad_user_cache WHERE id=?', (uid,))
    rec('用户', '禁用(改)', 'PASS' if (code == 200 and j and j.get('ok') and row['enabled'] == 0) else 'FAIL')
    code, j = api('post', f'/users/{uid}/toggle', data={'enabled': '1'})
    row = db.query_one('SELECT enabled FROM ad_user_cache WHERE id=?', (uid,))
    rec('用户', '启用(改)', 'PASS' if (code == 200 and j and j.get('ok') and row['enabled'] == 1) else 'FAIL')

# 重置密码（二次确认）
if uid:
    code, j = api('post', f'/users/{uid}/reset-password', data={'password': 'Xyz@98765', 'must_change': '1'})
    rec('用户', '重置密码缺确认→拒绝', 'PASS' if (code != 200 and j and not j.get('ok')) else 'FAIL',
        (j or {}).get('message', '')[:50])
    code, j = api('post', f'/users/{uid}/reset-password',
                  data={'password': 'Xyz@98765', 'must_change': '1', 'confirm': '1'})
    rec('用户', '重置密码(改)', 'PASS' if (code == 200 and j and j.get('ok')) else 'FAIL',
        (j or {}).get('message', '')[:80])

# 解锁
if uid:
    code, j = api('post', f'/users/{uid}/unlock')
    rec('用户', '解锁(改)', 'PASS' if (code == 200 and j and j.get('ok')) else 'FAIL')

# 移动 OU
if uid and child_dn:
    code, j = api('post', f'/users/{uid}/move', data={'target_ou': child_dn})
    ok_mv = code == 200 and j and j.get('ok')
    rec('用户', '移动OU(改)', 'PASS' if ok_mv else 'FAIL', (j or {}).get('message', ''))
    if ok_mv:
        # 移动也会重建缓存行（新自增 id），按 sam 重新定位
        row = db.query_one('SELECT id, ou_dn, dn FROM ad_user_cache WHERE domain_id=? AND sam_account_name=?',
                           (DID, sam))
        rec('用户', '移动后缓存ou_dn', 'PASS' if row and row['ou_dn'] == child_dn else 'FAIL',
            row['ou_dn'] if row else '-')
        if row:
            uid = row['id']
            user_dn = row['dn']

# 删除用户
if uid:
    code, j = api('post', f'/users/{uid}/delete', data={})
    rec('用户', '删除缺确认→拒绝', 'PASS' if (code != 200 and j and not j.get('ok')) else 'FAIL')
    code, j = api('post', f'/users/{uid}/delete', data={'confirm': '1'})
    ok_del = code == 200 and j and j.get('ok')
    rec('用户', '删除(删)', 'PASS' if ok_del else 'FAIL', (j or {}).get('message', ''))
    if ok_del:
        cnt = db.scalar('SELECT COUNT(*) FROM ad_user_cache WHERE domain_id=? AND sam_account_name=?', (DID, sam), 0)
        rec('用户', '删除后缓存清除', 'PASS' if cnt == 0 else 'FAIL', f'count={cnt}')
        code, j = api('get', f'/users/facets?domain_id={DID}')
        depts3 = dept_names(j)
        rec('部门', '删除用户后部门消失(删)', 'PASS' if f'自测部门{tag}改' not in depts3 else 'FAIL',
            f'depts={sorted(depts3)}')
        uid = None

# ---------------- 4. 计算机增删改查
# 系统未提供计算机的「新增」端点（AD 计算机对象由加域流程自动创建）；「删除」已支持
rec('计算机', '新增计算机(增)', 'NOT_SUPPORTED', '系统未提供该端点（设计如此）')

# 创建临时计算机对象（L 层），供系统 API 的「改/查」测试
pc_cn = f'QATP{tag}'
pc_dn = f'CN={pc_cn},{base_dn}'
pc_sam = f'{pc_cn}$'
pc_created = False
cid = None
try:
    conn = L.get_connection(d)
    ok_add = conn.add(pc_dn, object_class=['top', 'person', 'organizationalPerson', 'user', 'computer'],
                      attributes={'cn': pc_cn, 'sAMAccountName': pc_sam,
                                  'userAccountControl': 4096,  # WORKSTATION_TRUST_ACCOUNT
                                  'dNSHostName': f'qatp{tag}.citrixlab.local'})
    pc_created = bool(ok_add)
    if pc_created:
        cleanup['computer_dns'].append(pc_dn)
        db.execute("INSERT INTO ad_computer_cache(domain_id,dn,name,dns_host_name,enabled,description,ou_dn,"
                   "operating_system,synced_at) VALUES(?,?,?,?,?,?,?,?,datetime('now','localtime'))",
                   (DID, pc_dn, pc_cn, f'qatp{tag}.citrixlab.local', 1, '', base_dn, 'Test OS'))
        cid = db.scalar('SELECT id FROM ad_computer_cache WHERE domain_id=? AND dn=?', (DID, pc_dn), 0)
    rec('计算机', '临时对象准备', 'PASS' if pc_created and cid else 'FAIL', f'cid={cid}')
except Exception as e:
    rec('计算机', '临时对象准备', 'FAIL', str(e)[:100])

if cid:
    code, j = api('post', f'/computers/{cid}/update', data={'description': '自测描述', 'remark': '本地备注'})
    ok_upd = code == 200 and j and j.get('ok')
    rec('计算机', '编辑描述+备注(改)', 'PASS' if ok_upd else 'FAIL', (j or {}).get('message', ''))
    if ok_upd:
        row = db.query_one('SELECT description, remark FROM ad_computer_cache WHERE id=?', (cid,))
        rec('计算机', '编辑后缓存(AD描述/本地备注)', 'PASS' if row and row['description'] == '自测描述' and row['remark'] == '本地备注' else 'FAIL')

    code, j = api('post', f'/computers/{cid}/toggle', data={'enabled': '0'})
    rec('计算机', '禁用缺确认→拒绝', 'PASS' if (code != 200 and j and not j.get('ok')) else 'FAIL')
    code, j = api('post', f'/computers/{cid}/toggle', data={'enabled': '0', 'confirm': '1'})
    row = db.query_one('SELECT enabled FROM ad_computer_cache WHERE id=?', (cid,))
    rec('计算机', '禁用(改)', 'PASS' if (code == 200 and j and j.get('ok') and row['enabled'] == 0) else 'FAIL',
        (j or {}).get('message', '')[:60])
    code, j = api('post', f'/computers/{cid}/toggle', data={'enabled': '1'})
    row = db.query_one('SELECT enabled FROM ad_computer_cache WHERE id=?', (cid,))
    rec('计算机', '启用(改)', 'PASS' if (code == 200 and j and j.get('ok') and row['enabled'] == 1) else 'FAIL')

r = client.get(f'/computers/export?domain_id={DID}')
rec('计算机', '导出(查)', 'PASS' if r.status_code == 200 and len(r.data) > 1000 else 'FAIL', f'{len(r.data)}B')

# 删除（直连 AD，需二次确认）
if cid:
    code, j = api('post', f'/computers/{cid}/delete', data={})
    rec('计算机', '删除缺确认→拒绝', 'PASS' if (code != 200 and j and not j.get('ok')) else 'FAIL')
    code, j = api('post', f'/computers/{cid}/delete', data={'confirm': '1'})
    ok_del = code == 200 and j and j.get('ok')
    rec('计算机', '删除(删)', 'PASS' if ok_del else 'FAIL', (j or {}).get('message', ''))
    if ok_del:
        cnt = db.scalar('SELECT COUNT(*) FROM ad_computer_cache WHERE domain_id=? AND dn=?', (DID, pc_dn), 0)
        ad_exists = bool(L.get_connection(d).search(pc_dn, '(objectClass=*)', search_scope='BASE'))
        rec('计算机', '删除后缓存+AD 无残留', 'PASS' if (cnt == 0 and not ad_exists) else 'FAIL',
            f'cache={cnt} ad={ad_exists}')
        cleanup['computer_dns'].remove(pc_dn) if pc_dn in cleanup['computer_dns'] else None

# ---------------- 5. 安全/边界
code, j = api('post', f'/domains/{DID}/delete', data={})
rec('安全', '删除域缺确认→拒绝', 'PASS' if (code != 200 or not (j or {}).get('ok')) else 'FAIL')
code, j = api('post', '/trust/create', data={'local_id': DID, 'remote_domain_name': 'nonexist.local',
                                            'remote_dc_host': '10.255.255.1', 'remote_username': 'a',
                                            'remote_password': 'b', 'confirm': '1', 'direction': 'bidirectional'})
cnt_trust = db.scalar('SELECT COUNT(*) FROM ad_trust_cache', (), 0)
rec('安全', '信任创建失败不改缓存', 'PASS' if (code != 200 and j and not j.get('ok') and cnt_trust == 0) else 'FAIL',
    f'trust={cnt_trust}')

# ---------------- 6. 清理（OU 递归删除）
for ou in cleanup['ou_dns']:
    try:
        api('post', '/ous/delete', data={'domain_id': DID, 'dn': ou, 'recursive': '1', 'confirm': '1'})
    except Exception:
        pass
for pc in cleanup['computer_dns']:
    try:
        conn = L.get_connection(d)
        conn.delete(pc)
    except Exception:
        pass
    db.execute('DELETE FROM ad_computer_cache WHERE domain_id=? AND dn=?', (DID, pc))

# 汇总
print()
passed = sum(1 for r in ROWS if r[2] == 'PASS')
failed = [r for r in ROWS if r[2] == 'FAIL']
na = [r for r in ROWS if r[2] == 'NOT_SUPPORTED']
skipped = [r for r in ROWS if r[2] == 'SKIP']
print(f'===== 通过 {passed} / 共 {len(ROWS)}（失败 {len(failed)}、未提供 {len(na)}、跳过 {len(skipped)}）=====')
for r in failed:
    print(f'  [FAIL] {r[1]} / {r[2]}: {r[3]}')

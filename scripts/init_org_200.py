# -*- coding: utf-8 -*-
"""组织架构批量初始化：按公司部门/层级建立 OU，并批量创建 200 个用户 + 200 个计算机账户。

设计要点：
1. 两棵 OU 树挂在域根下：
   - OU=员工    （用户树，部门下可再分团队）
   - OU=计算机  （计算机树，与部门一一对应）
2. 用户命名规范：sAMAccountName = <部门英文缩写><2位序号>（全小写、唯一）；
   displayName/CN = <部门中文名>-<2位序号>；UPN/mail = <sAMAccountName>@域名。
3. 初始密码统一 Citrix@2026（满足复杂度），首次登录强制改密。
4. 计算机命名规范：CN/名称 = PC-<缩写>-<2位序号>；sAMAccountName 加 $ 后缀；
   dNSHostName = <小写名>.<域名>。
5. 写操作直连 AD，完成后做一次全量同步把对象刷入缓存并核对计数。
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import db, ad_ldap as L, sync_task

DID = db.scalar('SELECT id FROM ad_domain_conf ORDER BY id LIMIT 1', (), 1)
d = L.get_domain(DID)
BASE = d.base_dn
DOMAIN = d.domain_name
COMPANY = 'Citrix 科技有限公司'
INIT_PWD = 'Citrix@2026'

# 部门：(中文名, 英文缩写, 用户数, 计算机数, 是否技术部门)
# 信息技术部的用户与计算机由其下属团队承接，故本级数量为 0
DEPTS = [
    ('总经办', 'gm', 8, 5, False),
    ('人力资源部', 'hr', 10, 8, False),
    ('财务部', 'fin', 12, 10, False),
    ('行政部', 'adm', 9, 6, False),
    ('法务部', 'legal', 5, 3, False),
    ('采购部', 'pur', 7, 5, False),
    ('市场部', 'mkt', 14, 12, False),
    ('销售部', 'sales', 22, 25, False),
    ('客服部', 'cs', 14, 15, False),
    ('运营部', 'ops', 11, 10, False),
    ('产品部', 'pd', 14, 12, True),
    ('信息技术部', 'it', 0, 0, True),
    ('研发中心', 'rd', 16, 20, True),
    ('生产部', 'prod', 7, 8, False),
    ('仓储部', 'wh', 5, 5, False),
    ('质量部', 'qa', 7, 5, True),
    ('安全合规部', 'sec', 5, 3, False),
]

# 信息技术部下属团队：(中文名, 缩写, 用户数, 计算机数)
IT_TEAMS = [
    ('架构组', 'arch', 6, 8),
    ('研发组', 'rnd', 18, 25),
    ('运维组', 'sre', 10, 15),
]

USERS_ROOT = f'OU=员工,{BASE}'
COMPUTERS_ROOT = f'OU=计算机,{BASE}'


def title_for(abbr, idx, is_tech):
    if idx == 1:
        return '部门经理'
    if idx == 2:
        return '副经理'
    return '工程师' if is_tech else '专员'


def create_ou(parent, name, desc=''):
    dn = f'OU={name},{parent}'
    if db.query_one('SELECT 1 FROM ad_ou_cache WHERE domain_id=? AND dn=?', (DID, dn)):
        return dn, False
    L.create_ou(d, parent, name, desc)
    return dn, True


def main():
    t0 = time.time()
    ou_created, user_ok, user_fail, pc_ok, pc_fail = 0, 0, 0, 0, 0
    fail_log = []
    conn = L.get_connection(d)

    # ---------- 1. 创建 OU 树 ----------
    create_ou(BASE, '员工', '全司员工用户根')
    create_ou(BASE, '计算机', '全司计算机账户根')
    ou_created += 2
    for name, abbr, uc, pc, is_tech in DEPTS:
        dn, created = create_ou(USERS_ROOT, name, f'{name} 用户')
        ou_created += created
        create_ou(COMPUTERS_ROOT, name, f'{name} 计算机')
        ou_created += created
    for tname, tabbr, tuc, tpc in IT_TEAMS:
        _, created = create_ou(f'OU=信息技术部,{USERS_ROOT}', tname, f'{tname} 用户')
        ou_created += created
        create_ou(f'OU=信息技术部,{COMPUTERS_ROOT}', tname, f'{tname} 计算机')
        ou_created += created
    print(f'[OU] 已建立 {ou_created} 个新 OU（含员工/计算机两棵树）')

    # ---------- 2. 创建 200 用户 ----------
    def make_users(abbr, dept_name, ou_dn, count, is_tech):
        nonlocal user_ok, user_fail
        for i in range(1, count + 1):
            sam = f'{abbr}{i:02d}'
            try:
                L.create_user(d, {
                    'sam_account_name': sam,
                    'display_name': f'{dept_name}-{i:02d}',
                    'password': INIT_PWD,
                    'ou_dn': ou_dn,
                    'must_change_password': True,
                    'enabled': True,
                    'mail': f'{sam}@{DOMAIN}',
                    'title': title_for(abbr, i, is_tech),
                    'department': dept_name,
                    'company': COMPANY,
                    'description': '批量初始化',
                })
                user_ok += 1
            except Exception as e:
                user_fail += 1
                fail_log.append(f'用户 {sam}: {e}')

    for name, abbr, uc, pc, is_tech in DEPTS:
        if uc:
            make_users(abbr, name, f'OU={name},{USERS_ROOT}', uc, is_tech)
    for tname, tabbr, tuc, tpc in IT_TEAMS:
        make_users(tabbr, tname, f'OU={tname},OU=信息技术部,{USERS_ROOT}', tuc, True)
    print(f'[用户] 成功 {user_ok} / 失败 {user_fail}')

    # ---------- 3. 创建 200 计算机 ----------
    def make_computers(abbr, dept_name, ou_dn, count):
        nonlocal pc_ok, pc_fail
        for i in range(1, count + 1):
            pc_name = f'PC-{abbr.upper()}-{i:02d}'
            pc_dn = f'CN={pc_name},{ou_dn}'
            try:
                ok = conn.add(pc_dn,
                              object_class=['top', 'person', 'organizationalPerson', 'user', 'computer'],
                              attributes={
                                  'cn': pc_name,
                                  'sAMAccountName': f'{pc_name}$',
                                  'userAccountControl': 4096,  # WORKSTATION_TRUST_ACCOUNT
                                  'dNSHostName': f'{pc_name.lower()}.{DOMAIN}',
                                  'description': f'{dept_name} 计算机',
                                  'operatingSystem': 'Windows 11 Pro',
                              })
                if not ok:
                    raise RuntimeError(str(conn.result))
                pc_ok += 1
            except Exception as e:
                pc_fail += 1
                fail_log.append(f'计算机 {pc_name}: {e}')

    for name, abbr, uc, pc, is_tech in DEPTS:
        if pc:
            make_computers(abbr, name, f'OU={name},{COMPUTERS_ROOT}', pc)
    for tname, tabbr, tuc, tpc in IT_TEAMS:
        make_computers(tabbr, tname, f'OU={tname},OU=信息技术部,{COMPUTERS_ROOT}', tpc)
    print(f'[计算机] 成功 {pc_ok} / 失败 {pc_fail}')

    # ---------- 4. 全量同步 + 核对 ----------
    print('[同步] 执行全量同步...')
    res = sync_task.sync_one(DID, kind='full', operator='init')
    print(f'[同步] {res.get("ok")} {res.get("message")}')

    n_user = db.scalar('SELECT COUNT(*) FROM ad_user_cache WHERE domain_id=? AND company=?', (DID, COMPANY), 0)
    n_pc = db.scalar("SELECT COUNT(*) FROM ad_computer_cache WHERE domain_id=? AND dn LIKE 'CN=PC-%'", (DID,), 0)
    print(f'[核对] 用户(company={COMPANY}) = {n_user}；计算机(PC-*) = {n_pc}')

    print()
    print(f'===== 完成：OU +{ou_created}，用户 {user_ok}/{user_ok+user_fail}，计算机 {pc_ok}/{pc_ok+pc_fail}，'
          f'耗时 {int(time.time()-t0)}s =====')
    if fail_log:
        print('失败明细（前 20 条）：')
        for s in fail_log[:20]:
            print('  -', s)


if __name__ == '__main__':
    main()

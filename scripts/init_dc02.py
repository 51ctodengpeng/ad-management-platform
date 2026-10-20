# -*- coding: utf-8 -*-
"""DC02 组织架构初始化：按「中心 → 部门」两级建立 OU，批量创建 200 个用户。

与 DC01（citrixlab.local 平铺部门）刻意差异化：
- 一级为中心（挂域根），二级为部门/组（挂中心下）。
- 命名规范同 DC01：sAMAccountName=<英文缩写><2位序号>，displayName=<部门名>-NN，
  UPN/mail=<sam>@citrixlab02.local，初始密码 Citrix@2026 首次登录改密。
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules import db, ad_ldap as L, sync_task

DID = db.scalar("SELECT id FROM ad_domain_conf WHERE domain_name='citrixlab02.local' ORDER BY id LIMIT 1", (), 0)
if not DID:
    print('未找到 DC02 域（citrixlab02.local），请先在「多域管理」中添加')
    sys.exit(1)
d = L.get_domain(DID)
BASE = d.base_dn
DOMAIN = d.domain_name
COMPANY = 'Citrix 科技（第二事业部）'
INIT_PWD = 'Citrix@2026'

# 一级部门（直接挂域根）
TOP_DEPTS = [('总裁办', 'ceo', 6, False)]

# 中心 → 部门（两级）
CENTERS = [
    ('产品中心', [('产品部', 'prd', 14, True), ('设计部', 'dsn', 8, True)]),
    ('技术中心', [('前端组', 'fe', 20, True), ('后端组', 'be', 25, True),
                  ('运维组', 'opm', 12, True), ('测试组', 'tst', 13, True)]),
    ('市场中心', [('市场部', 'mktg', 12, False), ('品牌部', 'brd', 6, False)]),
    ('销售中心', [('销售一部', 's01', 15, False), ('销售二部', 's02', 15, False)]),
    ('交付中心', [('实施部', 'imp', 12, False), ('售后部', 'svc', 10, False)]),
    ('职能中心', [('人力资源部', 'hr', 8, False), ('财务部', 'fin', 10, False),
                  ('行政部', 'adm', 6, False), ('法务部', 'lg', 4, False), ('采购部', 'pr', 4, False)]),
]


def title_for(idx, is_tech):
    if idx == 1:
        return '中心总监' if False else '部门经理'
    if idx == 2:
        return '副经理'
    return '工程师' if is_tech else '专员'


def main():
    t0 = time.time()
    ou_created = user_ok = user_fail = 0
    fail_log = []

    # 1) 一级部门 + 中心 OU + 部门 OU
    for name, abbr, uc, is_tech in TOP_DEPTS:
        dn = f'OU={name},{BASE}'
        if not db.query_one('SELECT 1 FROM ad_ou_cache WHERE domain_id=? AND dn=?', (DID, dn)):
            L.create_ou(d, BASE, name, f'{name}（第二事业部）')
            ou_created += 1
    for cname, depts in CENTERS:
        cdn = f'OU={cname},{BASE}'
        if not db.query_one('SELECT 1 FROM ad_ou_cache WHERE domain_id=? AND dn=?', (DID, cdn)):
            L.create_ou(d, BASE, cname, f'{cname}（第二事业部）')
            ou_created += 1
        for dept, abbr, uc, is_tech in depts:
            ddn = f'OU={dept},{cdn}'
            if not db.query_one('SELECT 1 FROM ad_ou_cache WHERE domain_id=? AND dn=?', (DID, ddn)):
                L.create_ou(d, cdn, dept, f'{dept} 用户')
                ou_created += 1
    print(f'[OU] 新建 {ou_created} 个 OU')

    # 2) 创建用户
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
                    'title': title_for(i, is_tech),
                    'department': dept_name,
                    'company': COMPANY,
                    'description': 'DC02 批量初始化',
                })
                user_ok += 1
            except Exception as e:
                user_fail += 1
                fail_log.append(f'{sam}: {e}')

    for name, abbr, uc, is_tech in TOP_DEPTS:
        make_users(abbr, name, f'OU={name},{BASE}', uc, is_tech)
    for cname, depts in CENTERS:
        for dept, abbr, uc, is_tech in depts:
            make_users(abbr, dept, f'OU={dept},OU={cname},{BASE}', uc, is_tech)
    print(f'[用户] 成功 {user_ok} / 失败 {user_fail}')

    # 3) 全量同步 + 核对
    res = sync_task.sync_one(DID, kind='full', operator='init')
    print(f'[同步] {res.get("ok")} {res.get("message")}')
    n = db.scalar('SELECT COUNT(*) FROM ad_user_cache WHERE domain_id=? AND company=?', (DID, COMPANY), 0)
    print(f'[核对] DC02 用户({COMPANY}) = {n}')
    print(f'===== 完成：OU +{ou_created}，用户 {user_ok}/{user_ok+user_fail}，耗时 {int(time.time()-t0)}s =====')
    if fail_log:
        print('失败明细：')
        for s in fail_log[:20]:
            print('  -', s)


if __name__ == '__main__':
    main()

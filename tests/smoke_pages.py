# -*- coding: utf-8 -*-
"""页面级冒烟测试：登录后逐个 GET 所有页面，检查 HTTP 200 与关键内容。"""
import os
import sys
import re

os.environ.setdefault('ADM_HOST', '127.0.0.1')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_mod
import config
from modules import db, ad_ldap as L

application = app_mod.create_app()
application.config['TESTING'] = False
client = application.test_client()

# 登录（表单提交，接口同时兼容 form 与 json）
r = client.post('/login', data={'username': 'admin', 'password': config.DEFAULT_ADMIN_PASSWORD})
print('login:', r.status_code, r.get_data(as_text=True)[:200])

domains = db.query('SELECT * FROM ad_domain_conf ORDER BY id')
did = domains[0]['id'] if domains else 0
uid = db.query_one('SELECT id FROM ad_user_cache WHERE domain_id=? LIMIT 1', (did,))
gid = db.query_one('SELECT id FROM ad_group_cache WHERE domain_id=? LIMIT 1', (did,))
cid = db.query_one('SELECT id FROM ad_computer_cache WHERE domain_id=? LIMIT 1', (did,))
uid = uid['id'] if uid else 0
gid = gid['id'] if gid else 0
cid = cid['id'] if cid else 0

pages = [
    ('/dashboard', '/dashboard'),
    ('/domains', '/domains/'),
    ('/domains/new', '/domains/new'),
    ('/domains/edit', f'/domains/{did}/edit'),
    ('/trust', '/trust/'),
    ('/trust/new', '/trust/new'),
    ('/users', '/users/'),
    ('/users?domain', f'/users/?domain_id={did}'),
    ('/users/new', f'/users/new?domain_id={did}'),
    ('/users/detail', f'/users/{uid}'),
    ('/users/edit', f'/users/{uid}/edit'),
    ('/users/import', '/users/import'),
    ('/ous', '/ous/'),
    ('/ous?domain', f'/ous/?domain_id={did}'),
    ('/groups', '/groups/'),
    ('/groups?domain', f'/groups/?domain_id={did}'),
    ('/groups/detail', f'/groups/{gid}'),
    ('/computers', '/computers/'),
    ('/computers?domain', f'/computers/?domain_id={did}'),
    ('/logs', '/logs/'),
    ('/config', '/config/'),
    ('/profile', '/profile'),
]

fails = []
for name, url in pages:
    try:
        resp = client.get(url)
        body = resp.get_data(as_text=True)
        status = resp.status_code
        # 检查是否渲染出 Jinja 错误
        bad = []
        if status != 200:
            bad.append(f'HTTP {status}')
        for kw in ('UndefinedError', 'jinja2.exceptions', 'Traceback', 'Internal Server Error'):
            if kw in body:
                bad.append(kw)
        # 关键节点
        if status == 200 and ('adm-sidebar' not in body and 'login-page' not in body):
            bad.append('缺少侧边栏')
        flag = 'OK  ' if not bad else 'FAIL'
        print(f'{flag} {name:16s} {url:44s} {status} len={len(body)} {" ".join(bad)}')
        if bad:
            fails.append((name, url, bad, body[:4000]))
    except Exception as e:
        print(f'EXC  {name:16s} {url:44s} {type(e).__name__}: {e}')
        fails.append((name, url, [f'{type(e).__name__}: {e}'], ''))

print()
if fails:
    print(f'===== {len(fails)} 个页面失败 =====')
    for name, url, bad, body in fails:
        print(f'\n--- {name} {url} {bad}')
        # 打印 traceback 片段
        m = re.search(r'(Traceback[\s\S]{0,3000})', body)
        if m:
            print(m.group(1)[:3000])
        else:
            print(body[:1500])
else:
    print('===== 全部页面通过 =====')

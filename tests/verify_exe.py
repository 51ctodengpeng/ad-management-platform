# -*- coding: utf-8 -*-
"""验证 PyInstaller 打包产物：独立进程启动 exe，登录并抓取页面标题与关键状态码。"""
import os
import subprocess
import sys
import time
import urllib.request
import urllib.parse
import http.cookiejar

EXE = r'D:\work-code\AD域控管理系统\dist\AD域控管理系统\AD域控管理系统.exe'
WORK = r'D:\tmp\adm_exe_test'
PORT = 8125
os.makedirs(WORK, exist_ok=True)

env = dict(os.environ)
env['ADM_WORK_DIR'] = WORK
env.pop('HTTP_PROXY', None)
env.pop('HTTPS_PROXY', None)
env.pop('http_proxy', None)
env.pop('https_proxy', None)

out = open(os.path.join(WORK, 'out.log'), 'w', encoding='utf-8', errors='replace')
err = open(os.path.join(WORK, 'err.log'), 'w', encoding='utf-8', errors='replace')
proc = subprocess.Popen([EXE, '--prod', '--host', '127.0.0.1', '--port', str(PORT)],
                        cwd=WORK, env=env, stdout=out, stderr=err)
print('pid', proc.pid)

base = f'http://127.0.0.1:{PORT}'
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                     urllib.request.HTTPCookieProcessor(cj))
for i in range(40):
    time.sleep(1)
    try:
        r = opener.open(base + '/login', timeout=3)
        if r.status == 200:
            print('server up after', i + 1, 's')
            break
    except Exception:
        if proc.poll() is not None:
            print('process exited early rc=', proc.returncode)
            break
else:
    print('server not up')

data = urllib.parse.urlencode({'username': 'admin', 'password': 'powershell@2025'}).encode()
r = opener.open(base + '/login', data=data, timeout=10)
print('login', r.status, r.read().decode()[:80])

html = opener.open(base + '/', timeout=10).read().decode('utf-8', 'replace')
import re
m = re.search(r'<title>(.*?)</title>', html, re.S)
print('dashboard title:', m.group(1).strip() if m else 'NONE')
print('dashboard len:', len(html), '| has sidebar:', 'adm-sidebar' in html)
print('包含中文:', '仪表盘' in html)

for path in ('/users/', '/domains/', '/trust/', '/logs/', '/config/', '/static/css/app.css',
             '/static/vendor/bootstrap/bootstrap.min.css'):
    try:
        r = opener.open(base + path, timeout=10)
        body = r.read()
        print(f'{path:48s} {r.status} {len(body)}')
    except Exception as e:
        print(f'{path:48s} ERR {e}')

proc.terminate()
try:
    proc.wait(timeout=8)
except Exception:
    proc.kill()
out.close()
err.close()
print('--- stderr tail ---')
print(open(os.path.join(WORK, 'err.log'), encoding='utf-8', errors='replace').read()[-600:])

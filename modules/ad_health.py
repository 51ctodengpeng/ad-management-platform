# -*- coding: utf-8 -*-
"""AD 域控健康监控（仅企业版）。

采集已纳管域控的：
- 连接状态：TCP 端口 + LDAP 绑定（快速、可靠）。
- 复制状态：repadmin /replsummary（WinRM 执行，需域控启用 WinRM）。
- 资源状态：CPU / 内存 / 系统盘 / 运行时长（WinRM PowerShell）。

写操作复用 ad_trust 的 pywinrm 会话；采集失败仅降级为「无法采集」，不阻断其它项。
"""
import re
import socket
import time

import config
from modules import db
from modules import ad_ldap as L
from modules import ad_trust as T
from modules.applog import get_logger

log = get_logger('health')


def _winrm_ps(d, script: str, timeout: int = 40):
    """在域控上执行 PowerShell，返回 (ok, text)。失败不抛异常。"""
    try:
        s = T._session(d, timeout=timeout)
        r = s.run_ps(script)
        if r.status_code != 0:
            return False, T._winrm_err(r)
        return True, T._decode_winrm(r).strip()
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------- 连接状态
def collect_connection(d):
    ldap_ok, ldap_msg = False, ''
    try:
        ldap_ok, ldap_msg = L.test_connection(d)
    except Exception as e:
        ldap_msg = str(e)
    port = (d.ldap_port or (636 if d.use_ssl else 389))
    tcp_ok, tcp_msg = False, ''
    try:
        s = socket.socket()
        s.settimeout(config.PRECHECK_TIMEOUT)
        s.connect((d.dc_host, port))
        tcp_ok, tcp_msg = True, f'{d.dc_host}:{port} 可连通'
        s.close()
    except Exception as e:
        tcp_msg = f'{d.dc_host}:{port} 不可达（{e}）'
    return {'ldap_ok': ldap_ok, 'ldap_msg': ldap_msg, 'tcp_ok': tcp_ok, 'tcp_msg': tcp_msg}


# ---------------------------------------------------------------- 复制状态
def collect_replication(d):
    """repadmin /replsummary，取各 DSA 的 fails 数最大值判断复制是否异常。"""
    ok, text = _winrm_ps(d, 'repadmin /replsummary 2>&1 | Out-String', timeout=60)
    if not ok:
        return {'ok': False, 'collected': False, 'summary': (text or 'repadmin 执行失败')[:800],
                'fails': None}
    # 提取所有 "fails/total" 数字对，fails 最大值判定（表头 "fails/total" 不是数字，不会误匹配）
    fails = 0
    for f, _t in re.findall(r'(\d+)\s*/\s*(\d+)', text):
        f = int(f)
        if f > fails:
            fails = f
    has_err = fails > 0
    # 兜底：明确的 failed 文本（排除 "0 failed"）
    low = text.lower()
    if not has_err and 'failed' in low:
        has_err = '0 failed' not in low
    return {'ok': not has_err, 'collected': True, 'summary': text[:800],
            'fails': fails, 'has_failure': has_err}


# ---------------------------------------------------------------- 资源状态
_RES_SCRIPT = (
    "$os=Get-CimInstance Win32_OperatingSystem;"
    "$cpu=[math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average,1);"
    "$mem=[math]::Round(($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/$os.TotalVisibleMemorySize*100,1);"
    "$d=Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\";"
    "$f=[math]::Round($d.FreeSpace/1GB,1);$t=[math]::Round($d.Size/1GB,1);"
    "$up=((Get-Date)-$os.LastBootUpTime).TotalDays;"
    "\"CPU:$cpu|MEM:$mem|DISKFREE:$f|DISKTOTAL:$t|UPDAYS:$([math]::Round($up,1))|HOST:$env:COMPUTERNAME\""
)


def collect_resource(d):
    ok, text = _winrm_ps(d, _RES_SCRIPT, timeout=60)
    res = {'collected': False, 'cpu': None, 'mem': None, 'disk_free_gb': None,
           'disk_total_gb': None, 'up_days': None, 'host': ''}
    if not ok:
        res['error'] = text[:200]
        return res
    kv = {}
    for part in text.split('|'):
        if ':' in part:
            k, v = part.split(':', 1)
            kv[k.strip()] = v.strip()
    try:
        res['collected'] = True
        res['cpu'] = float(kv.get('CPU', 0) or 0)
        res['mem'] = float(kv.get('MEM', 0) or 0)
        res['disk_free_gb'] = float(kv.get('DISKFREE', 0) or 0)
        res['disk_total_gb'] = float(kv.get('DISKTOTAL', 0) or 0)
        res['up_days'] = float(kv.get('UPDAYS', 0) or 0)
        res['host'] = kv.get('HOST', '')
    except Exception as e:
        res['error'] = f'资源解析失败：{e}'
        res['collected'] = False
    return res


# ---------------------------------------------------------------- 汇总
def collect_domain(d, deep: bool = False) -> dict:
    conn = collect_connection(d)
    repl = collect_replication(d) if deep else None
    res = collect_resource(d) if deep else None
    issues = []

    if not conn['ldap_ok']:
        status = 'offline'
        issues.append(f"LDAP 绑定失败：{conn['ldap_msg']}")
    else:
        if deep:
            if repl and repl['collected'] and repl.get('has_failure'):
                issues.append(f"复制存在失败（fails={repl['fails']}）")
            if repl and not repl['collected']:
                issues.append(f"复制状态无法采集（{repl['summary'][:80]}）")
            if res and res['collected']:
                if res['disk_total_gb'] and res['disk_free_gb'] is not None:
                    used_pct = (res['disk_total_gb'] - res['disk_free_gb']) / res['disk_total_gb'] * 100
                    if used_pct >= 95:
                        issues.append(f"系统盘使用率 {used_pct:.1f}% 严重偏高")
                    elif used_pct >= 85:
                        issues.append(f"系统盘使用率 {used_pct:.1f}% 偏高")
                if res['mem'] is not None and res['mem'] >= 95:
                    issues.append(f"内存使用率 {res['mem']}% 严重偏高")
                elif res['mem'] is not None and res['mem'] >= 85:
                    issues.append(f"内存使用率 {res['mem']}% 偏高")
                if res['cpu'] is not None and res['cpu'] >= 95:
                    issues.append(f"CPU 使用率 {res['cpu']}% 严重偏高")
                elif res['cpu'] is not None and res['cpu'] >= 85:
                    issues.append(f"CPU 使用率 {res['cpu']}% 偏高")
            if res and not res['collected']:
                issues.append(f"资源状态无法采集（{res.get('error', '')[:80]}）")

        # 状态判定
        crit_markers = ('严重', '失败', 'LDAP 绑定失败')
        if any(any(m in i for m in crit_markers) for i in issues):
            status = 'critical'
        elif issues:
            status = 'warning'
        else:
            status = 'healthy'

    return {
        'domain_id': d.id,
        'name': d.name,
        'domain_name': d.domain_name,
        'dc_host': d.dc_host,
        'status': status,
        'connection': conn,
        'replication': repl,
        'resource': res,
        'issues': issues,
        'checked_at': time.strftime('%Y-%m-%d %H:%M:%S'),
    }


def summarize(deep: bool = False) -> dict:
    """巡检所有已纳管域控，返回 {domains, total, offline, critical, warning, healthy}。"""
    domains = L.load_domains()
    results = [collect_domain(d, deep=deep) for d in domains]
    stat = {'total': len(results), 'offline': 0, 'critical': 0, 'warning': 0, 'healthy': 0}
    for r in results:
        stat[r['status']] = stat.get(r['status'], 0) + 1
    return {'domains': results, 'stat': stat, 'issues_total': sum(len(r['issues']) for r in results)}

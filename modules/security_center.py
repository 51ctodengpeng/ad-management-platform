# -*- coding: utf-8 -*-
"""安全中心（仅企业版）：安全态势体检 + 异常登录检测。

安全态势体检：读 SQLite 缓存（快、稳、不额外压 AD）+ 少量实时 LDAP（特权组成员），
逐项输出高危/中危/低危风险清单，并汇总安全评分（0-100）。

异常登录检测：基于审计日志 ad_operation_log 的规则检测（轻量 UEBA），
识别连续登录失败、单 IP 多账号、非工作时间登录、账号多 IP 等异常。
"""
import time
from datetime import datetime, timedelta

from modules import db
from modules import ad_ldap as L
from modules.applog import get_logger

log = get_logger('security')

# 特权组清单（实时查成员）
PRIVILEGED_GROUPS = ['Domain Admins', 'Enterprise Admins', 'Schema Admins',
                     'Administrators', 'Account Operators', 'Backup Operators',
                     'Server Operators']

SEVERITY_WEIGHT = {'high': 15, 'medium': 8, 'low': 3}


def _now() -> datetime:
    return datetime.now()


def _dt_str(dt) -> str:
    return dt.strftime('%Y-%m-%d %H:%M:%S') if dt else ''


# ================================================================ 检查项（基于缓存）
def _finding(sev, title, items, detail=''):
    items = [str(x) for x in (items or [])][:30]
    return {'severity': sev, 'title': title, 'count': len(items), 'items': items,
            'detail': detail or f'共 {len(items)} 项'}


def _privileged_groups(d) -> list:
    """实时查特权组成员，返回风险清单（成员数异常或含非预期成员）。"""
    findings = []
    try:
        conn = L.get_connection(d)
        for gname in PRIVILEGED_GROUPS:
            try:
                conn.search(d.base_dn, f'(&(objectCategory=group)(sAMAccountName={gname}))',
                            attributes=['member', 'sAMAccountName'], size_limit=1)
                if not conn.entries:
                    continue
                e = conn.entries[0]
                members = e['member'].values if 'member' in e else []
                # 基础判定：成员数 > 阈值 或 空成员（关键组无人 = 风险）都提示
                if len(members) > 30:
                    findings.append(_finding('medium', f'特权组 {gname} 成员过多',
                                             [m[:80] for m in members],
                                             f'成员 {len(members)} 个，建议精简并定期核查'))
                elif gname in ('Domain Admins', 'Enterprise Admins', 'Schema Admins') and not members:
                    findings.append(_finding('high', f'特权组 {gname} 无成员',
                                             [f'{gname} 为空'], '关键特权组无成员，请立即核查'))
            except Exception:
                continue
    except Exception as e:
        log.debug('特权组查询失败 %s: %s', d.domain_name, e)
    return findings


def _pwd_policy(d) -> list:
    """实时查域密码策略（minPwdLength / lockoutThreshold / pwdProperties）。"""
    findings = []
    try:
        conn = L.get_connection(d)
        conn.search(d.base_dn, '(objectClass=*)', search_scope='BASE',
                    attributes=['minPwdLength', 'lockoutThreshold', 'pwdProperties'], size_limit=1)
        if not conn.entries:
            return findings
        e = conn.entries[0]
        def _int(attr):
            try:
                v = e[attr].value
                return int(v) if v not in (None, []) else None
            except Exception:
                return None
        minlen = _int('minPwdLength')
        lockout = _int('lockoutThreshold')
        props = _int('pwdProperties')
        if minlen is not None and minlen < 8:
            findings.append(_finding('medium', '密码最短长度不足', [f'当前 {minlen} 位'],
                                     '建议 ≥ 8 位（安全基线要求）'))
        if lockout is not None and lockout == 0:
            findings.append(_finding('medium', '未启用账号锁定策略', ['lockoutThreshold=0'],
                                     '连续失败不锁定，易被暴力破解'))
        if props is not None and not (props & 1):
            findings.append(_finding('low', '未启用密码复杂度要求', ['pwdProperties 无 COMPLEX'],
                                     '建议开启密码复杂度'))
    except Exception as e:
        log.debug('密码策略查询失败 %s: %s', d.domain_name, e)
    return findings


def scan_domain(d) -> dict:
    """扫描单个域，返回 {domain_id, domain, score, findings, checked_at}。"""
    now = _now()
    now_str = _dt_str(now)
    idle_line = _dt_str(now - timedelta(days=90))
    pwd_soon = _dt_str(now + timedelta(days=14))
    stale_pwd = _dt_str(now - timedelta(days=180))

    findings = []

    # 1. 特权组（实时）
    findings += _privileged_groups(d)

    # 2. 空密码/未设密码（pwdLastSet=0）且启用
    empty = db.query("SELECT sam_account_name, dn FROM ad_user_cache WHERE domain_id=? "
                     "AND enabled=1 AND (pwd_last_set IS NULL OR pwd_last_set='' OR pwd_last_set='0')", (d.id,))
    if empty:
        findings.append(_finding('high', '启用账号从未设置密码', [f'{r["sam_account_name"]} ({r["dn"]})' for r in empty],
                                 '从未设置密码且处于启用状态，存在被利用风险'))

    # 3. 密码永不过期且启用
    never = db.query("SELECT sam_account_name, dn FROM ad_user_cache WHERE domain_id=? AND enabled=1 "
                     "AND pwd_never_expires=1 AND pwd_last_set IS NOT NULL AND pwd_last_set<>'' AND pwd_last_set<>'0'",
                     (d.id,))
    if never:
        findings.append(_finding('high', '密码永不过期账号', [f'{r["sam_account_name"]} ({r["dn"]})' for r in never],
                                 '密码永不过期违背安全基线，建议改为定期过期'))

    # 4. 密码已过期
    expired = db.query("SELECT sam_account_name, dn FROM ad_user_cache WHERE domain_id=? AND enabled=1 "
                       "AND pwd_expires_at<>'' AND pwd_expires_at<=?", (d.id, now_str))
    if expired:
        findings.append(_finding('medium', '密码已过期账号', [f'{r["sam_account_name"]} ({r["dn"]})' for r in expired]))

    # 5. 密码即将过期（14 天内）
    soon = db.query("SELECT sam_account_name, pwd_expires_at FROM ad_user_cache WHERE domain_id=? AND enabled=1 "
                    "AND pwd_expires_at<>'' AND pwd_expires_at>? AND pwd_expires_at<=?",
                    (d.id, now_str, pwd_soon))
    if soon:
        findings.append(_finding('low', '密码即将过期（14 天内）',
                                 [f'{r["sam_account_name"]}（{r["pwd_expires_at"][:10]}）' for r in soon]))

    # 6. 僵尸账号（90 天未登录且启用）
    zombie = db.query("SELECT sam_account_name, dn, last_logon FROM ad_user_cache WHERE domain_id=? AND enabled=1 "
                      "AND (last_logon IS NULL OR last_logon='' OR last_logon<?)", (d.id, idle_line))
    if zombie:
        findings.append(_finding('medium', '长期未登录的僵尸账号（90 天）',
                                 [f'{r["sam_account_name"]}（{r["last_logon"] or "从未"}）' for r in zombie]))

    # 7. 禁用账号未清理（禁用且 90 天未登录）
    stale_disabled = db.query("SELECT sam_account_name, dn FROM ad_user_cache WHERE domain_id=? AND enabled=0 "
                              "AND (last_logon IS NULL OR last_logon='' OR last_logon<?)", (d.id, idle_line))
    if stale_disabled:
        findings.append(_finding('low', '禁用账号长期未清理', [r['sam_account_name'] for r in stale_disabled],
                                 '已禁用且 90 天未登录，可考虑删除'))

    # 8. 长期未改密（180 天）且启用
    stale_pwd = db.query("SELECT sam_account_name, pwd_last_set FROM ad_user_cache WHERE domain_id=? AND enabled=1 "
                         "AND pwd_last_set<>'' AND pwd_last_set IS NOT NULL AND pwd_last_set<>'0' AND pwd_last_set<?",
                         (d.id, stale_pwd))
    if stale_pwd:
        findings.append(_finding('low', '长期未修改密码（180 天）', [r['sam_account_name'] for r in stale_pwd]))

    # 9. 密码策略（实时）
    findings += _pwd_policy(d)

    # 汇总评分
    score = 100
    for f in findings:
        score -= SEVERITY_WEIGHT.get(f['severity'], 3)
    score = max(0, score)

    return {'domain_id': d.id, 'domain': d.domain_name, 'name': d.name,
            'score': score, 'findings': findings, 'checked_at': _dt_str(now)}


def scan_all(only_enabled: bool = True) -> dict:
    """巡检所有已纳管域，返回 {domains, overall_score, high, medium, low}。"""
    domains = L.load_domains(only_enabled=only_enabled)
    results = [scan_domain(d) for d in domains]
    scores = [r['score'] for r in results]
    overall = round(sum(scores) / len(scores)) if scores else 0
    high = sum(1 for r in results for f in r['findings'] if f['severity'] == 'high')
    medium = sum(1 for r in results for f in r['findings'] if f['severity'] == 'medium')
    low = sum(1 for r in results for f in r['findings'] if f['severity'] == 'low')
    return {'domains': results, 'overall_score': overall, 'high': high, 'medium': medium,
            'low': low, 'total_findings': high + medium + low,
            'checked_at': _dt_str(_now())}


# ================================================================ 异常登录检测
def detect_anomalies() -> dict:
    """基于审计日志做规则检测。返回 {items, checked_at}。"""
    now = _now()
    out = []
    try:
        # 1. 连续登录失败（近 24h，按账号）
        rows = db.query("SELECT target, COUNT(*) c, MAX(created_at) last FROM ad_operation_log "
                        "WHERE module='auth' AND action='login' AND result='failed' "
                        "AND created_at>=datetime('now','localtime','-1 day') "
                        "GROUP BY target HAVING c>=5 ORDER BY c DESC LIMIT 20")
        if rows:
            out.append({'severity': 'high', 'title': '连续登录失败（暴力破解迹象）',
                        'count': len(rows),
                        'items': [f'{r["target"]}：失败 {r["c"]} 次（最后 {r["last"]}）' for r in rows]})

        # 2. 单 IP 多账号尝试（近 1h）
        rows = db.query("SELECT ip, COUNT(DISTINCT target) c, COUNT(*) total FROM ad_operation_log "
                        "WHERE module='auth' AND action='login' AND result='failed' "
                        "AND created_at>=datetime('now','localtime','-1 hour') AND ip<>'' "
                        "GROUP BY ip HAVING c>=3 ORDER BY c DESC LIMIT 20")
        if rows:
            out.append({'severity': 'high', 'title': '单 IP 多账号尝试（横向暴力破解）',
                        'count': len(rows),
                        'items': [f'{r["ip"] or "?"}：尝试 {r["c"]} 个账号（{r["total"]} 次失败）' for r in rows]})

        # 3. 非工作时间成功登录（22:00-06:00）
        rows = db.query("SELECT target, ip, MAX(created_at) last, COUNT(*) c FROM ad_operation_log "
                        "WHERE module='auth' AND action='login' AND result='success' "
                        "AND created_at>=datetime('now','localtime','-1 day') "
                        "AND (CAST(strftime('%H', created_at) AS INTEGER) >= 22 "
                        "  OR CAST(strftime('%H', created_at) AS INTEGER) < 6) "
                        "GROUP BY target ORDER BY c DESC LIMIT 20")
        if rows:
            out.append({'severity': 'medium', 'title': '非工作时间登录（22:00-06:00）',
                        'count': len(rows),
                        'items': [f'{r["target"]}（{r["ip"] or "?"}）最后 {r["last"]}' for r in rows]})

        # 4. 账号多 IP 登录（近 24h）
        rows = db.query("SELECT target, COUNT(DISTINCT ip) c FROM ad_operation_log "
                        "WHERE module='auth' AND action='login' AND result='success' "
                        "AND created_at>=datetime('now','localtime','-1 day') AND ip<>'' "
                        "GROUP BY target HAVING c>=3 ORDER BY c DESC LIMIT 20")
        if rows:
            out.append({'severity': 'medium', 'title': '单账号多 IP 登录（疑似账号共享/被盗）',
                        'count': len(rows),
                        'items': [f'{r["target"]}：来自 {r["c"]} 个 IP' for r in rows]})
    except Exception as e:
        log.warning('异常登录检测失败：%s', e)
    return {'items': out, 'checked_at': _dt_str(now)}

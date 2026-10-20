# -*- coding: utf-8 -*-
"""邮箱告警通知：SMTP 发送告警邮件 + 可勾选的告警策略。

- SMTP 配置与策略状态存 sys_setting 键值表（对所有许可证版本生效，不做版本门控）。
- 密码用 security.encrypt_secret（Fernet）加密落库，不存明文。
- evaluate() 由调度器每 5 分钟调用一次；每条策略按自身建议频率（interval 分钟）节流检测，
  触发即发一封邮件（同一策略在一个 interval 内最多一封，避免刷屏）。
"""
import json
import smtplib
import time
from datetime import datetime
from email.message import EmailMessage

import config
from modules import db
from modules import ad_ldap as L
from modules import ad_health
from modules import security
from modules.applog import get_logger

log = get_logger('alert')

SMTP_TIMEOUT = 30          # SMTP 建连/读写超时（秒），SSL 握手 + 登录可能较久，独立于 AD 超时

# ---------------------------------------------------------------- 策略目录
# 顺序即页面展示顺序。threshold 为 None 表示布尔型（无阈值）；否则为数值阈值。
# interval：建议检测/通知节流频率（分钟）。frequency：展示用建议通知频率说明。
POLICIES = [
    {
        'key': 'domain_offline', 'name': '域控离线 / 不可达',
        'desc': '任一已纳管域控的 LDAP 连接失败或被标记为离线',
        'default_enabled': True, 'interval': 30, 'threshold': None,
        'frequency': '每 30 分钟（持续离线重复提醒）',
    },
    {
        'key': 'login_failures', 'name': '连续登录失败',
        'desc': '最近 10 分钟内系统登录失败次数达到阈值',
        'default_enabled': True, 'interval': 10, 'threshold': 5,
        'frequency': '每 10 分钟',
    },
    {
        'key': 'cpu_high', 'name': 'CPU 使用率过高',
        'desc': '域控 CPU 平均使用率 ≥ 阈值（%）',
        'default_enabled': True, 'interval': 30, 'threshold': 85,
        'frequency': '每 30 分钟',
    },
    {
        'key': 'mem_high', 'name': '内存使用率过高',
        'desc': '域控物理内存使用率 ≥ 阈值（%）',
        'default_enabled': True, 'interval': 30, 'threshold': 85,
        'frequency': '每 30 分钟',
    },
    {
        'key': 'disk_high', 'name': '磁盘使用率过高',
        'desc': '域控系统盘（C:）使用率 ≥ 阈值（%）',
        'default_enabled': True, 'interval': 30, 'threshold': 85,
        'frequency': '每 30 分钟',
    },
    {
        'key': 'sync_failed', 'name': '数据同步失败',
        'desc': '任一已启用域最近一次增量/全量同步失败',
        'default_enabled': True, 'interval': 30, 'threshold': None,
        'frequency': '每 30 分钟',
    },
    {
        'key': 'pwd_expiring', 'name': '密码即将过期账号数超阈值',
        'desc': '14 天内密码到期的账号数量 ≥ 阈值',
        'default_enabled': False, 'interval': 1440, 'threshold': 10,
        'frequency': '每天一次',
    },
]


# ---------------------------------------------------------------- SMTP 配置
def get_smtp_config() -> dict:
    """读取 SMTP 配置（不含密码明文，仅 password_set 标记）。"""
    port = db.get_setting('mail_port', '465')
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 465
    return {
        'enabled': db.get_setting('mail_enabled', '0') == '1',
        'host': db.get_setting('mail_host', '') or '',
        'port': port,
        'security': db.get_setting('mail_security', 'ssl') or 'ssl',
        'username': db.get_setting('mail_username', '') or '',
        'sender': db.get_setting('mail_sender', '') or '',
        'password_set': bool(db.get_setting('mail_password', '')),
        'recipients': db.get_setting('mail_recipients', '') or '',
    }


def save_smtp_config(enabled: bool, host: str, port: int, security_mode: str,
                     username: str, sender: str, password: str, recipients: str) -> None:
    db.set_setting('mail_enabled', '1' if enabled else '0')
    db.set_setting('mail_host', (host or '').strip())
    db.set_setting('mail_port', str(int(port or 465)))
    db.set_setting('mail_security', security_mode)
    db.set_setting('mail_username', (username or '').strip())
    db.set_setting('mail_sender', (sender or '').strip())
    db.set_setting('mail_recipients', (recipients or '').strip())
    if password:                                   # 留空 = 不修改已存密码
        db.set_setting('mail_password', security.encrypt_secret(password))


def _smtp_password() -> str:
    token = db.get_setting('mail_password', '') or ''
    if not token:
        return ''
    try:
        return security.decrypt_secret(token)
    except Exception as e:
        log.warning('SMTP 密码解密失败：%s', e)
        return ''


def send_email(subject: str, body: str, to: str = None, ignore_disabled: bool = False) -> tuple:
    """发送邮件。返回 (ok, err)。失败不抛异常，便于调度器隔离。

    ignore_disabled=True 时跳过「总开关」检查（用于手动发送测试邮件）。
    """
    cfg = get_smtp_config()
    if not cfg['enabled'] and not ignore_disabled:
        return False, '邮件告警未启用'
    if not cfg['host'] or not cfg['sender']:
        return False, 'SMTP 未配置（缺少主机或发件邮箱）'
    raw = (to or cfg['recipients'] or '')
    recipients = [r.strip() for r in raw.replace(';', ',').split(',') if r.strip()]
    if not recipients:
        return False, '未配置收件人'

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = cfg['sender']
    msg['To'] = ', '.join(recipients)
    msg.set_content(body)

    host, port = cfg['host'], cfg['port']
    sec = cfg['security']
    try:
        if sec == 'ssl':
            server = smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT)
        else:
            server = smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT)
            if sec == 'tls':
                server.ehlo()
                server.starttls()
                server.ehlo()
        server.timeout = SMTP_TIMEOUT
        user = cfg['username'] or cfg['sender']
        pwd = _smtp_password()
        if pwd:
            server.login(user, pwd)
        server.send_message(msg)
        try:
            server.quit()
        except Exception:
            pass
        return True, ''
    except Exception as e:
        return False, f'{type(e).__name__}: {e}'


# ---------------------------------------------------------------- 策略状态
def get_policy_state() -> dict:
    """读取策略状态（勾选 + 阈值），缺省回退目录默认值。"""
    raw = db.get_setting('alert_policies', '') or ''
    state = {}
    if raw:
        try:
            state = json.loads(raw)
        except Exception:
            state = {}
    out = {}
    for p in POLICIES:
        key = p['key']
        st = state.get(key, {}) or {}
        out[key] = {
            'enabled': bool(st.get('enabled', p['default_enabled'])),
            'threshold': int(st.get('threshold', p['threshold'] or 0) or 0),
        }
    return out


def save_policy_state(state: dict) -> None:
    db.set_setting('alert_policies', json.dumps(state, ensure_ascii=False))


# ---------------------------------------------------------------- 检测与发送
def _eval_resource(key: str, cfg: dict, cache: dict) -> list:
    """资源类策略（CPU/内存/磁盘）共用一次 WinRM 采集，避免重复连接。"""
    findings = []
    thr = int(cfg.get(key, {}).get('threshold', 85) or 85)
    for d in L.load_domains(only_enabled=True):
        res = cache.get(d.id)
        if res is None:
            try:
                res = ad_health.collect_resource(d)
            except Exception as e:
                res = {'collected': False, 'error': str(e)}
            cache[d.id] = res
        if not res.get('collected'):
            continue
        host = res.get('host') or d.dc_host
        if key == 'cpu_high':
            v = res.get('cpu')
            if v is not None and v >= thr:
                findings.append(f'{d.name}（{host}）CPU 使用率 {v}%（阈值 {thr}%）')
        elif key == 'mem_high':
            v = res.get('mem')
            if v is not None and v >= thr:
                findings.append(f'{d.name}（{host}）内存使用率 {v}%（阈值 {thr}%）')
        elif key == 'disk_high':
            free, total = res.get('disk_free_gb'), res.get('disk_total_gb')
            if total and free is not None:
                used = (total - free) / total * 100
                if used >= thr:
                    findings.append(f'{d.name}（{host}）系统盘使用率 {used:.1f}%（阈值 {thr}%）')
    return findings


def _eval_one(key: str, pol: dict, cfg: dict, cache: dict) -> list:
    """评估单条策略，返回触发的异常明细列表（空列表 = 未触发）。"""
    if key == 'domain_offline':
        return [f'{d.name}（{d.domain_name}）离线' for d in L.load_domains(only_enabled=True)
                if d.status == 'offline']
    if key == 'login_failures':
        thr = int(cfg.get(key, {}).get('threshold', 5) or 5)
        n = db.scalar("SELECT COUNT(*) FROM ad_operation_log WHERE module='auth' AND action='login' "
                      "AND result='failed' AND created_at>=datetime('now','localtime','-10 minutes')", (), 0)
        return [f'最近 10 分钟内有 {n} 次系统登录失败（阈值 {thr} 次）'] if n >= thr else []
    if key in ('cpu_high', 'mem_high', 'disk_high'):
        return _eval_resource(key, cfg, cache)
    if key == 'sync_failed':
        rows = db.query("SELECT name, domain_name, last_sync_msg FROM ad_domain_conf "
                        "WHERE enabled=1 AND (last_sync_msg LIKE '%失败%' OR last_sync_msg LIKE '%异常%')")
        return [f'{r["name"]}（{r["domain_name"]}）：{(r["last_sync_msg"] or "")[:60]}' for r in rows]
    if key == 'pwd_expiring':
        thr = int(cfg.get(key, {}).get('threshold', 10) or 10)
        n = db.scalar("SELECT COUNT(*) FROM ad_user_cache WHERE pwd_expires_at<>'' "
                      "AND pwd_expires_at>=datetime('now','localtime') "
                      "AND pwd_expires_at<=datetime('now','localtime','+14 days')", (), 0)
        return [f'有 {n} 个账号将在 14 天内密码到期（阈值 {thr} 个）'] if n >= thr else []
    return []


def _notify(key: str, pol: dict, findings: list) -> None:
    subject = f'[{config.APP_NAME}告警] {pol["name"]}'
    lines = [f'触发策略：{pol["name"]}', f'触发条件：{pol["desc"]}', '', '异常明细：']
    lines += ['· ' + f for f in findings]
    lines += ['', f'时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', f'来源：{config.APP_NAME}']
    ok, err = send_email(subject, '\n'.join(lines))
    if ok:
        log.info('告警邮件已发送：%s（%d 项）', pol['name'], len(findings))
        db.set_setting(f'alert_last_send:{key}', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    else:
        log.warning('告警邮件发送失败：%s → %s', pol['name'], err)


def evaluate() -> dict:
    """检测所有已启用且到期的策略，触发即发邮件。返回本次结果摘要。"""
    cfg = get_policy_state()
    now = time.time()
    resource_cache = {}
    summary = {'checked': 0, 'sent': 0, 'triggered': []}
    for pol in POLICIES:
        key = pol['key']
        if not cfg.get(key, {}).get('enabled', pol['default_enabled']):
            continue
        last = float(db.get_setting(f'alert_last_run:{key}', '0') or 0)
        if now - last < pol['interval'] * 60:
            continue
        # 先推进 last_run（无论是否触发），保证按频率节流、异常也不重复轰炸
        db.set_setting(f'alert_last_run:{key}', f'{now:.0f}')
        try:
            findings = _eval_one(key, pol, cfg, resource_cache)
        except Exception as e:
            log.warning('告警策略 %s 检测异常：%s', key, e)
            continue
        summary['checked'] += 1
        if findings:
            summary['triggered'].append(key)
            summary['sent'] += 1
            _notify(key, pol, findings)
    return summary


def test_email(to: str = None) -> tuple:
    """发送测试邮件（验证 SMTP 配置）。绕过总开关，只要 SMTP 主机/发件人/收件人齐全即可发送。"""
    return send_email(f'[{config.APP_NAME}] 测试邮件',
                      '这是一封测试邮件，用于验证 SMTP 告警配置是否正确。\n'
                      '收到即代表邮件告警链路已打通。', to=to, ignore_disabled=True)

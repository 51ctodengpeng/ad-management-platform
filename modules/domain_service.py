# -*- coding: utf-8 -*-
"""多域配置服务：录入、编辑、启停、删除、连通性测试、容量校验。"""
import socket
import re

import config
from modules import db
from modules import ad_ldap as L
from modules.applog import get_logger
from modules.security import encrypt_secret

log = get_logger('domain')

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$')
HOST_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9\-\.]+)?$')


def validate(data: dict, domain_id: int = None) -> tuple:
    """校验表单，返回 (清洗后的 dict, 错误信息)。"""
    errors = []
    name = (data.get('name') or '').strip()
    domain_name = (data.get('domain_name') or '').strip().lower().rstrip('.')
    dc_host = (data.get('dc_host') or '').strip()
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    remark = (data.get('remark') or '').strip()

    if not name:
        errors.append('域名称必填')
    elif len(name) > 64:
        errors.append('域名称不能超过 64 个字符')

    if not domain_name:
        errors.append('AD 域名必填')
    elif not DOMAIN_RE.match(domain_name):
        errors.append('AD 域名格式不正确，应为 FQDN，如 corp.example.com')

    if not dc_host:
        errors.append('域控 IP / 主机名必填')
    elif not _valid_host(dc_host):
        errors.append('域控地址不合法（可填 IP 或主机名，不要带 http:// 或端口）')

    if not username:
        errors.append('管理员账号必填')
    elif len(username) > 128:
        errors.append('管理员账号过长')

    # 编辑时密码可留空表示不修改
    if not domain_id and not password:
        errors.append('管理员密码必填')

    use_ssl = 1 if str(data.get('use_ssl')) in ('1', 'on', 'true') else 0
    try:
        raw_port = (data.get('ldap_port') or '').strip()
        ldap_port = int(raw_port) if raw_port else (636 if use_ssl else 389)
    except Exception:
        ldap_port = 0
    # 端口与 SSL 开关明显矛盾时自动纠正：明文默认 389、LDAPS 默认 636。
    # 保留用户自定义非标端口（如 10389 / 11636）的能力。
    if use_ssl and ldap_port == 389:
        ldap_port = 636
    elif not use_ssl and ldap_port == 636:
        ldap_port = 389
    if not (1 <= ldap_port <= 65535):
        errors.append('LDAP 端口不合法（默认 389，SSL 为 636）')

    if domain_id is None:
        total = db.scalar('SELECT COUNT(*) FROM ad_domain_conf', (), 0)
        if total >= config.MAX_DOMAINS:
            errors.append(f'已达最大域数量上限（{config.MAX_DOMAINS} 个），如需扩容请参考文档迁移 MySQL')
    if db.query_one('SELECT id FROM ad_domain_conf WHERE domain_name=? AND id IS NOT ?',
                    (domain_name, domain_id)):
        errors.append(f'域名 {domain_name} 已存在，不允许重复录入')

    clean = {
        'name': name, 'domain_name': domain_name, 'dc_host': dc_host, 'username': username,
        'ldap_port': ldap_port, 'use_ssl': use_ssl,
        'remark': remark,
        'netbios_name': (data.get('netbios_name') or '').strip().upper(),
        'base_dn': (data.get('base_dn') or '').strip() or L._domain_to_dn(domain_name),
        'enabled': 1 if str(data.get('enabled', '1')) in ('1', 'on', 'true') else 0,
    }
    if password:
        clean['password_enc'] = encrypt_secret(password)
    return clean, '；'.join(errors)


def _valid_host(host: str) -> bool:
    if host.count(':') > 1 or '/' in host or ' ' in host or 'http' in host.lower():
        return False
    try:
        socket.inet_aton(host)
        return True
    except Exception:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except Exception:
        pass
    return bool(HOST_RE.match(host))


def create(data: dict) -> int:
    clean, err = validate(data)
    if err:
        raise ValueError(err)
    new_id = db.insert(
        'INSERT INTO ad_domain_conf(name, domain_name, netbios_name, dc_host, username, password_enc, '
        'ldap_port, use_ssl, base_dn, enabled, is_debug, remark, status, dns_checked) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,\'unknown\',0)',
        (clean['name'], clean['domain_name'], clean['netbios_name'], clean['dc_host'],
         clean['username'], clean['password_enc'], clean['ldap_port'], clean['use_ssl'],
         clean['base_dn'], clean['enabled'],
         1 if data.get('is_debug') not in (None, '', '0', 0, False, 'off') else 0, clean['remark']))
    return new_id


def update(domain_id: int, data: dict) -> None:
    row = db.query_one('SELECT * FROM ad_domain_conf WHERE id=?', (domain_id,))
    if not row:
        raise ValueError('域不存在')
    clean, err = validate(data, domain_id=domain_id)
    if err:
        raise ValueError(err)
    sets = ['name=?', 'domain_name=?', 'netbios_name=?', 'dc_host=?', 'username=?', 'ldap_port=?',
            'use_ssl=?', 'base_dn=?', 'enabled=?', 'remark=?', "updated_at=datetime('now','localtime')"]
    params = [clean['name'], clean['domain_name'], clean['netbios_name'], clean['dc_host'],
              clean['username'], clean['ldap_port'], clean['use_ssl'], clean['base_dn'],
              clean['enabled'], clean['remark']]
    if 'password_enc' in clean:
        sets.append('password_enc=?')
        params.append(clean['password_enc'])
    # 关键连接参数变化 → 状态重置 + 连接失效
    if (row['dc_host'] != clean['dc_host'] or row['ldap_port'] != clean['ldap_port']
            or row['use_ssl'] != clean['use_ssl'] or row['username'] != clean['username']
            or 'password_enc' in clean):
        sets += ["status='unknown'", "status_msg='配置已变更，待重新检测'"]
    params.append(domain_id)
    db.execute(f'UPDATE ad_domain_conf SET {", ".join(sets)} WHERE id=?', tuple(params))
    L.invalidate_conn(domain_id)


def set_enabled(domain_id: int, enabled: bool) -> None:
    db.execute('UPDATE ad_domain_conf SET enabled=?, updated_at=datetime(\'now\',\'localtime\') WHERE id=?',
               (1 if enabled else 0, domain_id))
    if not enabled:
        L.invalidate_conn(domain_id)
        db.execute("UPDATE ad_domain_conf SET status='offline', status_msg='域连接已停用' WHERE id=?", (domain_id,))
    else:
        db.execute("UPDATE ad_domain_conf SET status='unknown', status_msg='已启用，待检测' WHERE id=?", (domain_id,))


def delete(domain_id: int) -> dict:
    """删除域配置及其缓存（AD 本身不做任何改动）。"""
    row = db.query_one('SELECT * FROM ad_domain_conf WHERE id=?', (domain_id,))
    if not row:
        raise ValueError('域不存在')
    counts = {}
    with db.tx(immediate=True) as c:
        for table in ('ad_user_cache', 'ad_ou_cache', 'ad_group_cache', 'ad_computer_cache', 'ad_trust_cache'):
            counts[table] = c.execute(f'DELETE FROM {table} WHERE domain_id=?', (domain_id,)).rowcount
        c.execute('DELETE FROM ad_domain_conf WHERE id=?', (domain_id,))
        c.execute('DELETE FROM app_lock WHERE name=?', (f'sync:domain:{domain_id}',))
    L.invalidate_conn(domain_id)
    return {'domain': row['domain_name'], 'counts': counts}


def check_quota(domain_id: int) -> None:
    n = db.scalar('SELECT COUNT(*) FROM ad_user_cache WHERE domain_id=?', (domain_id,), 0)
    if n >= config.MAX_USERS_PER_DOMAIN:
        raise ValueError(f'该域缓存用户已达上限 {config.MAX_USERS_PER_DOMAIN}，请参考文档迁移 MySQL')


def ensure_debug_domain() -> None:
    """首次启动录入固定调试环境，开发/联调可直接使用。"""
    cfg = config.DEBUG_DOMAIN
    if db.query_one('SELECT 1 FROM ad_domain_conf WHERE domain_name=?', (cfg['domain_name'],)):
        return
    if db.scalar('SELECT COUNT(*) FROM ad_domain_conf', (), 0) > 0:
        # 已有其它域时也补一个调试域（标记 is_debug，便于运维识别）
        pass
    db.insert(
        'INSERT INTO ad_domain_conf(name, domain_name, netbios_name, dc_host, username, password_enc, '
        'ldap_port, use_ssl, base_dn, enabled, is_debug, remark, status) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,\'unknown\')',
        (cfg['name'], cfg['domain_name'], cfg['netbios_name'], cfg['dc_host'], cfg['username'],
         encrypt_secret(cfg['password']), cfg['ldap_port'], cfg['use_ssl'],
         L._domain_to_dn(cfg['domain_name']), 1, cfg['is_debug'], cfg['remark']))
    log.info('已录入固定调试域 %s (%s)', cfg['domain_name'], cfg['dc_host'])


def list_domains() -> list:
    """域列表 + 缓存统计（读 SQLite，不探 AD；在线状态取库中最后一次检测结果）。"""
    rows = db.query('SELECT * FROM ad_domain_conf ORDER BY id')
    out = []
    for r in rows:
        item = dict(r)
        item.pop('password_enc', None)
        item['user_count'] = db.scalar('SELECT COUNT(*) FROM ad_user_cache WHERE domain_id=?', (r['id'],), 0)
        item['enabled_users'] = db.scalar(
            'SELECT COUNT(*) FROM ad_user_cache WHERE domain_id=? AND enabled=1', (r['id'],), 0)
        item['disabled_users'] = item['user_count'] - item['enabled_users']
        item['ou_count'] = db.scalar('SELECT COUNT(*) FROM ad_ou_cache WHERE domain_id=?', (r['id'],), 0)
        item['group_count'] = db.scalar('SELECT COUNT(*) FROM ad_group_cache WHERE domain_id=?', (r['id'],), 0)
        item['computer_count'] = db.scalar('SELECT COUNT(*) FROM ad_computer_cache WHERE domain_id=?', (r['id'],), 0)
        item['has_password'] = bool(r['password_enc'])
        out.append(item)
    return out


def refresh_status_all() -> list:
    """批量刷新在线状态（LDAP 探测），串行执行，单域失败不影响其他域。"""
    results = []
    for d in L.load_domains():
        if not d.enabled:
            results.append({'id': d.id, 'name': d.label, 'ok': False, 'msg': '已停用'})
            continue
        ok, msg = L.test_connection(d)
        results.append({'id': d.id, 'name': d.label, 'ok': ok, 'msg': msg})
    return results

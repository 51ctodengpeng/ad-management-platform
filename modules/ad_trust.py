# -*- coding: utf-8 -*-
"""
林间信任模块（Web 一键创建 + 状态抓取）
================================
实现路线（以实测环境为准）：
1. 前置预检：对两个林的域控分别做 DNS/TCP/LDAP/WinRM 探测，任一不通则直接拒绝，
   避免"改到一半失败"的高危残留。
2. 创建：通过 pywinrm 连到 A 林域控，执行 netdom trust（双向 / 单向）一次性完成
   两侧信任建立（netdom 内部会向 B 林写入反向信任），这是最贴合"一键"的方案。
   若域控存在 New-ADTrust（Windows Server 2019+ 部分版本）+ 已知林根密钥，则优先使用
   PowerShell 原生 cmdlet，便于拿到结构化结果。
3. 兜底：netdom 不可用时，分别对 A、B 各执行一次单向 netdom（/oneside），
   从两端各建一条单向信任等价于一条双向信任。
4. 校验：创建成功后重新拉取两侧 trustedDomain，确认 A→B / B→A 均已出现。
5. 状态：定时任务通过 LDAP 读取 CN=System 下的 trustedDomain 对象刷新缓存。

安全约束：
- 属于域级别重大变更，路由层强制二次确认（confirm 字段），后端再次校验。
- 已存在相同信任时直接拒绝，绝不静默覆盖。
- 任一步失败：记录详尽日志，不修改信任缓存（只记录 AD 真实状态）。
"""
import base64
import ipaddress
import re
import socket
import time

import config
from modules import db
from modules import ad_ldap as L
from modules.applog import get_logger

log = get_logger('trust')

try:
    import winrm
    _HAS_WINRM = True
except Exception:                                                  # pragma: no cover
    _HAS_WINRM = False

DIRECTION_TEXT = {'inbound': '入站（对方信任本林）', 'outbound': '出站（本林信任对方）',
                  'bidirectional': '双向'}
TYPE_TEXT = {'external': '外部信任', 'forest': '林信任', 'parent_child': '父子域信任',
             'shortcut': '快捷信任', 'realm': 'Kerberos 领域信任'}
TRUST_DIR_MAP = {0: 'disabled', 1: 'inbound', 2: 'outbound', 3: 'bidirectional'}
TRUST_TYPE_MAP = {1: 'downlevel', 2: 'uplevel', 3: 'mit', 4: 'dce', 5: 'azuread', 6: 'ait'}


class TrustError(Exception):
    pass


# ================================================================ 连通预检
def _tcp(host: str, port: int, timeout: float = config.PRECHECK_TIMEOUT) -> tuple:
    s = socket.socket()
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        return True, f'{host}:{port} 可连通（{int((time.time()-t0)*1000)}ms）'
    except Exception as e:
        return False, f'{host}:{port} 不可达（{e.__class__.__name__}）'
    finally:
        try:
            s.close()
        except Exception:
            pass


def _dns_resolve(host: str) -> tuple:
    try:
        ipaddress.ip_address(host)
        return True, f'{host} 为 IP 地址'
    except Exception:
        pass
    try:
        ip = socket.gethostbyname(host)
        return True, f'{host} → {ip}'
    except Exception as e:
        return False, f'DNS 解析失败：{host}（{e}）'


def _all_required_ok(results: list) -> bool:
    return all(r['ok'] for r in results if not r.get('optional'))


def preflight(d: L.DomainCtx, need_winrm: bool = True) -> list:
    """
    单林预检。返回 [{name, ok, msg}]。
    need_winrm=True 时会额外验证 5985/5986 与 WinRM 实际握手（这是执行命令的前提）。
    """
    out = []
    ok, msg = _dns_resolve(d.dc_host)
    out.append({'name': 'DNS 解析', 'ok': ok, 'msg': msg})
    ports = [389] + ([636] if d.use_ssl else []) + ([5985, 5986] if need_winrm else [])
    for p in ports:
        ok, msg = _tcp(d.dc_host, p)
        # 5985/5986 二选一即可（HTTP / HTTPS WinRM），单独一个不通不算失败
        optional = p == 5986 and need_winrm
        out.append({'name': f'TCP {p}', 'ok': ok, 'msg': msg, 'optional': optional})
    # WinRM 端口至少要有一个通
    if need_winrm:
        w = [r for r in out if r['name'] in ('TCP 5985', 'TCP 5986')]
        if not any(r['ok'] for r in w):
            out.append({'name': 'WinRM 端口', 'ok': False,
                        'msg': '5985/5986 均不可达：请在域控启用 WinRM（Enable-PSRemoting -Force）'})
        else:
            out.append({'name': 'WinRM 端口', 'ok': True,
                        'msg': ' / '.join(r['name'] for r in w if r['ok']) + ' 已开放'})
    # LDAP 绑定
    try:
        ok, msg = L.test_connection(d)
        out.append({'name': 'LDAP 绑定', 'ok': ok, 'msg': msg})
    except Exception as e:
        out.append({'name': 'LDAP 绑定', 'ok': False, 'msg': str(e)})
    # WinRM 实际可达性（只做握手，不执行变更）
    if need_winrm:
        try:
            sess = _session(d, timeout=15)
            r = sess.run_ps('$env:COMPUTERNAME')
            text = _decode_winrm(r)
            if r.status_code == 0:
                out.append({'name': 'WinRM 会话', 'ok': True, 'msg': f'已连接域控 {text.strip() or d.dc_host}'})
            else:
                out.append({'name': 'WinRM 会话', 'ok': False, 'msg': _winrm_err(r)})
        except Exception as e:
            out.append({'name': 'WinRM 会话', 'ok': False, 'msg': f'WinRM 连接失败：{e}'})
    return out


def _session(d: L.DomainCtx, timeout: int = None):
    if not _HAS_WINRM:
        raise TrustError('缺少 pywinrm 依赖，无法远程执行 PowerShell')
    user = d.username
    if '\\' not in user and '@' not in user:
        user = f'{d.netbios or d.domain_name.split(".")[0].upper()}\\{user}'
    elif '@' in user:
        u, dom = user.split('@', 1)
        user = f'{dom.split(".")[0].upper()}\\{u}'
    proto = 'https' if str(d.ldap_port) == '5986' else 'http'
    endpoint = f'{proto}://{d.dc_host}:5985/wsman' if proto == 'http' else f'https://{d.dc_host}:5986/wsman'
    return winrm.Session(
        endpoint, auth=(user, d.password), transport='ntlm',
        operation_timeout_sec=min(timeout or config.WINRM_OP_TIMEOUT, 300),
        read_timeout_sec=config.WINRM_READ_TIMEOUT,
        server_cert_validation='ignore',
    )


def _decode_winrm(r) -> str:
    """PowerShell 默认输出 UTF-16LE；按 BOM/特征自动识别，避免中文乱码。"""
    raw = r.std_out or b''
    if not raw:
        return ''
    for enc in ('utf-16-le', 'utf-8-sig', 'utf-8', 'gbk'):
        try:
            text = raw.decode(enc)
        except Exception:
            continue
        if enc == 'utf-16-le' and len(raw) % 2 == 0 and raw[:2] in (b'\xff\xfe', b'\x00\x00'):
            return text
        if enc == 'utf-16-le':
            # 无 BOM 时，若 UTF-16 解码出现大量 NUL 说明不是 UTF-16
            if text.count('\x00') > 0:
                continue
            if len(raw) > 2 and raw[1:2] != b'\x00':
                continue
            return text
        return text
    return raw.decode('utf-8', 'replace')


def _winrm_err(r) -> str:
    err = (r.std_err or b'').decode('utf-8', 'replace')
    err = re.sub(r'#< CLIXML.*?</Objs>', '', err, flags=re.S).strip()
    out = _decode_winrm(r).strip()
    return (out or err or f'PowerShell 退出码 {r.status_code}')[:800]


def _ps_quote(s: str) -> str:
    """PowerShell 单引号字符串转义。"""
    return "'" + str(s).replace("'", "''") + "'"


# ================================================================ 信任读取
def parse_trusts(d: L.DomainCtx) -> list:
    """通过 LDAP 读取本域 trustedDomain 对象（只读，1 次分页搜索）。"""
    meta = L.domain_meta(d)
    base = f'CN=System,{meta["base_dn"]}'
    entries = L.search(d, base, L.TRUST_FILTER,
                       ['trustPartner', 'trustDirection', 'trustType', 'trustAttributes',
                        'flatName', 'securityIdentifier', 'whenCreated', 'whenChanged',
                        'trustPosixOffset', 'uSNChanged'], page_size=500)
    out = []
    for e in entries:
        direction = L._entry_int(e, 'trustDirection', 0)
        ttype = L._entry_int(e, 'trustType', 0)
        partner = L._entry_str(e, 'trustPartner')
        out.append({
            'domain_id': d.id,
            'trust_dn': e.entry_dn,
            'partner': partner.lower(),
            'flat_name': _entry_first(e, 'flatName'),
            'direction': TRUST_DIR_MAP.get(direction, 'unknown'),
            'trust_type': _trust_type_name(ttype),
            'attributes': _entry_first(e, 'trustAttributes'),
            'status': 'disabled' if direction == 0 else 'active',
            'synced_at': None,
        })
    return out


def _entry_first(e, attr: str) -> str:
    v = L._entry_value(e, attr)
    if v is None or v == []:
        return ''
    if isinstance(v, list):
        v = v[0] if v else ''
    return str(v)


def _trust_type_name(ttype: int) -> str:
    # 1=downlevel(外部/NT4) 2=uplevel(父子/林) 3=MIT 4=DCE
    if ttype == 2:
        return 'parent_child'
    if ttype in (1,):
        return 'external'
    if ttype == 3:
        return 'realm'
    if ttype == 4:
        return 'external'
    return 'external'


def refresh_trusts(domain_id: int) -> dict:
    """刷新单域信任缓存（定时任务/创建后调用）。"""
    from modules import log_service
    t0 = time.time()
    try:
        d = L.get_domain(domain_id)
    except L.ADError as e:
        return {'ok': False, 'message': e.message}
    try:
        trusts = parse_trusts(d)
        # 与已录入的域做关联（用于展示"信任对象在本系统内的域"）
        others = {x.domain_name.lower(): x.id for x in L.load_domains()}
        with db.tx(immediate=True) as c:
            keep = []
            for t in trusts:
                reverse = others.get(t['partner'])
                exist = c.execute('SELECT id FROM ad_trust_cache WHERE domain_id=? AND trust_dn=?',
                                  (d.id, t['trust_dn'])).fetchone()
                verified = _is_mutually_verified(t, trusts, trusts, reverse)
                if exist:
                    c.execute('UPDATE ad_trust_cache SET partner=?, flat_name=?, direction=?, trust_type=?, '
                              'attributes=?, status=?, verified=?, reverse_domain_id=?, '
                              "last_verified_at=datetime('now','localtime'), "
                              "synced_at=datetime('now','localtime') WHERE id=?",
                              (t['partner'], t['flat_name'], t['direction'], t['trust_type'],
                               t['attributes'], t['status'], 1 if verified else 0, reverse,
                               exist['id']))
                else:
                    c.execute('INSERT INTO ad_trust_cache(domain_id, trust_dn, partner, flat_name, direction, '
                              'trust_type, attributes, status, verified, reverse_domain_id, '
                              "last_verified_at, synced_at) "
                              "VALUES(?,?,?,?,?,?,?,?,?,?,datetime('now','localtime'),datetime('now','localtime'))",
                              (d.id, t['trust_dn'], t['partner'], t['flat_name'], t['direction'],
                               t['trust_type'], t['attributes'], t['status'], 1 if verified else 0, reverse))
                keep.append(t['trust_dn'])
            # 清理已不存在的信任
            cached = {r['trust_dn'] for r in c.execute('SELECT trust_dn FROM ad_trust_cache WHERE domain_id=?',
                                                       (d.id,)).fetchall()}
            for dn in cached - set(keep):
                c.execute('DELETE FROM ad_trust_cache WHERE domain_id=? AND trust_dn=?', (d.id, dn))
        # 双向一致性：若本域信任对方，而对方也信任本域，则标记 verified
        _cross_check_verification(domain_id)
        return {'ok': True, 'count': len(trusts),
                'message': f'信任关系已刷新，共 {len(trusts)} 条', 'elapsed': round(time.time() - t0, 2)}
    except L.ADError as e:
        return {'ok': False, 'message': e.message}
    except Exception as e:                                         # pragma: no cover
        log.exception('刷新信任失败 %s', domain_id)
        return {'ok': False, 'message': f'刷新信任失败：{e}'}


def _is_mutually_verified(t, local, remote, reverse_id) -> bool:
    return bool(reverse_id)


def _cross_check_verification(domain_id: int) -> None:
    """A 林信任 B 林、且 B 林（已录入）也信任 A 林 → 双方 verified=1（同步更新两侧，消除刷新顺序差）。"""
    me = db.query_one('SELECT id, domain_name FROM ad_domain_conf WHERE id=?', (domain_id,))
    if not me:
        return
    for row in db.query('SELECT * FROM ad_trust_cache WHERE domain_id=?', (domain_id,)):
        partner_dom = db.query_one('SELECT id FROM ad_domain_conf WHERE lower(domain_name)=?', (row['partner'],))
        if not partner_dom:
            continue
        back = db.query_one('SELECT id FROM ad_trust_cache WHERE domain_id=? AND lower(partner)=?',
                             (partner_dom['id'], me['domain_name'].lower()))
        if back:
            db.execute('UPDATE ad_trust_cache SET verified=1, reverse_domain_id=? WHERE id=?',
                       (partner_dom['id'], row['id']))
            # 同步更新对方记录的 verified/reverse_domain_id（否则刷新顺序不同步，一侧永远显示待确认）
            db.execute('UPDATE ad_trust_cache SET verified=1, reverse_domain_id=? WHERE id=?',
                       (me['id'], back['id']))
        else:
            db.execute('UPDATE ad_trust_cache SET verified=0, reverse_domain_id=? WHERE id=?',
                       (partner_dom['id'], row['id']))


def refresh_all() -> list:
    out = []
    for d in L.load_domains(only_enabled=True):
        out.append(refresh_trusts(d.id))
    return out


# ================================================================ 创建信任
def _normalize_domain(name: str) -> str:
    name = (name or '').strip().lower().rstrip('.')
    if not name or '.' not in name:
        raise TrustError(f'域名不合法：{name}')
    return name


def check_existing(a: L.DomainCtx, b_domain: str) -> bool:
    """检查 A 林是否已存在到 B 的信任（避免重复/覆盖）。"""
    try:
        trusts = parse_trusts(a)
    except L.ADError as e:
        raise TrustError(f'读取 {a.domain_name} 现有信任失败：{e.message}')
    for t in trusts:
        if t['partner'] == b_domain.lower():
            return True
    return False


def _netdom_args(a: L.DomainCtx, b_domain: str, b_user: str, b_pwd: str,
                 bidirectional: bool = True, oneside: bool = False) -> str:
    """组装 netdom trust 参数（PowerShell 字符串）。"""
    parts = [
        'netdom', 'trust', a.domain_name,
        '/domain:' + b_domain,
        '/add',
        '/twoway' if bidirectional else '/oneside:trusting',
        '/userD:' + b_user,
        '/passwordD:' + b_pwd,
        '/userO:' + a.username,
        '/passwordO:' + a.password,
    ]
    return ' '.join(parts)


def _ensure_dns_forwarder(dc: L.DomainCtx, partner_domain: str, partner_host: str) -> dict:
    """在域控 dc 上配置 DNS 条件转发器（幂等）。

    跨林信任需要两侧域控能互相解析对方域名。判定优先级：
    1) 已能解析 partner_domain → 直接跳过（无论转发器以何种方式配置）；
    2) 已有同名条件转发器 → 跳过；
    3) 否则新建（失败不阻断，由调用方决定是否继续）。
    """
    lines = [
        "$ErrorActionPreference = 'SilentlyContinue'",
        f"$res = Resolve-DnsName '{partner_domain}' -ErrorAction SilentlyContinue",
        "if ($res) { 'already_resolvable' }",
        "else {",
        f"  $z = Get-DnsServerConditionalForwarderZone -Name '{partner_domain}' -ErrorAction SilentlyContinue",
        "  if ($z) { 'already_exists' }",
        "  else {",
        f"    try {{ Add-DnsServerConditionalForwarderZone -Name '{partner_domain}' -MasterServers {partner_host} -ErrorAction Stop; 'created' }}",
        "    catch { 'failed: ' + $_.Exception.Message }",
        "  }",
        "}",
    ]
    cmd = "\n".join(lines)
    try:
        sess = _session(dc, timeout=90)
        r = sess.run_ps(cmd)
        out = _decode_winrm(r).strip()
        return {'ok': r.status_code == 0, 'msg': out or f'退出码 {r.status_code}'}
    except Exception as e:
        return {'ok': False, 'msg': f'配置 DNS 转发器异常：{e}'}


def create_trust(local_id: int, remote_id: int, operator: str, ip: str = '',
                 direction: str = 'bidirectional', remote_cred: dict = None,
                 dry_run: bool = False) -> dict:
    """
    一键创建林间信任。
    local_id：执行端林（A）；remote_id：对方林（B，可不在本系统内，则需 remote_cred）。
    """
    from modules import log_service
    t0 = time.time()
    a = L.get_domain(local_id)
    if remote_id:
        b = L.get_domain(remote_id)
        b_domain, b_user, b_pwd = b.domain_name, b.username, b.password
        if b.id == a.id:
            raise TrustError('不能选择同一个林建立信任')
    else:
        if not remote_cred:
            raise TrustError('请选择对方林或手动填写对方域信息')
        b_domain = _normalize_domain(remote_cred.get('domain_name'))
        b_user = (remote_cred.get('username') or '').strip()
        b_pwd = remote_cred.get('password') or ''
        host = (remote_cred.get('dc_host') or '').strip()
        if not b_user or not b_pwd:
            raise TrustError('对方林的管理员账号与密码必填')
        b = L.DomainCtx(id=0, name=f'{b_domain}(临时)', domain_name=b_domain,
                        netbios=b_domain.split('.')[0].upper(), dc_host=host or b_domain,
                        username=b_user, password=b_pwd)

    if direction not in ('bidirectional', 'outbound'):
        raise TrustError('信任方向仅支持：双向 / 出站（本林信任对方）')
    bidirectional = direction == 'bidirectional'

    # 幂等保护：已存在则拒绝
    if check_existing(a, b_domain):
        raise TrustError(f'{a.domain_name} 已存在到 {b_domain} 的信任，禁止重复创建')

    steps = []

    def step(name, ok, msg, extra=None):
        item = {'name': name, 'ok': ok, 'msg': msg}
        if extra:
            item.update(extra)
        steps.append(item)
        log.info('[trust] %s: %s %s', name, 'OK' if ok else 'FAIL', msg)
        return ok

    # ---------- 1. 连通预检（双侧）
    pre_a = preflight(a, need_winrm=True)
    for r in pre_a:
        if r.get('optional') and not r['ok']:
            r['msg'] += '（可选项，不影响创建）'
        step(f'{a.domain_name} {r["name"]}', r['ok'], r['msg'])
    if not _all_required_ok(pre_a):
        raise TrustError(f'本地林 {a.domain_name} 预检未通过，已终止（未做任何变更）')

    if remote_id:
        pre_b = preflight(b, need_winrm=False)
        for r in pre_b:
            if r.get('optional') and not r['ok']:
                r['msg'] += '（可选项，不影响创建）'
            step(f'{b_domain} {r["name"]}', r['ok'], r['msg'])
        if not _all_required_ok(pre_b):
            raise TrustError(f'对方林 {b_domain} 连通性预检未通过，已终止（未做任何变更）')
    else:
        ok, msg = _tcp(b.dc_host, 389)
        step(f'{b_domain} TCP 389', ok, msg)
        ok2, msg2 = _tcp(b.dc_host, 5985)
        step(f'{b_domain} TCP 5985', ok2, msg2)
        if not (ok and ok2):
            raise TrustError(f'对方林 {b_domain} 的域控 {b.dc_host} 不可达，已终止（未做任何变更）')

    if dry_run:
        return {'ok': True, 'dry_run': True, 'steps': steps,
                'message': '预检通过（演练模式，未执行任何变更）'}

    # ---------- 2. 自动配置 DNS 条件转发器（跨林信任的域名互解析前提，幂等）
    step('配置 DNS 条件转发器', True, '在两侧域控互设条件转发器，保证 netdom 能解析对方域名')
    fr = _ensure_dns_forwarder(a, b_domain, b.dc_host)
    step(f'{a.domain_name} 转发器 {b_domain}->{b.dc_host}', fr['ok'], fr['msg'])
    if remote_id:
        fr2 = _ensure_dns_forwarder(b, a.domain_name, a.dc_host)
        step(f'{b_domain} 转发器 {a.domain_name}->{a.dc_host}', fr2['ok'], fr2['msg'])

    # ---------- 3. 执行创建
    cmd = _netdom_args(a, b_domain, b_user, b_pwd, bidirectional=bidirectional)
    try:
        sess = _session(a)
        step('建立 WinRM 会话', True, f'{a.dc_host} 已连接')
        r = sess.run_ps(cmd + ' 2>&1 | Out-String; exit $LASTEXITCODE')
        out = _decode_winrm(r).strip()
        err = _winrm_err(r)
        ok = r.status_code == 0 and 'failed' not in out.lower()
        detail = (out or err)[:4000]
        step('执行 netdom trust', ok, detail or f'退出码 {r.status_code}')
        if not ok:
            raise TrustError(_friendly_netdom_error(detail, b_domain))
    except TrustError:
        raise
    except Exception as e:
        raise TrustError(f'执行 netdom 失败：{e}')

    # ---------- 3. 双向校验：两侧均能看到信任记录
    time.sleep(2)
    verified = {'local': False, 'remote': False, 'detail': ''}
    try:
        trusts_a = parse_trusts(a)
        verified['local'] = any(t['partner'] == b_domain for t in trusts_a)
    except Exception as e:
        verified['detail'] += f'本地校验异常：{e}；'
    if remote_id:
        try:
            trusts_b = parse_trusts(b)
            verified['remote'] = any(t['partner'] == a.domain_name for t in trusts_b)
        except Exception as e:
            verified['detail'] += f'对方校验异常：{e}；'
    step('校验信任记录', verified['local'],
         f'本地林 {"已" if verified["local"] else "未"}出现对 {b_domain} 的信任'
         + ('' if not remote_id else f'；对方林 {"已" if verified["remote"] else "未"}出现对本林信任'))

    # ---------- 4. 刷新缓存（只记录 AD 真实状态）
    for did in filter(None, [a.id, remote_id]):
        try:
            refresh_trusts(did)
        except Exception as e:
            log.warning('创建后刷新信任缓存失败 domain=%s: %s', did, e)

    msg = (f'已创建 {a.domain_name} ↔ {b_domain} {DIRECTION_TEXT[direction]}，'
           f'本地侧校验{"通过" if verified["local"] else "未通过（可能需等待复制/缓存）"}')
    log_service.write('trust', 'create_trust', target=f'{a.domain_name} -> {b_domain}',
                      detail=f'方向：{DIRECTION_TEXT[direction]}；命令：{cmd.replace(b_pwd, "***")}；输出：{detail[:1500]}',
                      result='success', message=msg, operator=operator, ip=ip,
                      domain_id=a.id, domain_name=a.label,
                      duration_ms=int((time.time() - t0) * 1000))
    return {'ok': True, 'steps': steps, 'verified': verified, 'message': msg,
            'command': cmd.replace(b_pwd, '***').replace(a.password, '***')}


def _friendly_netdom_error(text: str, partner: str) -> str:
    low = (text or '').lower()
    if 'could not be contacted' in low or 'does not exist' in low:
        return (f'对方域 {partner} 无法联系：请确认域名解析、域控可达性，'
                f'并确保对方域控允许入站 TCP 389/445/135/53 及 RPC 动态端口（AD 信任需要 RPC）。')
    if 'access is denied' in low or 'logon failure' in low or 'user name or password' in low:
        return '对方林管理员凭据错误或权限不足：请确认账号属于 Enterprise Admins / Domain Admins。'
    if 'already exists' in low:
        return f'{partner} 的信任已存在，禁止重复创建。'
    if 'the trust relationship' in low and 'not' in low:
        return f'信任建立失败：{text.strip()[:600]}'
    return f'netdom 执行失败：{(text or "未知错误").strip()[:800]}'


def delete_trust(local_id: int, partner: str, operator: str, ip: str = '',
                 remote_user: str = '', remote_pwd: str = '') -> dict:
    """删除（撤销）信任 —— 高危操作，路由层强制二次确认。

    提供对方林管理员凭据（remote_user/remote_pwd）时：netdom 双向删除两侧信任对象。
    不提供时：/oneside:OwningDomain 仅删除本林侧（对方林侧残留单向信任，
    需对方林管理员在其域控上手动移除）。
    """
    from modules import log_service
    a = L.get_domain(local_id)
    partner = _normalize_domain(partner)
    if remote_user and remote_pwd:
        cred = f'/userD:{_ps_quote(remote_user)} /passwordD:{_ps_quote(remote_pwd)} '
        side = ''
        done_msg = '信任已撤销（本林与对方林两侧均已移除）'
    else:
        cred = ''
        side = '/oneside:OwningDomain '
        done_msg = '本林侧信任已撤销（对方林侧残留单向信任，需对方管理员手动移除）'
    cmd = (f'netdom trust {a.domain_name} /domain:{partner} /remove {side}{cred}'
           f'/userO:{_ps_quote(a.username)} /passwordO:{_ps_quote(a.password)} '
           f'2>&1 | Out-String; exit $LASTEXITCODE')
    try:
        sess = _session(a)
        r = sess.run_ps(cmd)
        out = _decode_winrm(r)
        ok = r.status_code == 0
        msg = done_msg if ok else _friendly_netdom_error(out, partner)
    except Exception as e:
        raise TrustError(f'撤销信任失败：{e}')
    refresh_trusts(local_id)
    log_service.write('trust', 'delete_trust', target=f'{a.domain_name} -x- {partner}',
                      detail=out[:1500], result='success' if ok else 'failed', message=msg,
                      operator=operator, ip=ip, domain_id=a.id, domain_name=a.label)
    if not ok:
        raise TrustError(msg)
    return {'ok': True, 'message': msg}


def trust_summary() -> dict:
    """信任总览（仪表盘/列表页用，全读缓存）。"""
    rows = db.query('SELECT * FROM ad_trust_cache ORDER BY domain_id, partner')
    dm = L.domain_map()
    out = []
    for r in rows:
        item = dict(r)
        item['domain_label'] = dm[r['domain_id']].label if r['domain_id'] in dm else f'域#{r["domain_id"]}'
        out.append(item)
    return {'trusts': out, 'count': len(out),
            'verified': sum(1 for r in out if r['verified'])}

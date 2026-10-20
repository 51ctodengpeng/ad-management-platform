# -*- coding: utf-8 -*-
"""
AD LDAP 核心模块（多域）
================================
铁律：所有写操作直连对应域控 AD；失败即返回错误，绝不改缓存。
     缓存只由"写成功后单条刷新"和"同步任务"维护。

实现要点
1. 多域：域配置来自 ad_domain_conf，Connection 按域构造并复用（线程内 TTL 缓存）。
2. 认证：优先 SIMPLE（user@domain，无需 MD4）；NTLM 需 hashlib.md4，
   Python 3.12+ 默认移除，已在 _patch_md4() 里用纯 Python 实现补齐，保证 NTLM 可用。
3. 故障隔离：域健康状态带 TTL 缓存，域控不可达时该域标记 offline，写操作前拒绝。
4. 错误翻译：把 AD 的 LDAP 诊断信息翻译成运维看得懂的中文。
"""
import random
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import config
from modules import db
from modules.applog import get_logger
from modules.security import decrypt_secret

log = get_logger('ldap')


# ================================================================ MD4 补丁
def _patch_md4():
    """Python 3.12+ 移除了 hashlib.md4，ldap3 的 NTLM 依赖它。用纯 Python 补齐。"""
    import hashlib
    if 'md4' in hashlib.algorithms_available:
        return

    class _MD4:
        name = 'md4'
        digest_size = 16
        block_size = 64

        def __init__(self, data=b''):
            self._buf = b''
            self._count = 0
            self._state = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
            if data:
                self.update(data)

        @staticmethod
        def _rotl(x, n):
            x &= 0xFFFFFFFF
            return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

        def _process(self, chunk):
            X = [int.from_bytes(chunk[i:i + 4], 'little') for i in range(0, 64, 4)]
            a, b, c, d = self._state
            F = lambda x, y, z: (x & y) | (~x & z)                       # noqa: E731
            G = lambda x, y, z: (x & y) | (x & z) | (y & z)              # noqa: E731
            H = lambda x, y, z: x ^ y ^ z                                # noqa: E731
            for i in range(16):
                k = i
                s = [3, 7, 11, 19][i % 4]
                a = self._rotl(a + F(b, c, d) + X[k], s)
                a, b, c, d = d, a, b, c
            for i in range(16):
                k = (i % 4) * 4 + i // 4
                s = [3, 5, 9, 13][i % 4]
                a = self._rotl(a + G(b, c, d) + X[k] + 0x5A827999, s)
                a, b, c, d = d, a, b, c
            order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for i in range(16):
                k = order[i]
                s = [3, 9, 11, 15][i % 4]
                a = self._rotl(a + H(b, c, d) + X[k] + 0x6ED9EBA1, s)
                a, b, c, d = d, a, b, c
            self._state = tuple((x + y) & 0xFFFFFFFF for x, y in zip(self._state, (a, b, c, d)))

        def update(self, data):
            data = bytes(data)
            self._count += len(data)
            self._buf += data
            while len(self._buf) >= 64:
                self._process(self._buf[:64])
                self._buf = self._buf[64:]
            return self

        def digest(self):
            msg = self._buf
            bit_len = (self._count * 8) & 0xFFFFFFFFFFFFFFFF
            pad = b'\x80' + b'\x00' * ((56 - (len(msg) + 1) % 64) % 64)
            msg = msg + pad + bit_len.to_bytes(8, 'little')
            st = self._state
            for i in range(0, len(msg), 64):
                self._process(msg[i:i + 64])
            out = b''.join(x.to_bytes(4, 'little') for x in self._state)
            self._state = st
            self._buf = b''
            self._count = 0
            return out

        def hexdigest(self):
            return self.digest().hex()

        def copy(self):
            n = _MD4()
            n._buf, n._count, n._state = self._buf, self._count, self._state
            return n

    def md4_ctor(data=b''):
        return _MD4(data)

    _orig_new = hashlib.new

    def _new(name, *args, **kwargs):
        if name.lower() == 'md4':
            return _MD4(args[0] if args else b'')
        return _orig_new(name, *args, **kwargs)

    hashlib.new = _new
    hashlib.md4 = md4_ctor                                        # type: ignore[attr-defined]
    try:
        algorithms = list(hashlib.algorithms_available)
        if 'md4' not in algorithms:
            algorithms.append('md4')
            hashlib.algorithms_available = set(algorithms)        # type: ignore[assignment]
    except Exception:
        pass
    hashlib._md4_patched = True


_patch_md4()

from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, AUTO_BIND_NONE, Tls, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE  # noqa: E402,E501
from ldap3.utils.conv import escape_filter_chars  # noqa: E402
import ssl  # noqa: E402

try:
    from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups, ad_remove_members_from_groups  # noqa: E402
    from ldap3.extend.microsoft.modifyPassword import ad_modify_password  # noqa: E402
    from ldap3.extend.microsoft.unlockAccount import ad_unlock_account  # noqa: E402
    _HAS_MS_EXT = True
except Exception:                                                  # pragma: no cover
    _HAS_MS_EXT = False
    ad_add_members_to_groups = ad_remove_members_from_groups = None
    ad_modify_password = None
    ad_unlock_account = None


# ================================================================ 常量
UAC_ACCOUNTDISABLE = 0x0002
UAC_LOCKOUT = 0x0010
UAC_PASSWD_NOTREQD = 0x0020
UAC_PASSWD_CANT_CHANGE = 0x0040
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_NORMAL_ACCOUNT = 0x0200
UAC_TRUSTED_FOR_DELEGATION = 0x80000
AD_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
NEVER_EXPIRE_INT = 9223372036854775807

USER_ATTRS = [
    'distinguishedName', 'sAMAccountName', 'cn', 'displayName', 'givenName', 'sn',
    'userPrincipalName', 'mail', 'telephoneNumber', 'mobile', 'title', 'department',
    'company', 'description', 'userAccountControl', 'pwdLastSet', 'lastLogonTimestamp',
    'whenCreated', 'whenChanged', 'uSNChanged', 'objectSid', 'sAMAccountType',
    'lockoutTime', 'badPwdCount', 'msDS-UserPasswordExpiryTimeComputed', 'memberOf', 'objectClass',
]
OU_ATTRS = ['distinguishedName', 'ou', 'name', 'description', 'uSNChanged', 'whenCreated', 'whenChanged']
GROUP_ATTRS = ['distinguishedName', 'sAMAccountName', 'cn', 'groupType', 'description', 'mail',
               'uSNChanged', 'whenCreated', 'member']
COMPUTER_ATTRS = ['distinguishedName', 'cn', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion',
                  'description', 'userAccountControl', 'lastLogonTimestamp', 'whenCreated',
                  'whenChanged', 'uSNChanged']

USER_FILTER = '(&(objectCategory=person)(objectClass=user))'
OU_FILTER = '(objectClass=organizationalUnit)'
GROUP_FILTER = '(&(objectCategory=group)(objectClass=group))'
COMPUTER_FILTER = '(&(objectCategory=computer)(objectClass=computer))'
TRUST_FILTER = '(objectClass=trustedDomain)'


# ================================================================ 异常
class ADError(Exception):
    """AD 操作失败（已翻译为可读中文）。"""

    def __init__(self, message: str, code: str = '', raw: str = ''):
        super().__init__(message)
        self.message = message
        self.code = code
        self.raw = raw


class ADUnavailable(ADError):
    """域控不可达 / 认证失败，属于连接级故障：该域应被标记离线。"""


class DomainDisabled(ADError):
    """域被停用，拒绝操作。"""


# ================================================================ 域上下文
@dataclass
class DomainCtx:
    id: int
    name: str
    domain_name: str
    netbios: str
    dc_host: str
    username: str
    password: str = field(repr=False, default='')
    ldap_port: int = 389
    use_ssl: int = 0
    base_dn: str = ''
    enabled: int = 1
    is_debug: int = 0
    remark: str = ''
    status: str = 'unknown'
    status_msg: str = ''
    forest_name: str = ''
    domain_mode: str = ''
    dns_checked: int = 0

    @property
    def label(self) -> str:
        return f'{self.name}({self.domain_name})'

    @property
    def sid(self) -> str:
        return f'domain#{self.id}'

    @property
    def bind_user(self) -> str:
        """SIMPLE 用 UPN，NTLM 用 DOMAIN\\user。"""
        if '@' in self.username or '\\' in self.username:
            return self.username
        return f'{self.username}@{self.domain_name}'

    @property
    def ntlm_user(self) -> str:
        if '\\' in self.username:
            return self.username
        if '@' in self.username:
            user, dom = self.username.split('@', 1)
            return f'{dom.split(".")[0].upper()}\\{user}'
        return f'{(self.netbios or self.domain_name.split(".")[0]).upper()}\\{self.username}'

    def cache_key(self) -> str:
        """连接缓存键：配置变更后自动失效。"""
        return f'{self.id}|{self.dc_host}|{self.ldap_port}|{self.use_ssl}|{self.username}|{self.enabled}'


def load_domains(only_enabled: bool = False) -> list:
    sql = 'SELECT * FROM ad_domain_conf' + (' WHERE enabled=1' if only_enabled else '') + ' ORDER BY id'
    rows = db.query(sql)
    out = []
    for r in rows:
        try:
            pwd = decrypt_secret(r['password_enc'])
        except Exception as e:
            log.error('域 %s 凭据解密失败: %s', r['name'], e)
            pwd = ''
        out.append(DomainCtx(
            id=r['id'], name=r['name'], domain_name=r['domain_name'],
            netbios=r['netbios_name'] or '', dc_host=r['dc_host'], username=r['username'],
            password=pwd, ldap_port=r['ldap_port'], use_ssl=r['use_ssl'],
            base_dn=r['base_dn'] or _domain_to_dn(r['domain_name']),
            enabled=r['enabled'], is_debug=r['is_debug'], remark=r['remark'] or '',
            status=r['status'], status_msg=r['status_msg'] or '',
            forest_name=r['forest_name'] or '', domain_mode=r['domain_mode'] or '',
            dns_checked=r['dns_checked'] or 0,
        ))
    return out


def get_domain(domain_id: int, only_enabled: bool = False) -> DomainCtx:
    for d in load_domains(only_enabled):
        if d.id == int(domain_id):
            return d
    raise ADError('域不存在或未启用', code='domain_not_found')


def domain_map() -> dict:
    """{id: DomainCtx}，供渲染时显示域名。"""
    return {d.id: d for d in load_domains()}


def _domain_to_dn(domain_name: str) -> str:
    return ','.join('DC=' + p for p in (domain_name or '').strip('.').split('.') if p)


def dn_to_domain(dn: str) -> str:
    parts = [p[3:] for p in (dn or '').split(',') if p.upper().startswith('DC=')]
    return '.'.join(parts)


# ================================================================ 值转换
def uac_enabled(uac: int) -> bool:
    return not bool(int(uac or 0) & UAC_ACCOUNTDISABLE)


def filetime_to_dt(value) -> datetime | None:
    """AD FILETIME → UTC datetime；0 / 空 / 极大值 返回 None。"""
    if value in (None, '', [], 0, '0'):
        return None
    try:
        v = int(value)
    except Exception:
        return None
    if v <= 0 or v >= NEVER_EXPIRE_INT:
        return None
    try:
        return AD_EPOCH + timedelta(microseconds=v / 10)
    except Exception:
        return None


def dt_to_str(dt: datetime | None, fmt: str = '%Y-%m-%d %H:%M:%S') -> str:
    """统一展示格式。
    AD 返回的 generalizedTime（whenCreated/whenChanged）本身是 UTC（带 Z），
    ldap3 只做时区标注不做换算，这里统一转成本地时区展示。
    """
    if not dt:
        return ''
    if dt.tzinfo is not None:
        dt = dt.astimezone()
    return dt.strftime(fmt)


def _ad_time_to_str(e, attr: str) -> str:
    """whenCreated / whenChanged：优先用原始值（可靠 UTC），退回解析值。"""
    try:
        if attr in e and e[attr].raw_values:
            raw = e[attr].raw_values[0]
            if isinstance(raw, bytes):
                raw = raw.decode('ascii', 'ignore')
            s = str(raw).strip()
            if s.endswith('Z'):
                s = s[:-1]
            fmt = '%Y%m%d%H%M%S.%f' if '.' in s else '%Y%m%d%H%M%S'
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            return dt.astimezone().strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        pass
    v = _entry_value(e, attr)
    return dt_to_str(v) if isinstance(v, datetime) else ''


def sid_to_str(raw: bytes) -> str:
    if not raw:
        return ''
    try:
        rev = raw[0]
        count = raw[1]
        auth = int.from_bytes(raw[2:8], 'big')
        subs = [int.from_bytes(raw[8 + i * 4:12 + i * 4], 'little') for i in range(count)]
        return 'S-%d-%d-%s' % (rev, auth, '-'.join(str(s) for s in subs))
    except Exception:
        return ''


# ================================================================ 连接管理
_conn_cache = {}
_conn_lock = threading.Lock()
_health = {}          # domain_id -> {'ok': bool, 'ts': float, 'msg': str}
_health_lock = threading.Lock()


def invalidate_conn(domain_id: int = None) -> None:
    with _conn_lock:
        if domain_id is None:
            for c in _conn_cache.values():
                try:
                    c.unbind()
                except Exception:
                    pass
            _conn_cache.clear()
        else:
            for k in [k for k in _conn_cache if k.startswith(f'{domain_id}|')]:
                try:
                    _conn_cache.pop(k).unbind()
                except Exception:
                    pass


def _ssl_port(d: DomainCtx) -> int:
    """LDAPS 实际端口：用户自定义非默认端口优先，否则 636。"""
    return d.ldap_port if d.ldap_port not in (0, 389) else 636


def _effective_port(d: DomainCtx) -> int:
    """当前连接实际生效端口：SSL 模式返回 LDAPS 端口，明文模式返回 LDAP 端口。"""
    return _ssl_port(d) if d.use_ssl else (d.ldap_port or 389)


def _build_server(d: DomainCtx) -> Server:
    if d.use_ssl:
        # LDAPS 必须走 636（或用户自定义端口）。防御性纠正：若端口仍是明文默认 389，
        # 说明配置矛盾（如编辑时改了 SSL 开关却没同步端口），自动改用 636，避免在
        # 明文端口上做 TLS 握手导致「invalid server address / 远程主机强制关闭连接」。
        tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)
        return Server(d.dc_host, port=_ssl_port(d), use_ssl=True, tls=tls,
                      get_info=ALL, connect_timeout=config.AD_CONNECT_TIMEOUT)
    return Server(d.dc_host, port=d.ldap_port or 389, use_ssl=False,
                  get_info=ALL, connect_timeout=config.AD_CONNECT_TIMEOUT)


def _translate_ldap_error(result: dict, d: DomainCtx = None) -> ADError:
    """把 ldap3 结果翻译成运维可读的中文错误。"""
    desc = (result or {}).get('description') or ''
    message = (result or {}).get('message') or ''
    raw = f'{desc} {message}'.strip()
    low = raw.lower()
    dm = d.domain_name if d else ''
    mapping = [
        ('invalidcredentials', '域管理员账号或密码错误，请检查域配置'),
        ('constraintviolation', '违反域策略约束（如密码复杂度/长度/历史密码不符合要求）'),
        ('entryalreadyexists', '对象已存在（账号或 OU 名称重复）'),
        ('insufficientaccessrights', 'AD 权限不足：请确认该域账号有对应 OU 的委派权限'),
        ('unwillingtoperform', '域控拒绝执行该请求（常见原因：仅允许加密通道修改密码，或功能级别不支持该操作）'),
        ('notallowedonnonleaf', '该对象下还有子对象，不能直接删除'),
        ('objectclassviolation', '对象类型不符合 AD 架构要求'),
        ('invalidattributevalue', '属性值不合法（可能包含特殊字符或格式错误）'),
        ('namingviolation', '对象名称不合法（DN 含非法字符或长度超限）'),
        ('referral', '该对象位于其他域/分区，请切换到对应域操作'),
        ('unavailablecriticalextension', '域控不支持该操作所需的扩展（检查是否为只读域控）'),
        ('busy', '域控繁忙，请稍后重试'),
        ('timelimit', '域控响应超时，请稍后重试'),
        ('size limitexceeded', '结果集超出域控返回上限，请联系管理员调整策略'),
        ('strongauthrequired', 'AD 要求加密通道（LDAPS/STARTTLS）才能完成该操作'),
        ('confidentialityrequired', '该操作要求加密连接，请在域配置中开启 SSL（636 端口）'),
        ('unwilling to perform', '域控拒绝执行该请求'),
    ]
    for key, zh in mapping:
        if key in low:
            return ADError(zh, code=desc, raw=raw)
    if desc in ('invalidCredentials',):
        return ADError('域管理员账号或密码错误，请检查域配置', code=desc, raw=raw)
    return ADError(f'AD 操作失败：{raw or "未知错误"}', code=desc, raw=raw)


def get_connection(d: DomainCtx, force_new: bool = False) -> Connection:
    """
    取该域连接。复用已有绑定；失效自动重连一次。
    连接级错误抛 ADUnavailable（上层据此把域标记为 offline）。
    """
    if not d.enabled:
        raise DomainDisabled(f'域 {d.label} 已停用')
    if not d.password:
        raise ADUnavailable(f'域 {d.label} 凭据缺失，请重新编辑域配置填写密码')
    key = d.cache_key()
    with _conn_lock:
        conn = None if force_new else _conn_cache.get(key)
        if conn is not None and conn.bound:
            return conn
        if conn is not None:
            try:
                conn.unbind()
            except Exception:
                pass
            _conn_cache.pop(key, None)

        server = _build_server(d)
        last_err = None
        modes = []
        mode = (config.AD_AUTH_MODE or 'auto').lower()
        if mode == 'simple':
            modes = [('simple', d.bind_user)]
        elif mode == 'ntlm':
            modes = [('ntlm', d.ntlm_user)]
        else:
            modes = [('simple', d.bind_user), ('ntlm', d.ntlm_user)]

        for kind, user in modes:
            try:
                c = Connection(
                    server, user=user, password=d.password,
                    authentication=SIMPLE if kind == 'simple' else NTLM,
                    auto_bind=AUTO_BIND_NONE, receive_timeout=config.AD_RECEIVE_TIMEOUT,
                    raise_exceptions=False, read_only=False,
                )
                if c.bind():
                    _conn_cache[key] = c
                    log.debug('域 %s 绑定成功（%s）', d.domain_name, kind)
                    return c
                res = c.result
                desc = str(res.get('description', ''))
                if desc == 'invalidCredentials':
                    raise ADUnavailable(
                        f'域 {d.label} 认证失败：管理员账号或密码错误（{kind} 认证）',
                        code='invalidCredentials', raw=str(res))
                last_err = ADError(f'域 {d.label} 绑定失败：{desc} {res.get("message","")}',
                                   code=desc, raw=str(res))
            except ADUnavailable:
                raise
            except Exception as e:
                last_err = ADUnavailable(f'域 {d.label} 无法连接 {d.dc_host}:{d.ldap_port} — {e}',
                                         code='connect_error', raw=str(e))
        raise last_err or ADUnavailable(f'域 {d.label} 连接失败')


def release_conn(d: DomainCtx) -> None:
    """释放（用于批量读，避免长时间持有连接）。"""
    key = d.cache_key()
    with _conn_lock:
        c = _conn_cache.pop(key, None)
    if c is not None:
        try:
            c.unbind()
        except Exception:
            pass


# ================================================================ 健康检查
def mark_health(d: DomainCtx, ok: bool, msg: str = '') -> None:
    with _health_lock:
        prev = _health.get(d.id)
        _health[d.id] = {'ok': ok, 'ts': time.time(), 'msg': msg}
    status = 'online' if ok else 'offline'
    # 只在与库中状态不同或消息变化时写库，减少写放大
    if not prev or prev.get('ok') != ok or prev.get('msg') != msg:
        try:
            db.execute("UPDATE ad_domain_conf SET status=?, status_msg=?, last_check_at=datetime('now','localtime') "
                       "WHERE id=?", (status, (msg or '')[:500], d.id))
        except Exception as e:
            log.debug('更新域状态失败: %s', e)


def health(d: DomainCtx, ttl: int = None) -> tuple:
    """返回 (ok, msg)，带 TTL 缓存，避免每次页面请求都探测。"""
    ttl = config.AD_HEALTH_TTL if ttl is None else ttl
    with _health_lock:
        h = _health.get(d.id)
    if h and (time.time() - h['ts']) < ttl:
        return h['ok'], h['msg']
    return test_connection(d, update_state=True)


def _probe_tcp(host: str, port: int, timeout: float = 4.0) -> tuple:
    """TCP 端口预探测，用于把「网络不通」和「凭据错误」区分开。

    返回 (ok, message)。连接成功返回 (True, '')；失败给出带排查建议的中文说明。
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return True, ''
    except socket.timeout:
        return False, (f'网络不可达：连接 {host}:{port} 超时（{timeout:.0f}s）。'
                       f'请检查域控服务是否在运行、防火墙是否放通该端口、本机到域控的路由是否正常')
    except socket.gaierror as e:
        return False, f'地址解析失败：无法解析主机 {host}（{e}）。请填写域控的 IP 地址或可解析的主机名'
    except ConnectionRefusedError:
        return False, (f'端口被拒绝：{host}:{port} 未监听。'
                       f'域控上对应的 AD 服务可能未启动，或端口已被修改')
    except OSError as e:
        return False, f'网络不可达：连接 {host}:{port} 失败（{e}）'
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def test_connection(d: DomainCtx, update_state: bool = True) -> tuple:
    """
    连通性测试：TCP 预探测 + LDAP 绑定 + 读域根对象。
    返回 (ok, message)；成功时顺带补齐 base_dn / forest / 域功能级别。

    分层诊断：先探测端口，再尝试绑定。这样「网络不通」与「密码错误」会给出
    完全不同的提示，避免运维在密码问题上排查半天网络。
    """
    t0 = time.time()
    reachable, probe_msg = _probe_tcp(d.dc_host, _effective_port(d))
    if not reachable:
        msg = f'域 {d.label} {probe_msg}'
        if update_state:
            mark_health(d, False, msg)
        return False, msg
    try:
        conn = get_connection(d, force_new=True)
        if not conn.search(d.base_dn, '(objectClass=*)', search_scope='BASE',
                           attributes=['distinguishedName', 'msDS-Behavior-Version', 'objectSid'],
                           size_limit=1):
            raise ADUnavailable(f'域 {d.label} 绑定成功但无法读取域根 {d.base_dn}：'
                                f'{conn.result.get("description")}')
        info = {'base_dn': d.base_dn, 'domain_mode': '', 'sid': '', 'forest': ''}
        if conn.entries:
            e = conn.entries[0]
            if 'msDS-Behavior-Version' in e:
                info['domain_mode'] = _mode_name(e['msDS-Behavior-Version'].value)
            if 'objectSid' in e:
                info['sid'] = sid_to_str(e['objectSid'].raw_values[0]
                                         if e['objectSid'].raw_values else b'')
        # 林名：从 Configuration 分区命名上下文推断
        try:
            naming = conn.server.info.other.get('configurationNamingContext') or []
            if naming:
                info['forest'] = dn_to_domain(naming[0])
        except Exception:
            pass
        if update_state:
            sets = ['base_dn=?', "status='online'", 'status_msg=?', 'last_check_at=datetime(\'now\',\'localtime\')']
            params = [info['base_dn'], f'LDAP 连接正常（{int((time.time()-t0)*1000)}ms）']
            if info['domain_mode']:
                sets.append('domain_mode=?')
                params.append(info['domain_mode'])
            if info['sid']:
                sets.append('domain_sid=?')
                params.append(info['sid'])
            sets.append('forest_name=?')
            params.append(info['forest'])
            params.append(d.id)
            db.execute(f'UPDATE ad_domain_conf SET {", ".join(sets)} WHERE id=?', tuple(params))
        mark_health(d, True, f'LDAP 连接正常（{int((time.time()-t0)*1000)}ms）')
        return True, f'连接成功：{d.dc_host}:{d.ldap_port}，域根 {d.base_dn or info["base_dn"]}'
    except ADError as e:
        if update_state:
            mark_health(d, False, e.message)
        return False, e.message
    except Exception as e:
        msg = f'域 {d.label} 连接异常：{e}'
        if update_state:
            mark_health(d, False, msg)
        return False, msg
    finally:
        invalidate_conn(d.id)


def require_online(d: DomainCtx) -> None:
    """写操作前置：域离线则直接拒绝（只读不写，故障隔离）。"""
    ok, msg = health(d, ttl=config.AD_WRITE_HEALTH_TTL)
    if not ok:
        raise ADUnavailable(f'域 {d.label} 当前不可用（{msg}），该域已置为只读，禁止修改操作')


def _mode_name(v) -> str:
    try:
        v = int(v)
    except Exception:
        return ''
    return {0: 'Windows2000', 1: 'Windows2003Interim', 2: 'Windows2003', 3: 'Windows2008',
            4: 'Windows2008R2', 5: 'Windows2012', 6: 'Windows2012R2', 7: 'Windows2016'}.get(v, str(v))


# ================================================================ 通用搜索
def search(d: DomainCtx, base_dn: str, ldap_filter: str, attributes: list, page_size: int = None,
           size_limit: int = None) -> list:
    """分页搜索，返回 ldap3 Entry 列表。"""
    conn = get_connection(d)
    page_size = page_size or config.AD_PAGE_SIZE
    out = []
    try:
        cookie = None
        while True:
            ok = conn.search(base_dn or d.base_dn, ldap_filter,
                             search_scope='SUBTREE', attributes=attributes,
                             paged_size=page_size, paged_cookie=cookie,
                             size_limit=size_limit or 0,
                             time_limit=60)
            if not ok:
                # AD 在"无匹配对象"时可能返回空 results + success，属正常情况
                if not (conn.result or {}).get('message') and (conn.result or {}).get('description') == 'success':
                    break
                err = _translate_ldap_error(conn.result, d)
                if err.code == 'sizeLimitExceeded' and out:
                    break
                raise err
            out.extend(conn.response)
            cookie = (conn.result or {}).get('controls', {}).get('1.2.840.113556.1.4.319', {}).get(
                'value', {}).get('cookie')
            if not cookie:
                break
        return conn.entries
    except ADUnavailable:
        raise
    except ADError:
        raise
    except Exception as e:
        # 连接中断 → 丢弃连接，下次重连
        invalidate_conn(d.id)
        raise ADUnavailable(f'域 {d.label} 查询失败：{e}', code='search_error', raw=str(e))


def _entry_value(e, name):
    try:
        if name in e:
            return e[name].value
    except Exception:
        pass
    return None


def _entry_str(e, name, default='') -> str:
    v = _entry_value(e, name)
    if v is None or v == []:
        return default
    if isinstance(v, list):
        v = v[0] if v else default
    return str(v)


def _entry_int(e, name, default=0) -> int:
    v = _entry_value(e, name)
    if v is None or v == []:
        return default
    if isinstance(v, list):
        return int(v[0]) if v else default
    try:
        return int(v)
    except Exception:
        return default


# ================================================================ 元数据
def domain_meta(d: DomainCtx) -> dict:
    """域根 + defaultNamingContext 等元数据。用于同步和林信任。"""
    conn = get_connection(d)
    meta = {'base_dn': d.base_dn, 'config_nc': '', 'root_domain_dn': '', 'domain_sid': '',
            'domain_mode': '', 'forest': '', 'netbios': '', 'max_pwd_age_days': None,
            'domain_name': d.domain_name}
    try:
        # 命名上下文属于根 DSE（server.info.other），不是域对象属性
        other = {}
        try:
            info = conn.server.info
            if info is not None:
                other = {k.lower(): v for k, v in (info.other or {}).items()}
        except Exception:
            pass

        def _first(key):
            v = other.get(key)
            if not v:
                return ''
            return v[0] if isinstance(v, (list, tuple)) else str(v)

        if not conn.search(d.base_dn, '(objectClass=*)', search_scope='BASE',
                           attributes=['distinguishedName', 'msDS-Behavior-Version', 'objectSid',
                                       'maxPwdAge', 'name'],
                           size_limit=1):
            raise _translate_ldap_error(conn.result, d)
        e = conn.entries[0]
        dn = _entry_str(e, 'distinguishedName')
        meta['base_dn'] = dn or d.base_dn
        meta['config_nc'] = _first('configurationnamingcontext') or (
            f'CN=Configuration,{dn}' if dn else '')
        meta['root_domain_dn'] = _first('rootdomainnamingcontext') or meta['config_nc']
        meta['domain_sid'] = sid_to_str(e['objectSid'].raw_values[0]
                                        if 'objectSid' in e and e['objectSid'].raw_values else b'')
        meta['domain_mode'] = _mode_name(_entry_value(e, 'msDS-Behavior-Version'))
        if meta['root_domain_dn']:
            meta['forest'] = dn_to_domain(meta['root_domain_dn'])
        elif meta['config_nc']:
            meta['forest'] = dn_to_domain(meta['config_nc'])
        meta['domain_name'] = dn_to_domain(dn) or d.domain_name
        netbios = _entry_str(e, 'name')
        meta['netbios'] = (d.netbios or (netbios.split(',')[0].split('=')[-1] if netbios else '')).upper()
        try:
            age = _entry_value(e, 'maxPwdAge')
            if age not in (None, [], '0', 0):
                meta['max_pwd_age_days'] = abs(int(age)) / 864000000000.0
        except Exception:
            pass
        return meta
    except ADError:
        raise
    except Exception as e:
        invalidate_conn(d.id)
        raise ADUnavailable(f'域 {d.label} 读取域信息失败：{e}')


# ================================================================ 用户：读
PAGE_USER_CACHE_COLUMNS = (
    'domain_id', 'dn', 'sam_account_name', 'display_name', 'cn', 'given_name', 'sn',
    'user_principal_name', 'mail', 'telephone', 'mobile', 'title', 'department', 'company',
    'description', 'ou_dn', 'sam_account_type', 'user_account_control', 'enabled', 'locked',
    'pwd_never_expires', 'pwd_last_set', 'pwd_expires_at', 'last_logon', 'usn',
    'when_created', 'when_changed',
)


def entry_to_user_row(e, d: DomainCtx, max_pwd_age_days=None) -> dict:
    dn = e.entry_dn
    uac = _entry_int(e, 'userAccountControl', UAC_NORMAL_ACCOUNT)
    raw_pwd_last = _entry_value(e, 'pwdLastSet')
    try:
        pwd_last_int = int(raw_pwd_last) if raw_pwd_last not in (None, []) else None
    except Exception:
        pwd_last_int = None
    pwd_never_set = (pwd_last_int == 0)              # 从未设置密码：不能登录，不能算"永不过期"
    pwd_last_set_dt = filetime_to_dt(raw_pwd_last)
    last_logon = filetime_to_dt(_entry_value(e, 'lastLogonTimestamp'))
    lockout = _entry_int(e, 'lockoutTime', 0)
    expires = None
    raw_exp = _entry_value(e, 'msDS-UserPasswordExpiryTimeComputed')
    try:
        ival = int(raw_exp) if raw_exp not in (None, [], '') else None
    except Exception:
        ival = None
    if pwd_never_set:
        expires = None
    elif ival and 0 < ival < NEVER_EXPIRE_INT:
        expires = AD_EPOCH + timedelta(microseconds=ival / 10)
    elif pwd_last_set_dt and max_pwd_age_days and not (uac & UAC_DONT_EXPIRE_PASSWORD):
        expires = pwd_last_set_dt + timedelta(days=max_pwd_age_days)
    pwd_never = bool(uac & UAC_DONT_EXPIRE_PASSWORD)
    if pwd_never:
        expires = None
    ou_dn = dn.split(',', 1)[1] if ',' in dn else d.base_dn
    return {
        'domain_id': d.id,
        'dn': dn,
        'sam_account_name': _entry_str(e, 'sAMAccountName'),
        'display_name': _entry_str(e, 'displayName') or _entry_str(e, 'cn'),
        'cn': _entry_str(e, 'cn'),
        'given_name': _entry_str(e, 'givenName'),
        'sn': _entry_str(e, 'sn'),
        'user_principal_name': _entry_str(e, 'userPrincipalName'),
        'mail': _entry_str(e, 'mail'),
        'telephone': _entry_str(e, 'telephoneNumber'),
        'mobile': _entry_str(e, 'mobile'),
        'title': _entry_str(e, 'title'),
        'department': _entry_str(e, 'department'),
        'company': _entry_str(e, 'company'),
        'description': _entry_str(e, 'description'),
        'ou_dn': ou_dn,
        'sam_account_type': str(_entry_value(e, 'sAMAccountType') or ''),
        'user_account_control': uac,
        'enabled': 1 if uac_enabled(uac) else 0,
        'locked': 1 if lockout > 0 else 0,
        'pwd_never_expires': 1 if (pwd_never and not pwd_never_set) else 0,
        'pwd_last_set': dt_to_str(pwd_last_set_dt) or ('从未设置' if pwd_never_set else ''),
        'pwd_expires_at': dt_to_str(expires),
        'last_logon': dt_to_str(last_logon),
        'usn': _entry_int(e, 'uSNChanged', 0),
        'when_created': _ad_time_to_str(e, 'whenCreated'),
        'when_changed': _ad_time_to_str(e, 'whenChanged'),
    }


def list_users(d: DomainCtx, max_pwd_age_days=None) -> list:
    if max_pwd_age_days is None:
        max_pwd_age_days = _pwd_age(d)
    entries = search(d, d.base_dn, USER_FILTER, USER_ATTRS)
    return [entry_to_user_row(e, d, max_pwd_age_days) for e in entries]


def list_users_by_usn(d: DomainCtx, after_usn: int, max_pwd_age_days=None) -> list:
    """uSNChanged 增量拉取（>= 以便幂等重放，不丢变更）。"""
    if max_pwd_age_days is None:
        max_pwd_age_days = _pwd_age(d)
    flt = f'(&{USER_FILTER}(uSNChanged>={int(after_usn)}))'
    entries = search(d, d.base_dn, flt, USER_ATTRS)
    return [entry_to_user_row(e, d, max_pwd_age_days) for e in entries]


_pwd_age_cache = {}
_pwd_age_lock = threading.Lock()


def _pwd_age(d: DomainCtx, ttl: float = 600):
    """密码最大有效期（天），带缓存；取不到时退回 None（不计算过期时间）。"""
    with _pwd_age_lock:
        c = _pwd_age_cache.get(d.id)
    if c and (time.time() - c[0]) < ttl:
        return c[1]
    try:
        v = domain_meta(d).get('max_pwd_age_days')
    except Exception:
        v = None
    with _pwd_age_lock:
        _pwd_age_cache[d.id] = (time.time(), v)
    return v


def get_user_dn_list(d: DomainCtx) -> set:
    entries = search(d, d.base_dn, USER_FILTER, ['distinguishedName'])
    return {e.entry_dn for e in entries}


def list_ous(d: DomainCtx) -> list:
    entries = search(d, d.base_dn, OU_FILTER, OU_ATTRS)
    rows = []
    for e in entries:
        dn = e.entry_dn
        parent = dn.split(',', 1)[1] if ',' in dn else d.base_dn
        rows.append({
            'domain_id': d.id, 'dn': dn,
            'name': _entry_str(e, 'ou') or _entry_str(e, 'name') or dn.split(',')[0][3:],
            'parent_dn': parent,
            'description': _entry_str(e, 'description'),
            'depth': max(0, dn.count(',') - d.base_dn.count(',')),
            'usn': _entry_int(e, 'uSNChanged', 0),
            'when_created': _ad_time_to_str(e, 'whenCreated'),
        })
    rows.sort(key=lambda r: r['dn'])
    return rows


def list_ous_by_usn(d: DomainCtx, after_usn: int) -> list:
    flt = f'(&{OU_FILTER}(uSNChanged>={int(after_usn)}))'
    entries = search(d, d.base_dn, flt, OU_ATTRS)
    rows = []
    for e in entries:
        dn = e.entry_dn
        parent = dn.split(',', 1)[1] if ',' in dn else d.base_dn
        rows.append({
            'domain_id': d.id, 'dn': dn,
            'name': _entry_str(e, 'ou') or _entry_str(e, 'name') or dn.split(',')[0][3:],
            'parent_dn': parent,
            'description': _entry_str(e, 'description'),
            'depth': max(0, dn.count(',') - d.base_dn.count(',')),
            'usn': _entry_int(e, 'uSNChanged', 0),
            'when_created': _ad_time_to_str(e, 'whenCreated'),
        })
    return rows


def list_groups(d: DomainCtx) -> list:
    entries = search(d, d.base_dn, GROUP_FILTER, GROUP_ATTRS)
    rows = []
    for e in entries:
        gt = _entry_int(e, 'groupType', 0)
        scope = {-2147483648: 'DomainLocal', -2147483647: 'Global', -2147483646: 'Universal'}.get(gt, '')
        if not scope:
            # 带 0x80000000 符号位
            base = gt & 0x7FFFFFFF
            scope = {0: 'DomainLocal', 2: 'Global', 4: 'Universal'}.get(base, 'Unknown')
        category = 'Security' if gt & 0x80000000 else 'Distribution'
        members = _entry_value(e, 'member') or []
        if not isinstance(members, list):
            members = [members]
        dn = e.entry_dn
        rows.append({
            'domain_id': d.id, 'dn': dn,
            'name': _entry_str(e, 'cn'),
            'sam_account_name': _entry_str(e, 'sAMAccountName'),
            'scope': scope, 'category': category,
            'description': _entry_str(e, 'description'),
            'mail': _entry_str(e, 'mail'),
            'ou_dn': dn.split(',', 1)[1] if ',' in dn else d.base_dn,
            'member_count': len(members),
            'usn': _entry_int(e, 'uSNChanged', 0),
        })
    return rows


def list_computers(d: DomainCtx) -> list:
    entries = search(d, d.base_dn, COMPUTER_FILTER, COMPUTER_ATTRS)
    rows = []
    for e in entries:
        uac = _entry_int(e, 'userAccountControl', 0x1000)
        dn = e.entry_dn
        rows.append({
            'domain_id': d.id, 'dn': dn,
            'name': _entry_str(e, 'cn'),
            'dns_host_name': _entry_str(e, 'dNSHostName'),
            'operating_system': _entry_str(e, 'operatingSystem'),
            'os_version': _entry_str(e, 'operatingSystemVersion'),
            'description': _entry_str(e, 'description'),
            'ou_dn': dn.split(',', 1)[1] if ',' in dn else d.base_dn,
            'enabled': 1 if uac_enabled(uac) else 0,
            'last_logon': dt_to_str(filetime_to_dt(_entry_value(e, 'lastLogonTimestamp'))),
            'when_created': _ad_time_to_str(e, 'whenCreated'),
            'usn': _entry_int(e, 'uSNChanged', 0),
        })
    return rows


# ================================================================ 用户：实时详情
def user_realtime(d: DomainCtx, dn: str) -> dict:
    """
    用户详情页实时单条拉取：锁定状态、密码过期时间、上次登录时间等。
    不可达时返回 {'ok': False, 'error': ...}，页面降级展示缓存值。
    """
    try:
        conn = get_connection(d)
        ok = conn.search(dn, '(objectClass=*)', search_scope='BASE',
                         attributes=['lockoutTime', 'badPwdCount', 'pwdLastSet',
                                     'msDS-UserPasswordExpiryTimeComputed', 'lastLogon',
                                     'lastLogonTimestamp', 'logonCount', 'userAccountControl',
                                     'memberOf', 'whenChanged', 'accountExpires', 'lastLogoff'],
                         size_limit=1)
        if not ok or not conn.entries:
            return {'ok': False, 'error': _translate_ldap_error(conn.result, d).message}
        e = conn.entries[0]
        meta = {}
        try:
            meta = domain_meta(d)
        except Exception:
            pass
        lockout = _entry_int(e, 'lockoutTime', 0)
        uac = _entry_int(e, 'userAccountControl', 512)
        raw_pwd_last = _entry_value(e, 'pwdLastSet')
        try:
            pwd_last_int = int(raw_pwd_last) if raw_pwd_last not in (None, []) else None
        except Exception:
            pwd_last_int = None
        pwd_never_set = (pwd_last_int == 0)
        expires_raw = _entry_value(e, 'msDS-UserPasswordExpiryTimeComputed')
        try:
            ival = int(expires_raw) if expires_raw not in (None, [], '') else None
        except Exception:
            ival = None
        pwd_expires = None
        if pwd_never_set:
            pwd_expires = '密码从未设置'
        elif ival and 0 < ival < NEVER_EXPIRE_INT:
            pwd_expires = dt_to_str(AD_EPOCH + timedelta(microseconds=ival / 10))
        elif not (uac & UAC_DONT_EXPIRE_PASSWORD) and ival != NEVER_EXPIRE_INT:
            pls = filetime_to_dt(raw_pwd_last)
            if pls and meta.get('max_pwd_age_days'):
                pwd_expires = dt_to_str(pls + timedelta(days=meta['max_pwd_age_days']))
        last_logon = filetime_to_dt(_entry_value(e, 'lastLogon'))
        last_logon_ts = filetime_to_dt(_entry_value(e, 'lastLogonTimestamp'))
        account_expires = filetime_to_dt(_entry_value(e, 'accountExpires'))
        groups = _entry_value(e, 'memberOf') or []
        if not isinstance(groups, list):
            groups = [groups]
        return {
            'ok': True,
            'locked': lockout > 0,
            'lockout_time': dt_to_str(filetime_to_dt(lockout)) or ('未锁定' if not lockout else ''),
            'bad_pwd_count': _entry_int(e, 'badPwdCount', 0),
            'enabled': uac_enabled(uac),
            'uac': uac,
            'pwd_never_expires': bool(uac & UAC_DONT_EXPIRE_PASSWORD),
            'pwd_last_set': ('从未设置' if pwd_never_set else dt_to_str(filetime_to_dt(raw_pwd_last))),
            'pwd_expires_at': pwd_expires or ('永不过期' if uac & UAC_DONT_EXPIRE_PASSWORD else ''),
            'last_logon': dt_to_str(last_logon),
            'last_logon_timestamp': dt_to_str(last_logon_ts),
            'logon_count': _entry_int(e, 'logonCount', 0),
            'account_expires': dt_to_str(account_expires) or '永不过期',
            'when_changed': _ad_time_to_str(e, 'whenChanged'),
            'groups': [str(g) for g in groups],
            'fetched_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
    except ADError as e:
        return {'ok': False, 'error': e.message}
    except Exception as e:
        return {'ok': False, 'error': f'实时查询失败：{e}'}


# ================================================================ 写入结果判定
def _check(d: DomainCtx, conn, ok: bool, action_hint: str = '') -> None:
    if ok:
        return
    res = conn.result or {}
    desc = str(res.get('description', ''))
    # 连接级问题：标记离线
    if desc in ('unavailable', 'connectError', 'invalidCredentials', 'localError'):
        msg = _translate_ldap_error(res, d).message
        mark_health(d, False, msg)
        invalidate_conn(d.id)
        raise ADUnavailable(msg, code=desc, raw=str(res))
    raise _translate_ldap_error(res, d)


def _exists(conn, dn: str) -> bool:
    try:
        return bool(conn.search(dn, '(objectClass=*)', search_scope='BASE', attributes=['1.1'], size_limit=1))
    except Exception:
        return False


def _escape_dn_component(name: str) -> str:
    """DN 转义：去掉会破坏 DN 的字符，合并多余空白。"""
    name = (name or '').strip()
    name = re.sub(r'\s+', ' ', name)
    name = name.replace('\\', '').replace('/', '').replace(',', '，')
    name = name.replace('+', '').replace('"', '').replace('<', '').replace('>', '')
    name = name.replace(';', '').replace('=', '')
    if not name:
        raise ADError('名称不能为空')
    if len(name) > 64:
        raise ADError('名称长度不能超过 64 个字符')
    return name


def _escape_rdn_value(name: str) -> str:
    name = _escape_dn_component(name)
    if name.startswith(' ') or name.endswith(' '):
        name = name.strip()
    if name[0] in '#':
        name = '\\' + name
    return name


# ================================================================ 用户：写
def create_user(d: DomainCtx, data: dict) -> dict:
    """新增用户。data: sam, password, ou_dn, display_name, given_name, sn, upn, mail, ..."""
    require_online(d)
    sam = (data.get('sam_account_name') or '').strip()
    if not sam:
        raise ADError('登录名（sAMAccountName）必填')
    if len(sam) > 20:
        raise ADError('登录名不能超过 20 个字符（AD 限制）')
    if not re.match(r'^[A-Za-z0-9._\-]+$', sam):
        raise ADError('登录名只能包含字母、数字、点、下划线、短横线')
    pwd = data.get('password') or ''
    if not pwd:
        raise ADError('初始密码必填')
    ou_dn = data.get('ou_dn') or d.base_dn
    display = (data.get('display_name') or sam).strip()
    # CN 与 DN 必须同时确定：未填显示名时 CN 用登录名，否则用显示名
    cn_raw = (data.get('display_name') or '').strip() or sam
    cn = _escape_rdn_value(cn_raw)
    dn = f'CN={cn},{ou_dn}'
    conn = get_connection(d)
    if _exists(conn, dn):
        raise ADError(f'该 OU 下已存在同名对象：{cn_raw}')
    attrs = {
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'sAMAccountName': sam,
        'userPrincipalName': (data.get('user_principal_name') or f'{sam}@{d.domain_name}').strip(),
        'displayName': display,
        'cn': cn,
    }
    if data.get('given_name'):
        attrs['givenName'] = data['given_name'].strip()
    sn = (data.get('sn') or '').strip()
    attrs['sn'] = sn or (cn_raw[:1] if cn_raw else sam)   # AD 要求 person 必须有 sn
    for ad_attr, key in (('mail', 'mail'), ('telephoneNumber', 'telephone'),
                         ('mobile', 'mobile'), ('title', 'title'),
                         ('department', 'department'), ('company', 'company'),
                         ('description', 'description')):
        v = (data.get(key) or '').strip()
        if v:
            attrs[ad_attr] = v
    ok = conn.add(dn, attributes=attrs)
    _check(d, conn, ok, 'create_user')
    # 设置密码 + 启用账号（先创建禁用态再设置密码，避免空密码窗口）
    try:
        if data.get('enabled', True):
            _set_password_internal(d, conn, dn, pwd, must_change=data.get('must_change_password', True))
            _enable_user_internal(d, conn, dn)
        else:
            _set_password_internal(d, conn, dn, pwd, must_change=data.get('must_change_password', True))
    except Exception:
        # 密码设置失败 → 回滚刚创建的用户，避免留下无密码账号
        try:
            conn.delete(dn)
        except Exception:
            pass
        raise
    # 允许把新用户直接加入组
    for gdn in data.get('group_dns') or []:
        add_group_members(d, gdn, [dn], skip_health=True)
    return {'dn': dn, 'sam_account_name': sam, 'password': pwd}


def _secure_connection(d: DomainCtx) -> Connection:
    """
    获取"加密通道"连接（修改 unicodePwd 的硬性要求）：
    优先 LDAPS 636；不可用时尝试 STARTTLS；都不可用则抛错并给出配置指引。
    结果按域缓存，避免每次改密码都探测。
    """
    key = f'secure:{d.id}|{d.dc_host}'
    with _conn_lock:
        c = _conn_cache.get(key)
        if c is not None and c.bound:
            return c
    errors = []
    # 1) LDAPS
    for port in (_ssl_port(d),):
        try:
            tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)
            srv = Server(d.dc_host, port=port or 636, use_ssl=True, tls=tls,
                         get_info=ALL, connect_timeout=config.AD_CONNECT_TIMEOUT)
            c = Connection(srv, user=d.bind_user, password=d.password, auto_bind=AUTO_BIND_NONE,
                           receive_timeout=config.AD_RECEIVE_TIMEOUT, raise_exceptions=False)
            if c.bind():
                with _conn_lock:
                    _conn_cache[key] = c
                return c
            errors.append(f'LDAPS {port}: {c.result.get("description")}')
        except Exception as e:
            errors.append(f'LDAPS {port}: {e}')
    # 2) STARTTLS
    try:
        tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)
        srv = Server(d.dc_host, port=d.ldap_port or 389, use_ssl=False, tls=tls,
                     get_info=ALL, connect_timeout=config.AD_CONNECT_TIMEOUT)
        c = Connection(srv, user=d.bind_user, password=d.password, auto_bind=AUTO_BIND_NONE,
                       receive_timeout=config.AD_RECEIVE_TIMEOUT, raise_exceptions=False)
        if c.open() and c.start_tls() and c.bind():
            with _conn_lock:
                _conn_cache[key] = c
            return c
        errors.append(f'STARTTLS: {c.result}')
    except Exception as e:
        errors.append(f'STARTTLS: {e}')
    raise ADError('该域不支持明文连接修改密码：域控 636(LDAPS) 与 STARTTLS 均不可用。'
                  '请在域配置中开启 SSL（端口 636）后重试，并确认域控已部署证书。'
                  f'（{"；".join(errors[:2])}）', code='strongAuthRequired')


def _set_password_internal(d: DomainCtx, conn, dn: str, pwd: str, must_change: bool = True):
    """
    修改密码：AD 只允许在加密通道上写 unicodePwd。
    先尝试当前连接（已是 LDAPS 时直接成功）；失败再走 _secure_connection()。
    """
    last_err = None
    candidates = [conn]
    secure = None
    if not d.use_ssl:
        try:
            secure = _secure_connection(d)
            candidates = [secure]
        except ADError as e:
            last_err = e
    for c in candidates:
        try:
            if _HAS_MS_EXT:
                ok = ad_modify_password(c, dn, pwd, None)
                if ok:
                    if must_change:
                        c.modify(dn, {'pwdLastSet': [(MODIFY_REPLACE, [0])]})
                    return
                res = c.result or {}
                low = str(res).lower()
                if 'unwilling' in low or 'confidentiality' in low or 'strongauth' in low:
                    last_err = ADError('域控要求加密通道才能修改密码', code=str(res.get('description')))
                    continue
                last_err = _translate_ldap_error(res, d)
                break
            else:                                                # pragma: no cover
                ok = c.extend.microsoft.modify_password(dn, pwd)
                _check(d, c, ok)
                return
        except ADError:
            raise
        except Exception as e:
            last_err = ADError(f'设置密码失败：{e}')
    if isinstance(last_err, ADError) and last_err.code in (
            'unwillingToPerform', 'confidentialityRequired', 'strongAuthRequired', 'operationsError'):
        # 再兜底一次：强制换加密连接重试
        try:
            sc = _secure_connection(d)
            if ad_modify_password(sc, dn, pwd, None):
                if must_change:
                    sc.modify(dn, {'pwdLastSet': [(MODIFY_REPLACE, [0])]})
                return
        except ADError as e:
            raise e
    raise last_err or ADError('设置密码失败：未知原因')


def _enable_user_internal(d: DomainCtx, conn, dn: str):
    uac = _get_uac(conn, dn)
    if uac is None:
        raise ADError('读取用户 userAccountControl 失败')
    new_uac = (uac & ~UAC_ACCOUNTDISABLE)
    ok = conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
    _check(d, conn, ok)


def _get_uac(conn, dn: str):
    if not conn.search(dn, '(objectClass=*)', search_scope='BASE',
                       attributes=['userAccountControl'], size_limit=1):
        return None
    try:
        return int(conn.entries[0]['userAccountControl'].value)
    except Exception:
        return None


def reset_password(d: DomainCtx, dn: str, new_pwd: str, must_change: bool = False,
                   unlock: bool = True) -> None:
    require_online(d)
    conn = get_connection(d)
    if not _exists(conn, dn):
        raise ADError('用户不存在（可能已被删除），请刷新列表')
    _set_password_internal(d, conn, dn, new_pwd, must_change=must_change)
    if unlock:
        try:
            set_unlock(d, dn)
        except Exception:
            pass


def set_enabled(d: DomainCtx, dn: str, enabled: bool) -> int:
    require_online(d)
    conn = get_connection(d)
    uac = _get_uac(conn, dn)
    if uac is None:
        raise ADError('用户不存在或无法读取属性')
    new_uac = (uac & ~UAC_ACCOUNTDISABLE) if enabled else (uac | UAC_ACCOUNTDISABLE)
    ok = conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
    _check(d, conn, ok)
    return new_uac


def set_unlock(d: DomainCtx, dn: str) -> None:
    require_online(d)
    conn = get_connection(d)
    if _HAS_MS_EXT:
        ok = ad_unlock_account(conn, dn)
        if not ok:
            res = conn.result or {}
            # 已解锁（lockoutTime 已是 0）时 AD 可能返回 noSuchAttribute/other，视为成功
            if str(res.get('description')) in ('noSuchAttribute', 'operationsError'):
                return
            raise _translate_ldap_error(res, d)
    else:                                                        # pragma: no cover
        ok = conn.modify(dn, {'lockoutTime': [(MODIFY_REPLACE, ['0'])]})
        _check(d, conn, ok)


def update_user(d: DomainCtx, dn: str, data: dict) -> dict:
    """编辑用户属性。返回 {dn, renamed} 以便缓存跟随新 DN。"""
    require_online(d)
    conn = get_connection(d)
    if not _exists(conn, dn):
        raise ADError('用户不存在（可能已被删除），请刷新列表')
    changes = {}
    field_map = {
        'display_name': 'displayName', 'given_name': 'givenName', 'sn': 'sn',
        'mail': 'mail', 'telephone': 'telephoneNumber', 'mobile': 'mobile',
        'title': 'title', 'department': 'department', 'company': 'company',
        'description': 'description', 'user_principal_name': 'userPrincipalName',
    }
    for key, ad_attr in field_map.items():
        if key in data:
            v = (data.get(key) or '').strip()
            changes[ad_attr] = [(MODIFY_REPLACE, [v] if v else [])]
    if changes:
        ok = conn.modify(dn, changes)
        _check(d, conn, ok)
    new_dn = dn
    # CN 重命名（displayName 与 CN 同步，保证列表名称一致）
    if 'cn' in data or 'display_name' in data:
        new_cn = (data.get('cn') or data.get('display_name') or '').strip()
        if new_cn:
            new_cn = _escape_rdn_value(new_cn)
            old_rdn = dn.split(',', 1)[0]
            if old_rdn[3:] != new_cn:
                ok = conn.modify_dn(dn, f'CN={new_cn}', delete_old_dn=True)
                _check(d, conn, ok)
                new_dn = f'CN={new_cn},{dn.split(",", 1)[1]}'
                if 'displayName' not in changes:
                    conn.modify(new_dn, {'displayName': [(MODIFY_REPLACE, [new_cn])]})
    return {'dn': new_dn, 'old_dn': dn}


def move_user(d: DomainCtx, dn: str, target_ou_dn: str) -> str:
    require_online(d)
    if not target_ou_dn:
        raise ADError('目标 OU 不能为空')
    if dn.split(',', 1)[1].lower() == target_ou_dn.lower():
        return dn
    conn = get_connection(d)
    if not _exists(conn, dn):
        raise ADError('用户不存在（可能已被删除），请刷新列表')
    ok = conn.modify_dn(dn, dn.split(',', 1)[0], new_superior=target_ou_dn)
    _check(d, conn, ok)
    return f'{dn.split(",", 1)[0]},{target_ou_dn}'


def delete_user(d: DomainCtx, dn: str) -> None:
    require_online(d)
    conn = get_connection(d)
    if not _exists(conn, dn):
        raise ADError('用户不存在或已被删除')
    ok = conn.delete(dn)
    _check(d, conn, ok)


def offboard_user(d: DomainCtx, dn: str, offboard_ou: str = '', disable: bool = True) -> dict:
    """离职一键处理：移除所有组成员关系 + 禁用账号 + 可选移动到离职 OU。

    步骤可独立失败但不中断（组移除失败只告警，不阻断禁用/移动），保证核心的
    「禁用」一定执行，避免离职账号残留可登录状态。
    """
    require_online(d)
    conn = get_connection(d)
    if not _exists(conn, dn):
        raise ADError('用户不存在或已被删除')
    removed = []
    failed_groups = []
    try:
        conn.search(dn, '(objectClass=*)', search_scope='BASE', attributes=['memberOf'])
        if conn.entries:
            g = _entry_value(conn.entries[0], 'memberOf') or []
            gs = [g] if isinstance(g, str) else list(g)
            for gdn in gs:
                try:
                    remove_group_members(d, gdn, [dn])
                    removed.append(gdn)
                except Exception as e:
                    failed_groups.append(f'{gdn}({e})')
    except Exception as e:
        log.warning('离职读取组成员失败 %s: %s', dn, e)
    if disable:
        set_enabled(d, dn, False)
    new_dn = dn
    if offboard_ou:
        new_dn = move_user(d, dn, offboard_ou)
    return {'dn': new_dn, 'groups_removed': len(removed), 'failed_groups': failed_groups}


def add_group_members(d: DomainCtx, group_dn: str, member_dns: list, skip_health=False) -> None:
    if not skip_health:
        require_online(d)
    if not member_dns:
        return
    conn = get_connection(d)
    if _HAS_MS_EXT:
        ok = ad_add_members_to_groups(conn, member_dns, group_dn, fix=True)
        if ok:
            return
        res = conn.result or {}
        # 部分成员已在组内时 AD 报 entryAlreadyExists，逐条重试以得到准确结果
        desc = str(res.get('description', ''))
        if desc == 'entryAlreadyExists' or 'already' in str(res.get('message', '')).lower():
            failed = []
            for m in member_dns:
                try:
                    if not _HAS_MS_EXT or not ad_add_members_to_groups(conn, [m], group_dn):
                        failed.append(m)
                except Exception as ex:
                    failed.append(f'{m}({ex})')
            if failed:
                raise ADError(f'部分成员添加失败：{"; ".join(failed[:5])}')
            return
        raise _translate_ldap_error(res, d)
    ok = conn.modify(group_dn, {'member': [(MODIFY_ADD, member_dns)]})
    _check(d, conn, ok)


def remove_group_members(d: DomainCtx, group_dn: str, member_dns: list) -> None:
    require_online(d)
    if not member_dns:
        return
    conn = get_connection(d)
    if _HAS_MS_EXT:
        ok = ad_remove_members_from_groups(conn, member_dns, group_dn, fix=True)
        if ok:
            return
        raise _translate_ldap_error(conn.result or {}, d)
    ok = conn.modify(group_dn, {'member': [(MODIFY_DELETE, member_dns)]})
    _check(d, conn, ok)


# ================================================================ OU：写
def create_ou(d: DomainCtx, parent_dn: str, name: str, description: str = '') -> str:
    require_online(d)
    parent_dn = parent_dn or d.base_dn
    name_clean = _escape_rdn_value(name)
    dn = f'OU={name_clean},{parent_dn}'
    conn = get_connection(d)
    if _exists(conn, dn):
        raise ADError(f'该位置已存在同名 OU：{name}')
    attrs = {'objectClass': ['top', 'organizationalUnit'], 'ou': name_clean}
    if description:
        attrs['description'] = description
    ok = conn.add(dn, attributes=attrs)
    _check(d, conn, ok)
    return dn


def update_ou(d: DomainCtx, dn: str, data: dict) -> str:
    require_online(d)
    conn = get_connection(d)
    if not _exists(conn, dn):
        raise ADError('OU 不存在')
    new_dn = dn
    if data.get('description') is not None:
        v = (data.get('description') or '').strip()
        ok = conn.modify(dn, {'description': [(MODIFY_REPLACE, [v] if v else [])]})
        _check(d, conn, ok)
    new_name = (data.get('name') or '').strip()
    if new_name:
        new_name = _escape_rdn_value(new_name)
        if dn.split(',', 1)[0][3:] != new_name:
            ok = conn.modify_dn(dn, f'OU={new_name}', delete_old_dn=True)
            _check(d, conn, ok)
            new_dn = f'OU={new_name},{dn.split(",", 1)[1]}'
            conn.modify(new_dn, {'ou': [(MODIFY_REPLACE, [new_name])]})
    return new_dn


def delete_ou(d: DomainCtx, dn: str, recursive: bool = False) -> int:
    """删除 OU。recursive=True 时先递归删除子对象（AD 默认不允许删非叶子节点）。"""
    require_online(d)
    conn = get_connection(d)
    if not _exists(conn, dn):
        raise ADError('OU 不存在')
    deleted = 0
    if recursive:
        entries = search(d, dn, '(objectClass=*)', ['distinguishedName'], size_limit=5000)
        children = [e.entry_dn for e in entries if e.entry_dn.lower() != dn.lower()]
        # 深的先删
        for cdn in sorted(children, key=lambda x: -x.count(',')):
            ok = conn.delete(cdn)
            if not ok:
                raise _translate_ldap_error(conn.result or {}, d)
            deleted += 1
    ok = conn.delete(dn)
    if not ok:
        err = _translate_ldap_error(conn.result or {}, d)
        if err.code == 'notAllowedOnNonLeaf':
            raise ADError('该 OU 下仍有子对象（用户/组/OU），请勾选"递归删除"或先迁移子对象')
        raise err
    return deleted + 1


# ================================================================ 组：写
def create_group(d: DomainCtx, data: dict) -> str:
    require_online(d)
    name = (data.get('name') or '').strip()
    if not name:
        raise ADError('组名必填')
    name_clean = _escape_rdn_value(name)
    sam = (data.get('sam_account_name') or name).strip()
    if len(sam) > 20:
        raise ADError('组登录名不能超过 20 个字符（AD 限制）')
    ou_dn = data.get('ou_dn') or f'CN=Users,{d.base_dn}'
    scope = data.get('scope') or 'Global'
    category = data.get('category') or 'Security'
    gt_map = {
        ('DomainLocal', 'Security'): -2147483644, ('Global', 'Security'): -2147483646,
        ('Universal', 'Security'): -2147483640, ('DomainLocal', 'Distribution'): 4,
        ('Global', 'Distribution'): 2, ('Universal', 'Distribution'): 8,
    }
    gt = gt_map.get((scope, category), -2147483646)
    dn = f'CN={name_clean},{ou_dn}'
    conn = get_connection(d)
    if _exists(conn, dn):
        raise ADError(f'该位置已存在同名对象：{name}')
    attrs = {
        'objectClass': ['top', 'group'],
        'cn': name_clean, 'sAMAccountName': sam, 'groupType': gt,
    }
    desc = (data.get('description') or '').strip()
    if desc:
        attrs['description'] = desc
    mail = (data.get('mail') or '').strip()
    if mail:
        attrs['mail'] = mail
    ok = conn.add(dn, attributes=attrs)
    _check(d, conn, ok)
    return dn


def update_group(d: DomainCtx, dn: str, data: dict) -> None:
    require_online(d)
    conn = get_connection(d)
    changes = {}
    for key, attr in (('description', 'description'), ('mail', 'mail')):
        if key in data:
            v = (data.get(key) or '').strip()
            changes[attr] = [(MODIFY_REPLACE, [v] if v else [])]
    if changes:
        ok = conn.modify(dn, changes)
        _check(d, conn, ok)


def delete_group(d: DomainCtx, dn: str) -> None:
    require_online(d)
    conn = get_connection(d)
    if not _exists(conn, dn):
        raise ADError('组不存在')
    ok = conn.delete(dn)
    _check(d, conn, ok)


# ================================================================ 计算机：写
def update_computer(d: DomainCtx, dn: str, data: dict) -> None:
    require_online(d)
    conn = get_connection(d)
    changes = {}
    if 'description' in data:
        v = (data.get('description') or '').strip()
        changes['description'] = [(MODIFY_REPLACE, [v] if v else [])]
    if 'dns_host_name' in data:
        v = (data.get('dns_host_name') or '').strip()
        if v:
            changes['dNSHostName'] = [(MODIFY_REPLACE, [v])]
    if not changes:
        return
    ok = conn.modify(dn, changes)
    _check(d, conn, ok)


def set_computer_enabled(d: DomainCtx, dn: str, enabled: bool) -> None:
    require_online(d)
    conn = get_connection(d)
    uac = _get_uac(conn, dn)
    if uac is None:
        raise ADError('计算机对象不存在')
    new_uac = (uac & ~UAC_ACCOUNTDISABLE) if enabled else (uac | UAC_ACCOUNTDISABLE)
    ok = conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
    _check(d, conn, ok)


def delete_computer(d: DomainCtx, dn: str) -> None:
    """删除计算机账户（高危，需二次确认）。"""
    require_online(d)
    conn = get_connection(d)
    if not _exists(conn, dn):
        raise ADError('计算机对象不存在或已被删除')
    ok = conn.delete(dn)
    _check(d, conn, ok)


# ================================================================ 认证自检
def self_check(d: DomainCtx) -> list:
    """域配置诊断：DNS/端口/LDAP 绑定/写权限/AD 模块，用于"测试连通性"。"""
    import socket
    results = []

    def add(name, ok, msg):
        results.append({'name': name, 'ok': ok, 'msg': msg})

    # 1. TCP 端口
    for port in (_effective_port(d),):
        s = socket.socket()
        s.settimeout(config.PRECHECK_TIMEOUT)
        try:
            s.connect((d.dc_host, port or 389))
            add(f'TCP {port}', True, f'{d.dc_host}:{port} 可连通')
        except Exception as e:
            add(f'TCP {port}', False, f'{d.dc_host}:{port} 不可达（{e}）')
        finally:
            s.close()
    # 2. LDAP 绑定
    try:
        ok, msg = test_connection(d)
        add('LDAP 绑定', ok, msg)
    except Exception as e:
        add('LDAP 绑定', False, str(e))
    # 3. 读权限 / 域信息
    if any(r['name'] == 'LDAP 绑定' and r['ok'] for r in results):
        base = d.base_dn
        try:
            meta = domain_meta(d)
            base = meta['base_dn'] or base
            add('域信息读取', True, f'域根 {meta["base_dn"]}，SID {meta["domain_sid"] or "未知"}，'
                                    f'功能级别 {meta["domain_mode"] or "未知"}')
            try:
                db.execute('UPDATE ad_domain_conf SET base_dn=?, forest_name=?, domain_sid=?, '
                           'domain_mode=?, netbios_name=COALESCE(NULLIF(netbios_name,\'\'),?) WHERE id=?',
                           (meta['base_dn'], meta['forest'], meta['domain_sid'], meta['domain_mode'],
                            meta['netbios'], d.id))
            except Exception:
                pass
        except ADError as e:
            add('域信息读取', False, e.message)
        # 4. 写权限（在域根创建后立即删除临时 OU，风险最小）
        try:
            conn = get_connection(d)
            tag = f'__adm_selftest_{int(time.time())}'
            tmp = f'OU={tag},{base}'
            if conn.add(tmp, ['top', 'organizationalUnit'], {'ou': tag}):
                conn.delete(tmp)
                add('写权限', True, '具备域内创建/删除对象权限')
            else:
                err = _translate_ldap_error(conn.result or {}, d)
                add('写权限', False, err.message)
        except Exception as e:
            add('写权限', False, str(e))
    return results

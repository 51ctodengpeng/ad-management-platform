# -*- coding: utf-8 -*-
"""许可授权：默认 30 天试用 + 导入许可文件永久激活。

加密方案（选型见 README 授权章节）：
- Ed25519 非对称签名：私钥由激活服务器离线保管，客户端只内嵌公钥，无法伪造许可。
- 许可文件 = JSON { payload: {...}, signature: base64(Ed25519(payload_canonical)) }。
- payload 为明文（可读、便于审计），签名保证不可篡改；如需保密可再叠加 AES-GCM 加密内容。

机器绑定：machine_fingerprint() 基于 Windows MachineGuid + MAC + 主机名，可选绑定许可到单机。
"""
import base64
import hashlib
import json
import os
import socket
import time
import uuid
from datetime import datetime, timedelta

from modules import db
from modules.applog import get_logger

log = get_logger('license')

TRIAL_DAYS = 30
TRIAL_SECONDS = TRIAL_DAYS * 86400
# 进程启动时的单调时钟（不受改系统时间影响），用于累计「真实流逝」的试用时长
_session_mono = time.monotonic()

# 内置公钥（Ed25519，base64，32 字节），与激活服务端 keys/private.key 配对。
# 私钥仅在激活服务端，客户端无法伪造许可。
BUILTIN_PUBLIC_KEY_B64 = 'X9VVIY9/ODrXg5H1KMJKeRlU0/7/4fi0KifoUTMmtBg='

# 许可原文落库加密密钥（Fernet 对称加密，base64）。内置在代码中，防止「不逆向、只看
# 数据库文件」就读取许可明文。注意：逆向 exe 仍可提取该密钥，属「提高门槛」而非绝对安全；
# 可用环境变量 ADM_LICENSE_SECRET 覆盖（部署换钥/多实例隔离）。
LICENSE_SECRET_B64 = 'qvoQUOVpwNOU43qOJKanWIN8NNT4ApFji3ypb1G48Gw='


def _fernet():
    from cryptography.fernet import Fernet
    key = os.environ.get('ADM_LICENSE_SECRET', '').strip() or LICENSE_SECRET_B64
    return Fernet(key.encode('utf-8'))


def _encrypt_raw(raw: str) -> str:
    return _fernet().encrypt(raw.encode('utf-8')).decode('ascii')


def _decrypt_raw(enc: str) -> str:
    try:
        return _fernet().decrypt(enc.encode('ascii')).decode('utf-8')
    except Exception:
        return ''


def get_public_key_b64() -> str:
    """验签公钥（Ed25519，base64）。

    方案：公钥内置在客户端（被授权校验方），私钥仅存于激活服务端。默认用内置公钥，
    部署时如需更换密钥对，可用环境变量 ADM_LICENSE_PUBKEY 覆盖（用于测试/换钥）。
    """
    key = os.environ.get('ADM_LICENSE_PUBKEY', '').strip()
    return key or BUILTIN_PUBLIC_KEY_B64


def canonical_bytes(payload: dict) -> bytes:
    """规范序列化：签名与验签两端必须用同一规则，否则验签失败。"""
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def machine_fingerprint() -> str:
    parts = []
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Cryptography')
        parts.append(str(winreg.QueryValueEx(k, 'MachineGuid')[0]))
        winreg.CloseKey(k)
    except Exception:
        pass
    parts.append(f'{uuid.getnode():012x}')
    parts.append(socket.gethostname())
    return hashlib.sha256('|'.join(parts).encode('utf-8')).hexdigest()[:32]


def ensure_trial() -> None:
    """首次运行：初始化 30 天试用期（时长基于单调时钟累计，不受改系统时间影响）。"""
    if db.query_one('SELECT 1 FROM license_state WHERE id=1'):
        return
    now = datetime.now()
    db.execute(
        "INSERT INTO license_state(id, status, first_run_at, trial_expires_at, "
        "trial_elapsed_seconds, last_seen_wall, machine_id) "
        "VALUES(1, 'trial', ?, ?, 0, ?, ?)",
        (now.strftime('%Y-%m-%d %H:%M:%S'),
         (now + timedelta(days=TRIAL_DAYS)).strftime('%Y-%m-%d %H:%M:%S'),
         now.strftime('%Y-%m-%d %H:%M:%S'),
         machine_fingerprint()))


def get_state() -> dict:
    """当前授权状态 + 试用剩余天数。

    试用期基于「单调时钟累计真实流逝时长」，改写系统时间无法延长/缩短试用期：
    - 往前调时间：monotonic 照常累加，试用照常到期，不延长。
    - 往后调时间：monotonic 不跳变，试用不因改时间而立即过期。
    """
    ensure_trial()
    row = db.query_one('SELECT * FROM license_state WHERE id=1')
    if not row:
        return {'status': 'trial', 'trial_remaining_days': TRIAL_DAYS, 'edition': ''}
    d = dict(row)
    d['machine_id'] = machine_fingerprint()

    # 累计真实流逝时长并写回（重启后不丢）
    elapsed = float(d.get('trial_elapsed_seconds') or 0) + (time.monotonic() - _session_mono)
    db.execute('UPDATE license_state SET trial_elapsed_seconds=? WHERE id=1', (elapsed,))

    # 时间回拨检测（记录日志；判断仍以 monotonic 为准）
    wall_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    last_wall = d.get('last_seen_wall') or ''
    if last_wall and wall_now < last_wall:
        log.warning('检测到系统时间回拨：%s -> %s（试用期按真实流逝时间计）', last_wall, wall_now)
    db.execute('UPDATE license_state SET last_seen_wall=? WHERE id=1', (wall_now,))

    if d['status'] == 'trial':
        d['trial_remaining_days'] = max(0, int((TRIAL_SECONDS - elapsed) / 86400))
        if elapsed >= TRIAL_SECONDS:
            d['status'] = 'expired'
            db.execute("UPDATE license_state SET status='expired' WHERE id=1")
    # 激活态：①重新验签原始许可（防本地篡改 status/raw）②校验机器绑定 ③有期限许可用单调时钟判到期
    if d['status'] == 'activated':
        payload = _reverify(_decrypt_raw(d.get('raw') or ''))
        bound = (payload.get('machine_id') or '').strip() if payload else ''
        if payload is None or (bound and bound != machine_fingerprint()):
            d['status'] = 'trial'
            d['trial_remaining_days'] = max(0, int((TRIAL_SECONDS - elapsed) / 86400))
            db.execute("UPDATE license_state SET status='trial', raw='', customer='', edition='', "
                       "license_id='', expires_at='', activated_elapsed=0, license_duration_seconds=0 WHERE id=1")
        elif float(d.get('license_duration_seconds') or 0) > 0:
            used = elapsed - float(d.get('activated_elapsed') or 0)
            d['license_remaining_days'] = max(0, int((float(d['license_duration_seconds']) - used) / 86400))
            if used >= float(d['license_duration_seconds']):
                d['status'] = 'expired'
                db.execute("UPDATE license_state SET status='expired' WHERE id=1")
    # 到期日期（年月日），供前端展示；永久许可为空
    d['expires_date'] = ''
    if d.get('expires_at') and d['expires_at'] not in ('permanent', '0'):
        d['expires_date'] = d['expires_at'][:10]
    return d


def is_activated() -> bool:
    return get_state().get('status') == 'activated'


# ---------------------------------------------------------------- 版本功能权限
# 版本梯度：域数量、单域用户上限为硬限制，高级功能为软开关。试用/未激活按 enterprise 全开。
EDITION_FEATURES = {
    'standard': {'max_domains': 1, 'max_users': 2000, 'recycle': False, 'alerts': False,
                 'offboard': False, 'trust': False, 'selective_export': False, 'health': False,
                 'security_center': False},
    'professional': {'max_domains': 3, 'max_users': 10000, 'recycle': True, 'alerts': True,
                     'offboard': True, 'trust': False, 'selective_export': True, 'health': False,
                     'security_center': False},
    'enterprise': {'max_domains': 20, 'max_users': 20000, 'recycle': True, 'alerts': True,
                   'offboard': True, 'trust': True, 'selective_export': True, 'health': True,
                   'security_center': True},
}


def features() -> dict:
    """当前授权版本的功能权限。试用/未激活 → enterprise 全开（让客户体验全部价值）。"""
    st = get_state()
    edition = (st.get('edition') or 'enterprise') if st.get('status') == 'activated' else 'enterprise'
    return EDITION_FEATURES.get(edition, EDITION_FEATURES['enterprise'])


def feature_allowed(name: str) -> bool:
    return bool(features().get(name, False))


# ---------------------------------------------------------------- 授权功能清单
# 授权页「许可功能」展示：顺序即展示顺序。
# 布尔型功能 → 打勾/置灰由版本矩阵开关决定；数值额度型 → 恒打勾，右侧显示额度。
FEATURE_CATALOG = [
    # (key, 名称, 是否数值额度型)
    ('recycle', '回收站（软删除）', False),
    ('alerts', '告警中心', False),
    ('offboard', '离职处理', False),
    ('trust', '林间信任', False),
    ('selective_export', '选择性导出（按条件）', False),
    ('health', 'AD 域控健康监控', False),
    ('security_center', '安全中心（安全体检/异常检测）', False),
    ('max_domains', '多域管理（域数量）', True),
    ('max_users', '单域用户上限', True),
]


def feature_list() -> list:
    """返回当前授权功能清单（供授权页展示），每项 {key,label,enabled,value}。

    - 布尔型：enabled 取版本矩阵开关；value 为空。
    - 数值额度型（域数量/单域用户上限）：enabled 恒为 True，value 为当前额度。
    """
    f = features()
    items = []
    for key, label, is_num in FEATURE_CATALOG:
        item = {'key': key, 'label': label, 'value': ''}
        if is_num:
            item['enabled'] = True
            item['value'] = f.get(key)
        else:
            item['enabled'] = bool(f.get(key, False))
        items.append(item)
    return items


def max_domains() -> int:
    return features().get('max_domains', 20)


def max_users() -> int:
    """当前授权版本的单域用户上限（标准 2000 / 专业 10000 / 企业 20000）。"""
    return features().get('max_users', 20000)


def _reverify(raw: str):
    """重新验签原始许可，验签通过返回 payload，否则返回 None。"""
    if not raw:
        return None
    try:
        data = json.loads(raw)
        payload = data.get('payload')
        sig_b64 = data.get('signature')
        if not isinstance(payload, dict) or not sig_b64:
            return None
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(get_public_key_b64()))
        pub.verify(base64.b64decode(sig_b64), canonical_bytes(payload))
        return payload
    except Exception:
        return None


def verify_and_activate(raw: str) -> dict:
    """校验许可文件并激活。返回 {ok, message, ...}。"""
    try:
        data = json.loads(raw)
    except Exception:
        return {'ok': False, 'message': '许可文件不是合法 JSON'}
    payload = data.get('payload')
    sig_b64 = data.get('signature')
    if not isinstance(payload, dict) or not sig_b64:
        return {'ok': False, 'message': '许可文件缺少 payload 或 signature'}

    if not get_public_key_b64():
        return {'ok': False, 'message': '尚未配置许可公钥，请先在授权页「配置公钥」粘贴供应商提供的公钥'}

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(get_public_key_b64()))
        pub.verify(base64.b64decode(sig_b64), canonical_bytes(payload))
    except InvalidSignature:
        return {'ok': False, 'message': '签名校验失败：许可被篡改或由非授权来源签发'}
    except Exception as e:
        return {'ok': False, 'message': f'签名校验异常：{e}'}

    bound = (payload.get('machine_id') or '').strip()
    if bound and bound != machine_fingerprint():
        return {'ok': False, 'message': '该许可绑定的机器与当前机器不匹配'}

    expires = payload.get('expires_at') or ''
    if expires and expires not in ('permanent', '0'):
        try:
            if datetime.fromisoformat(expires) < datetime.now():
                return {'ok': False, 'message': '许可已过期'}
        except Exception:
            return {'ok': False, 'message': '许可有效期字段格式错误'}

    # 有期限许可时长（秒），permanent=0；激活时刻的累计单调秒数（供到期判断，防改系统时间）
    duration = 0.0
    if expires and expires not in ('permanent', '0'):
        try:
            issued = datetime.fromisoformat(payload.get('issued_at') or '')
            exp = datetime.fromisoformat(expires)
            duration = max(0.0, (exp - issued).total_seconds())
        except Exception:
            duration = 0.0
    elapsed_now = float(db.scalar('SELECT trial_elapsed_seconds FROM license_state WHERE id=1', (), 0) or 0)
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    db.execute(
        "UPDATE license_state SET status='activated', activated_at=?, customer=?, edition=?, "
        "license_id=?, expires_at=?, raw=?, activated_elapsed=?, license_duration_seconds=? WHERE id=1",
        (now, payload.get('customer', ''), payload.get('edition', ''), payload.get('license_id', ''),
         expires if expires not in ('permanent', '0') else '', _encrypt_raw(raw), elapsed_now, duration))
    log.info('许可激活成功：customer=%s edition=%s', payload.get('customer', ''), payload.get('edition', ''))
    return {'ok': True, 'message': '激活成功', 'customer': payload.get('customer', ''),
            'edition': payload.get('edition', '')}

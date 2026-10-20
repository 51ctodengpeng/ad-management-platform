# -*- coding: utf-8 -*-
"""系统账号认证：PBKDF2 校验、角色、登录失败锁定。"""
import time
import uuid
from datetime import datetime

import config
from modules import db
from modules.security import hash_password, verify_password, password_strength_error
from modules.applog import get_logger

log = get_logger('auth')

ROLE_NAMES = {'super_admin': '超级管理员', 'operator': '普通运维'}
MAX_FAIL = 5              # 连续失败次数（默认，可由「登录安全」配置覆盖）
LOCK_SECONDS = 300        # 锁定时长（默认，可由「登录安全」配置覆盖）


def _fail_key(username: str) -> str:
    return f'auth_fail:{username.lower()}'


def _get_fail(username: str):
    raw = db.get_setting(_fail_key(username))
    if not raw:
        return 0, 0.0
    try:
        cnt, ts = raw.split('|')
        return int(cnt), float(ts)
    except Exception:
        return 0, 0.0


def locked_remaining(username: str) -> int:
    cnt, ts = _get_fail(username)
    if cnt >= login_max_fail():
        left = int(login_lock_seconds() - (time.time() - ts))
        return max(0, left)
    return 0


def authenticate(username: str, password: str):
    """返回 (user_row | None, 错误信息)。"""
    username = (username or '').strip()
    if not username or not password:
        return None, '请输入用户名和密码'
    left = locked_remaining(username)
    if left:
        if left >= 60:
            return None, f'该账号连续登录失败，已临时锁定，请 {left // 60} 分钟后重试'
        return None, f'该账号连续登录失败，已临时锁定，请 {left} 秒后重试'
    row = db.query_one('SELECT * FROM sys_user WHERE username=?', (username,))
    if not row or not verify_password(password, row['password_hash'], row['salt']):
        cnt, ts = _get_fail(username)
        if not row:
            # 防用户名探测：对不存在的账号也计数（按用户名维度）
            cnt += 1
        else:
            cnt = cnt + 1 if (time.time() - ts) < login_lock_seconds() else 1
        db.set_setting(_fail_key(username), f'{cnt}|{time.time()}')
        return None, '用户名或密码错误'
    if not row['status']:
        return None, '该账号已被禁用，请联系超级管理员'
    if row['account_expires'] and row['account_expires'] < datetime.now().strftime('%Y-%m-%d %H:%M:%S'):
        return None, '该账号已过期，请联系管理员'
    db.set_setting(_fail_key(username), '')
    return row, ''


def touch_login(user_id: int, ip: str) -> None:
    db.execute("UPDATE sys_user SET last_login_at=datetime('now','localtime'), last_login_ip=? WHERE id=?",
               (ip, user_id))


def create_user(username: str, password: str, display_name: str = '', role: str = 'operator') -> int:
    username = (username or '').strip()
    if not username or len(username) < 3:
        raise ValueError('用户名至少 3 个字符')
    err = password_strength_error(password)
    # 系统账号允许 8 位以上即可
    if err and '至少 7 位' in err:
        err = None if len(password or '') >= 8 else '密码长度至少 8 位'
    if err:
        raise ValueError(err)
    if role not in ROLE_NAMES:
        from modules import rbac
        if not rbac.get_role(role):
            raise ValueError('角色不合法')
    if db.query_one('SELECT 1 FROM sys_user WHERE username=?', (username,)):
        raise ValueError('用户名已存在')
    pwd_hash, salt = hash_password(password)
    return db.insert(
        'INSERT INTO sys_user(username, password_hash, salt, display_name, role, status) VALUES(?,?,?,?,?,1)',
        (username, pwd_hash, salt, display_name or username, role))


def change_password(user_id: int, old_pwd: str, new_pwd: str) -> None:
    row = db.query_one('SELECT * FROM sys_user WHERE id=?', (user_id,))
    if not row:
        raise ValueError('账号不存在')
    if not verify_password(old_pwd, row['password_hash'], row['salt']):
        raise ValueError('原密码错误')
    if len(new_pwd or '') < 8:
        raise ValueError('新密码长度至少 8 位')
    pwd_hash, salt = hash_password(new_pwd)
    db.execute("UPDATE sys_user SET password_hash=?, salt=?, updated_at=datetime('now','localtime') WHERE id=?",
               (pwd_hash, salt, user_id))


def reset_password(user_id: int, new_pwd: str) -> None:
    if len(new_pwd or '') < 8:
        raise ValueError('新密码长度至少 8 位')
    pwd_hash, salt = hash_password(new_pwd)
    db.execute("UPDATE sys_user SET password_hash=?, salt=?, updated_at=datetime('now','localtime') WHERE id=?",
               (pwd_hash, salt, user_id))
    # 重置密码即解除登录失败锁定，否则「被锁后重置密码」仍无法登录
    row = db.query_one('SELECT username FROM sys_user WHERE id=?', (user_id,))
    if row:
        db.set_setting(_fail_key(row['username']), '')


def update_user(user_id: int, display_name: str = None, role: str = None, account_expires: str = None) -> None:
    """更新运维账号：显示名 / 角色 / 有效期（account_expires 空串或 None = 永久）。"""
    row = db.query_one('SELECT * FROM sys_user WHERE id=?', (user_id,))
    if not row:
        raise ValueError('账号不存在')
    sets, params = [], []
    if display_name is not None:
        sets.append('display_name=?'); params.append(display_name or row['username'])
    if role is not None:
        if role not in ROLE_NAMES:
            from modules import rbac
            if not rbac.get_role(role):
                raise ValueError('角色不合法')
        sets.append('role=?'); params.append(role)
    if account_expires is not None:
        # '' 或 None = 永久
        sets.append('account_expires=?'); params.append(account_expires or None)
    if not sets:
        return
    sets.append("updated_at=datetime('now','localtime')")
    params.append(user_id)
    db.execute(f'UPDATE sys_user SET {", ".join(sets)} WHERE id=?', tuple(params))


def ensure_default_admin() -> None:
    """首启创建默认超级管理员（admin / powershell@2025），并提示立即修改。"""
    if db.scalar('SELECT COUNT(*) FROM sys_user', (), 0) == 0:
        create_user(config.DEFAULT_ADMIN_USER, config.DEFAULT_ADMIN_PASSWORD,
                    '超级管理员', 'super_admin')
        log.warning('已创建默认系统账号 %s，请登录后立即修改密码', config.DEFAULT_ADMIN_USER)


# ---------------------------------------------------------------- 会话安全配置
# 存 sys_setting 表（键值），对「所有许可证版本」生效，不受版本功能矩阵限制。
SESSION_TIMEOUT_CHOICES = [15, 30, 60, 120, 240]   # 常规时长（分钟）；0 = 永不超时


def session_timeout_minutes() -> int:
    """登录会话无操作超时（分钟）。返回 0 表示永不超时。"""
    raw = db.get_setting('session_timeout_minutes', '')
    try:
        v = int(raw)
    except (TypeError, ValueError):
        v = config.SESSION_TIMEOUT_MINUTES
    if v < 0:
        v = config.SESSION_TIMEOUT_MINUTES
    return v


def allow_concurrent_login() -> bool:
    """是否允许同一账号在多端同时登录（默认允许）。对所有许可证类型生效。"""
    return db.get_setting('allow_concurrent_login', '1') != '0'


def issue_login_token(user_id: int) -> str:
    """登录成功后签发会话令牌并覆盖记录到服务端（用于单会话互踢）。"""
    token = uuid.uuid4().hex
    db.set_setting(f'login_token:{user_id}', token)
    return token


def is_login_token_valid(user_id: int, token: str) -> bool:
    """校验会话令牌：允许并发时恒真；禁止并发时须与最新令牌一致（旧会话被挤下线）。"""
    if allow_concurrent_login():
        return True
    if not token:
        return False
    return db.get_setting(f'login_token:{user_id}', '') == token


def clear_login_token(user_id: int, token: str) -> None:
    """退出登录时，仅当本会话令牌仍是当前最新令牌时才清除（避免误伤其它并发会话）。"""
    if token and db.get_setting(f'login_token:{user_id}', '') == token:
        db.set_setting(f'login_token:{user_id}', '')


# ---------------------------------------------------------------- 登录安全配置
def login_max_fail() -> int:
    """连续失败锁定阈值（默认 5，可配 3~20）。"""
    raw = db.get_setting('login_max_fail', '')
    try:
        v = int(raw)
        if 3 <= v <= 20:
            return v
    except (TypeError, ValueError):
        pass
    return MAX_FAIL


def login_lock_seconds() -> int:
    """锁定时长（秒，默认 300，可配 60~3600）。"""
    raw = db.get_setting('login_lock_seconds', '')
    try:
        v = int(raw)
        if 60 <= v <= 3600:
            return v
    except (TypeError, ValueError):
        pass
    return LOCK_SECONDS


# ---------------------------------------------------------------- 密码恢复方式
def recovery_allow_license() -> bool:
    """是否允许「导入许可」重置密码（默认开启）。"""
    return db.get_setting('recovery_allow_license', '1') != '0'


def recovery_allow_questions() -> bool:
    """是否允许「密保问题」重置密码（默认开启）。"""
    return db.get_setting('recovery_allow_questions', '1') != '0'


def recovery_options() -> dict:
    """当前启用的密码恢复方式 + 已设密保问题（供登录页「忘记密码」展示）。"""
    return {
        'allow_license': recovery_allow_license(),
        'allow_questions': recovery_allow_questions(),
        'questions_set': has_security_questions(),
        'questions': get_security_questions(),
    }


# ---------------------------------------------------------------- 密保问题
SECURITY_QUESTION_SLOTS = 3
QUESTION_PRESETS = [
    '你的第一份工作的公司名称是什么？',
    '你母亲的姓名是什么？',
    '你的出生城市是哪里？',
    '你的第一辆车的品牌是什么？',
    '你最喜欢的一部电影是什么？',
    '你小学班主任的姓名是什么？',
]


def _q_key(i: int) -> str:
    return f'recovery_q{i}'


def _a_hash_key(i: int) -> str:
    return f'recovery_a{i}h'


def _a_salt_key(i: int) -> str:
    return f'recovery_a{i}s'


def get_security_questions() -> list:
    """返回已设置的密保问题（仅问题文本，不含答案），供设置页回显。"""
    out = []
    for i in range(1, SECURITY_QUESTION_SLOTS + 1):
        q = db.get_setting(_q_key(i), '') or ''
        has_a = bool(db.get_setting(_a_hash_key(i), ''))
        out.append({'slot': i, 'question': q, 'answered': has_a})
    return out


def has_security_questions() -> bool:
    return any(x['answered'] for x in get_security_questions())


def set_security_questions(questions: list) -> None:
    """保存密保问题。questions: [(question, answer), ...] 长度=3，空 answer 表示该槽位不设置。"""
    for i in range(1, SECURITY_QUESTION_SLOTS + 1):
        q, a = ('', '')
        if i - 1 < len(questions):
            q, a = questions[i - 1]
        q = (q or '').strip()
        a = (a or '').strip()
        db.set_setting(_q_key(i), q)
        if a:
            h, s = hash_password(a)
            db.set_setting(_a_hash_key(i), h)
            db.set_setting(_a_salt_key(i), s)
        else:
            db.set_setting(_a_hash_key(i), '')
            db.set_setting(_a_salt_key(i), '')


def verify_security_answers(answers: dict) -> bool:
    """校验密保答案。answers: {slot: answer}。所有已设置的问题必须全部答对。"""
    checked_any = False
    for i in range(1, SECURITY_QUESTION_SLOTS + 1):
        h = db.get_setting(_a_hash_key(i), '')
        s = db.get_setting(_a_salt_key(i), '')
        if not h or not s:
            continue
        checked_any = True
        ans = (answers.get(str(i)) or answers.get(i) or '').strip()
        if not verify_password(ans, h, s):
            return False
    return checked_any


def reset_admin_password(new_pwd: str) -> str:
    """重置第一个超级管理员的密码，返回其用户名。"""
    if len(new_pwd or '') < 8:
        raise ValueError('新密码长度至少 8 位')
    row = db.query_one("SELECT id, username FROM sys_user WHERE role='super_admin' ORDER BY id LIMIT 1")
    if not row:
        raise ValueError('不存在超级管理员账号')
    reset_password(row['id'], new_pwd)
    return row['username']


def login_cfg() -> dict:
    """登录安全 + 密码恢复配置汇总（供系统设置页）。"""
    return {
        'max_fail': login_max_fail(),
        'lock_seconds': login_lock_seconds(),
        'allow_license': recovery_allow_license(),
        'allow_questions': recovery_allow_questions(),
        'questions': get_security_questions(),
        'question_presets': QUESTION_PRESETS,
    }

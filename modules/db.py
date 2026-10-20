# -*- coding: utf-8 -*-
"""
SQLite 访问层
================================
设计要点：
1. 每个线程独立连接（sqlite3 连接非线程安全），threading.local 持有。
2. 连接建立即执行生产级 PRAGMA（WAL / synchronous=NORMAL / cache_size / busy_timeout），
   彻底规避 database is locked。
3. 提供事务上下文 tx()，支持批次提交（每 N 条 commit），避免大事务阻塞读。
4. 提供跨线程/跨进程租约锁 sync_lock()，防止"手动同步"和"定时同步"同时跑同一个域把数据写乱。
"""
import os
import sqlite3
import threading
import time
from contextlib import contextmanager

import config
from modules.security import decrypt_secret, encrypt_secret  # noqa: F401  (对外统一导出)

_local = threading.local()
_init_lock = threading.Lock()


# ---------------------------------------------------------------- 连接
def _apply_pragmas(conn: sqlite3.Connection) -> None:
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA cache_size=10000')
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA temp_store=MEMORY')
    conn.execute('PRAGMA busy_timeout=30000')


def get_conn() -> sqlite3.Connection:
    """获取当前线程连接。"""
    conn = getattr(_local, 'conn', None)
    if conn is None:
        conn = sqlite3.connect(
            config.DB_PATH,
            timeout=config.SQLITE_TIMEOUT,
            isolation_level=None,          # 手动控制事务，避免隐式 BEGIN 造成锁
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        _apply_pragmas(conn)
        _local.conn = conn
    return conn


def close_conn() -> None:
    conn = getattr(_local, 'conn', None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
        _local.conn = None


@contextmanager
def tx(immediate: bool = False):
    """
    事务上下文。immediate=True 时立即获取写锁，避免"读后升级写"导致的死锁/忙等。
    支持嵌套调用（内层不再 BEGIN）。
    """
    conn = get_conn()
    if getattr(_local, 'in_tx', False):
        yield conn
        return
    _local.in_tx = True
    try:
        conn.execute('BEGIN IMMEDIATE' if immediate else 'BEGIN')
        try:
            yield conn
            conn.execute('COMMIT')
        except Exception:
            try:
                conn.execute('ROLLBACK')
            except Exception:
                pass
            raise
    finally:
        _local.in_tx = False


# ---------------------------------------------------------------- 查询辅助
def query(sql: str, params=()) -> list:
    return get_conn().execute(sql, params).fetchall()


def query_one(sql: str, params=()):
    return get_conn().execute(sql, params).fetchone()


def scalar(sql: str, params=(), default=None):
    row = query_one(sql, params)
    if row is None:
        return default
    v = row[0]
    return default if v is None else v


def execute(sql: str, params=()) -> int:
    cur = get_conn().execute(sql, params)
    return cur.rowcount


def insert(sql: str, params=()) -> int:
    cur = get_conn().execute(sql, params)
    return cur.lastrowid


def like_escape(value: str) -> str:
    """转义 SQL LIKE 通配符（配合 `LIKE ? ESCAPE '\\'` 使用）。

    DN 里的 `_` 在 LIKE 中表示“任意单字符”，`%` 表示“任意串”。结构性判断
    （父 OU / 子树 / 级联改名）若直接拼接，`OU=IT_01` 会误命中 `OU=IT101`。
    """
    return (value or '').replace('\\', '\\\\').replace('_', '\\_').replace('%', '\\%')


def dn_like(dn: str) -> str:
    """DN 子树后缀匹配字面量：匹配 `<anything>,<dn>`。"""
    return '%,' + like_escape(dn)


def dn_like_child(dn: str) -> str:
    """DN 自身+子对象方向字面量：匹配 `<dn>,<anything>`。"""
    return like_escape(dn) + ',%'


# ---------------------------------------------------------------- 建表
SCHEMA = [
    # 1. 系统运维账号
    """
    CREATE TABLE IF NOT EXISTS sys_user (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        username        TEXT NOT NULL UNIQUE,
        password_hash   TEXT NOT NULL,
        salt            TEXT NOT NULL,
        display_name    TEXT,
        role            TEXT NOT NULL DEFAULT 'operator',   -- super_admin | operator | 自定义角色 key
        status          INTEGER NOT NULL DEFAULT 1,          -- 1 启用 0 禁用
        account_expires TEXT,                                -- 账号有效期（NULL=永久）
        last_login_at   TEXT,
        last_login_ip   TEXT,
        created_at      TEXT NOT NULL DEFAULT (datetime('now','localtime')),
        updated_at      TEXT
    )
    """,
    # 2. 多域配置表
    """
    CREATE TABLE IF NOT EXISTS ad_domain_conf (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        name            TEXT NOT NULL,
        domain_name     TEXT NOT NULL,              -- corp.example.com
        netbios_name    TEXT,
        dc_host         TEXT NOT NULL,              -- 域控 IP/主机名
        username        TEXT NOT NULL,
        password_enc    TEXT NOT NULL,              -- Fernet 加密
        ldap_port       INTEGER NOT NULL DEFAULT 389,
        use_ssl         INTEGER NOT NULL DEFAULT 0,
        base_dn         TEXT,                       -- 首次连接自动探测
        bind_dn         TEXT,                       -- 绑定账号 DN（自动探测）
        forest_name     TEXT,
        domain_sid      TEXT,
        domain_mode     TEXT,
        enabled         INTEGER NOT NULL DEFAULT 1,
        is_debug        INTEGER NOT NULL DEFAULT 0,
        remark          TEXT,
        status          TEXT NOT NULL DEFAULT 'unknown',   -- online | offline | unknown
        status_msg      TEXT,
        last_check_at   TEXT,
        last_sync_at    TEXT,
        last_sync_type  TEXT,                       -- full | incr
        last_sync_msg   TEXT,
        max_usn         INTEGER NOT NULL DEFAULT 0, -- 增量同步水位线
        dns_checked     INTEGER NOT NULL DEFAULT 0,
        created_at      TEXT NOT NULL DEFAULT (datetime('now','localtime')),
        updated_at      TEXT
    )
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS ux_domain_name ON ad_domain_conf(domain_name)
    """,
    # 3. AD 用户缓存
    """
    CREATE TABLE IF NOT EXISTS ad_user_cache (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id           INTEGER NOT NULL,
        dn                  TEXT NOT NULL,
        sam_account_name    TEXT,
        display_name        TEXT,
        cn                  TEXT,
        given_name          TEXT,
        sn                  TEXT,
        user_principal_name TEXT,
        mail                TEXT,
        telephone           TEXT,
        mobile              TEXT,
        title               TEXT,
        department          TEXT,
        company             TEXT,
        description         TEXT,
        ou_dn               TEXT,
        sam_account_type    TEXT,
        user_account_control INTEGER NOT NULL DEFAULT 512,
        enabled             INTEGER NOT NULL DEFAULT 1,
        locked              INTEGER NOT NULL DEFAULT 0,
        pwd_never_expires   INTEGER NOT NULL DEFAULT 0,
        pwd_last_set        TEXT,
        pwd_expires_at      TEXT,               -- 由 pwdLastSet + maxPwdAge 计算，供仪表盘统计
        last_logon          TEXT,
        usn                 INTEGER NOT NULL DEFAULT 0,
        when_created        TEXT,
        when_changed        TEXT,
        synced_at           TEXT,
        UNIQUE(domain_id, dn)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_user_domain ON ad_user_cache(domain_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_user_sam ON ad_user_cache(domain_id, sam_account_name)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_user_ou ON ad_user_cache(domain_id, ou_dn)
    """,
    # 4. 运维操作日志
    """
    CREATE TABLE IF NOT EXISTS ad_operation_log (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id       INTEGER,
        domain_name     TEXT,
        module          TEXT NOT NULL,          -- auth | domain | trust | user | ou | group | computer | sync
        action          TEXT NOT NULL,          -- create_user / reset_password ...
        target          TEXT,                   -- 操作对象 DN / 账号 / 域名
        detail          TEXT,
        result          TEXT NOT NULL DEFAULT 'success',  -- success | failed
        message         TEXT,
        operator        TEXT,
        ip              TEXT,
        client_type     TEXT,                -- 客户端类型（浏览器/脚本，解析 User-Agent）
        duration_ms     INTEGER,
        created_at      TEXT NOT NULL DEFAULT (datetime('now','localtime'))
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_log_time ON ad_operation_log(created_at)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_log_domain ON ad_operation_log(domain_id, created_at)
    """,
    # 5. OU 缓存
    """
    CREATE TABLE IF NOT EXISTS ad_ou_cache (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id   INTEGER NOT NULL,
        dn          TEXT NOT NULL,
        name        TEXT,
        parent_dn   TEXT,
        description TEXT,
        depth       INTEGER NOT NULL DEFAULT 0,
        user_count  INTEGER NOT NULL DEFAULT 0,
        usn         INTEGER NOT NULL DEFAULT 0,
        when_created TEXT,
        synced_at   TEXT,
        UNIQUE(domain_id, dn)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_ou_domain ON ad_ou_cache(domain_id)
    """,
    # 6. 组缓存
    """
    CREATE TABLE IF NOT EXISTS ad_group_cache (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id   INTEGER NOT NULL,
        dn          TEXT NOT NULL,
        name        TEXT,
        sam_account_name TEXT,
        scope       TEXT,                  -- DomainLocal | Global | Universal
        category    TEXT,                  -- Security | Distribution
        description TEXT,
        mail        TEXT,
        ou_dn       TEXT,
        member_count INTEGER NOT NULL DEFAULT 0,
        usn         INTEGER NOT NULL DEFAULT 0,
        synced_at   TEXT,
        UNIQUE(domain_id, dn)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_group_domain ON ad_group_cache(domain_id)
    """,
    # 7. 计算机缓存
    """
    CREATE TABLE IF NOT EXISTS ad_computer_cache (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id           INTEGER NOT NULL,
        dn                  TEXT NOT NULL,
        name                TEXT,
        dns_host_name       TEXT,
        operating_system    TEXT,
        os_version          TEXT,
        description         TEXT,
        ou_dn               TEXT,
        enabled             INTEGER NOT NULL DEFAULT 1,
        last_logon          TEXT,
        when_created        TEXT,
        usn                 INTEGER NOT NULL DEFAULT 0,
        remark              TEXT,              -- 本系统备注，不写回 AD
        remark_updated_by   TEXT,
        remark_updated_at   TEXT,
        synced_at           TEXT,
        UNIQUE(domain_id, dn)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_computer_domain ON ad_computer_cache(domain_id)
    """,
    # 8. 林信任关系缓存
    """
    CREATE TABLE IF NOT EXISTS ad_trust_cache (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id       INTEGER NOT NULL,
        trust_dn        TEXT NOT NULL,
        partner         TEXT,                -- 对方域/林 FQDN
        flat_name       TEXT,
        direction       TEXT,                -- inbound | outbound | bidirectional
        trust_type      TEXT,                -- external | forest | parent_child | shortcut | realm
        attributes      TEXT,
        status          TEXT NOT NULL DEFAULT 'active',   -- active | disabled | unknown
        verified        INTEGER NOT NULL DEFAULT 0,       -- 双向可验证（对方也信任回来）
        reverse_domain_id INTEGER,           -- 对方在本系统内的域 id（若已录入）
        last_verified_at TEXT,
        synced_at       TEXT,
        UNIQUE(domain_id, trust_dn)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_trust_domain ON ad_trust_cache(domain_id)
    """,
    # 9. 后台任务表（同步/批量任务队列，单并发执行保证不并发写 AD）
    """
    CREATE TABLE IF NOT EXISTS task_queue (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        task_type   TEXT NOT NULL,           -- sync_domain | sync_all | trust_create | trust_refresh | batch
        domain_id   INTEGER,
        payload     TEXT,
        status      TEXT NOT NULL DEFAULT 'pending',  -- pending | running | success | failed
        message     TEXT,
        operator    TEXT,
        created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
        started_at  TEXT,
        finished_at TEXT
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_task_status ON task_queue(status, created_at)
    """,
    # 10. 租约锁（跨进程互斥：同步、批量写 AD）
    """
    CREATE TABLE IF NOT EXISTS app_lock (
        name        TEXT PRIMARY KEY,
        owner       TEXT,
        acquired_at REAL,
        expires_at  REAL
    )
    """,
    # 11. 系统设置 KV
    """
    CREATE TABLE IF NOT EXISTS sys_setting (
        k   TEXT PRIMARY KEY,
        v   TEXT,
        updated_at TEXT
    )
    """,
    # 12. 回收站（软删除：删除前快照目录对象，30 天内可还原）
    """
    CREATE TABLE IF NOT EXISTS ad_recycle_bin (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id     INTEGER NOT NULL,
        entity_type   TEXT NOT NULL,          -- user / group / ou / computer
        name          TEXT NOT NULL,          -- 显示名或登录名
        dn            TEXT NOT NULL,          -- 原始 DN
        snapshot      TEXT NOT NULL,          -- JSON 快照（还原用）
        deleted_by    TEXT DEFAULT '',
        deleted_at    TEXT DEFAULT (datetime('now','localtime')),
        restored_at   TEXT DEFAULT ''
    )
    """,
    # 13. 许可授权状态（试用/激活持久化）
    """
    CREATE TABLE IF NOT EXISTS license_state (
        id                      INTEGER PRIMARY KEY CHECK (id=1),
        status                  TEXT NOT NULL DEFAULT 'trial',   -- trial / activated / expired / revoked
        first_run_at            TEXT,
        trial_expires_at        TEXT,
        trial_elapsed_seconds   REAL NOT NULL DEFAULT 0,        -- 累计已用试用秒数（monotonic，防改系统时间）
        last_seen_wall          TEXT DEFAULT '',                -- 最后看到的系统时间（回拨检测）
        activated_elapsed       REAL NOT NULL DEFAULT 0,        -- 激活时刻的累计单调秒数（有期限许可到期用）
        license_duration_seconds REAL NOT NULL DEFAULT 0,       -- 有期限许可时长（秒，permanent=0）
        activated_at            TEXT,
        customer                TEXT DEFAULT '',
        edition                 TEXT DEFAULT '',
        license_id              TEXT DEFAULT '',
        expires_at              TEXT DEFAULT '',
        machine_id              TEXT DEFAULT '',
        raw                     TEXT DEFAULT ''                 -- 许可文件原文（审计）
    )
    """,
    # 14. 角色（RBAC：模块×操作权限 + 数据范围）
    """
    CREATE TABLE IF NOT EXISTS sys_role (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        key             TEXT NOT NULL UNIQUE,           -- super_admin / operator / 自定义标识
        display_name    TEXT NOT NULL,
        description     TEXT,
        is_builtin      INTEGER NOT NULL DEFAULT 0,     -- 1=内置角色（不可删除/不可改权限）
        permissions     TEXT NOT NULL DEFAULT '{}',     -- JSON: {module: [actions]}
        scope_type      TEXT NOT NULL DEFAULT 'all',    -- all | custom
        scope_domains   TEXT NOT NULL DEFAULT '[]',     -- JSON: [domain_id]（scope_type=custom 时）
        created_at      TEXT NOT NULL DEFAULT (datetime('now','localtime')),
        updated_at      TEXT
    )
    """,
]


def init_db() -> None:
    """初始化数据库（幂等）。WAL 模式持久化在库文件里，一次设置长期生效。"""
    with _init_lock:
        conn = get_conn()
        # 强制落盘 WAL，确认生效
        mode = conn.execute('PRAGMA journal_mode=WAL').fetchone()[0]
        if str(mode).lower() != 'wal':
            raise RuntimeError(f'SQLite 未能开启 WAL 模式，当前为 {mode}；请检查数据目录写权限')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA cache_size=10000')
        conn.execute('PRAGMA busy_timeout=30000')
        for ddl in SCHEMA:
            conn.execute(ddl)
        _migrate(conn)
        # 每次启动清理过期租约
        conn.execute('DELETE FROM app_lock WHERE expires_at < ?', (time.time(),))


def _columns(conn, table) -> set:
    return {r[1] for r in conn.execute(f'PRAGMA table_info({table})').fetchall()}


def _migrate(conn) -> None:
    """轻量迁移：为老版本库补齐新增列，避免升级时手工改库。"""
    migrations = {
        'sys_user': [
            ('account_expires', 'TEXT'),
        ],
        'ad_domain_conf': [
            ('dns_checked', 'INTEGER NOT NULL DEFAULT 0'),
            ('domain_sid', 'TEXT'),
            ('domain_mode', 'TEXT'),
            ('max_usn', 'INTEGER NOT NULL DEFAULT 0'),
        ],
        'ad_user_cache': [
            ('pwd_expires_at', 'TEXT'),
            ('sam_account_type', 'TEXT'),
        ],
        'ad_computer_cache': [
            ('remark', 'TEXT'),
            ('remark_updated_by', 'TEXT'),
            ('remark_updated_at', 'TEXT'),
        ],
        'ad_trust_cache': [
            ('verified', 'INTEGER NOT NULL DEFAULT 0'),
            ('reverse_domain_id', 'INTEGER'),
        ],
        'ad_operation_log': [
            ('client_type', 'TEXT'),
        ],
        'license_state': [
            ('trial_elapsed_seconds', 'REAL NOT NULL DEFAULT 0'),
            ('last_seen_wall', "TEXT DEFAULT ''"),
            ('activated_elapsed', 'REAL NOT NULL DEFAULT 0'),
            ('license_duration_seconds', 'REAL NOT NULL DEFAULT 0'),
        ],
    }
    for table, cols in migrations.items():
        existing = _columns(conn, table)
        for name, ddl in cols:
            if name not in existing:
                conn.execute(f'ALTER TABLE {table} ADD COLUMN {name} {ddl}')


# ---------------------------------------------------------------- 租约锁
class LockBusy(Exception):
    """锁被占用，说明同一资源已有任务在跑。"""


class _Lease:
    def __init__(self, name: str, owner: str, ttl: float):
        self.name, self.owner, self.ttl = name, owner, ttl

    def heartbeat(self, extra_ttl: float = None) -> None:
        """长任务续约，避免 TTL 到期被别人抢走。"""
        ttl = extra_ttl or self.ttl
        execute('UPDATE app_lock SET expires_at=? WHERE name=? AND owner=?',
                (time.time() + ttl, self.name, self.owner))

    def release(self) -> None:
        try:
            execute('DELETE FROM app_lock WHERE name=? AND owner=?', (self.name, self.owner))
        except Exception:
            pass


@contextmanager
def sync_lock(name: str, ttl: float = 1800, owner: str = None, wait: float = 0):
    """跨线程/跨进程租约锁。wait>0 时短暂等待，否则立即抛 LockBusy。"""
    import uuid
    owner = owner or f'{os.getpid()}:{threading.get_ident()}:{uuid.uuid4().hex[:8]}'
    deadline = time.time() + max(wait, 0)
    while True:
        now = time.time()
        with tx(immediate=True) as conn:
            conn.execute('DELETE FROM app_lock WHERE expires_at < ?', (now,))
            row = conn.execute('SELECT owner, expires_at FROM app_lock WHERE name=?', (name,)).fetchone()
            if row is None or row['owner'] == owner:
                conn.execute(
                    'INSERT INTO app_lock(name, owner, acquired_at, expires_at) VALUES(?,?,?,?) '
                    'ON CONFLICT(name) DO UPDATE SET owner=excluded.owner, '
                    'acquired_at=excluded.acquired_at, expires_at=excluded.expires_at',
                    (name, owner, now, now + ttl),
                )
                break
        if time.time() >= deadline:
            raise LockBusy(f'资源锁 {name} 被占用（已有任务在执行）')
        time.sleep(0.5)
    lease = _Lease(name, owner, ttl)
    try:
        yield lease
    finally:
        lease.release()


def pending_task_ids(limit: int = 20) -> list:
    """内存队列丢任务时的兜底恢复：取库中仍为 pending 的任务 id。"""
    try:
        return [r['id'] for r in query("SELECT id FROM task_queue WHERE status='pending' ORDER BY id LIMIT ?",
                                       (limit,))]
    except Exception:
        return []


# ---------------------------------------------------------------- 设置项
def get_setting(key: str, default=None):
    row = query_one('SELECT v FROM sys_setting WHERE k=?', (key,))
    return row['v'] if row else default


def set_setting(key: str, value) -> None:
    execute(
        'INSERT INTO sys_setting(k, v, updated_at) VALUES(?,?,datetime(\'now\',\'localtime\')) '
        'ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at',
        (key, '' if value is None else str(value)),
    )

# -*- coding: utf-8 -*-
"""
AD域Web管理系统 - 全局配置
================================
所有可调参数集中在此：路径、SQLite 生产参数、定时任务、AD 连接、安全策略。
支持通过环境变量覆盖（生产部署推荐用环境变量注入密码与密钥）。
"""
import os
import sys

# ---------------------------------------------------------------- 基础路径
# PyInstaller 打包后 sys._MEIPASS 为临时解包目录（只读），数据必须落到 exe 同级目录
def _app_root() -> str:
    if getattr(sys, 'frozen', False):
        # 便携版：exe 所在目录；数据目录优先使用同目录（可被 --workdir 覆盖）
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


BASE_DIR = _app_root()
# 允许安装包把工作目录指定到 ProgramData（可写、非管理员也能改配置）
WORK_DIR = os.environ.get('ADM_WORK_DIR') or BASE_DIR

if getattr(sys, 'frozen', False):
    RESOURCE_DIR = getattr(sys, '_MEIPASS', BASE_DIR)
else:
    RESOURCE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_DIR = os.path.join(WORK_DIR, 'database')
LOG_DIR = os.path.join(WORK_DIR, 'logs')
DB_PATH = os.environ.get('ADM_DB_PATH') or os.path.join(DATA_DIR, 'ad_cache.db')

for _d in (DATA_DIR, LOG_DIR):
    os.makedirs(_d, exist_ok=True)

# ---------------------------------------------------------------- Web 服务
APP_NAME = 'AD域控管理系统'
# 版本号：每次发布 +1（单一来源，app.py / modules/backup.py 引用此值）
APP_VERSION = '1.0.3'
# 默认仅监听本机，避免把域管理员后台直接暴露到网络；部署到内网服务器时改为 0.0.0.0
SERVER_HOST = os.environ.get('ADM_HOST', '0.0.0.0')
SERVER_PORT = int(os.environ.get('ADM_PORT', '8080'))
SECRET_KEY = os.environ.get('ADM_SECRET_KEY', '')
SESSION_TIMEOUT_MINUTES = 30      # 登录会话默认无操作超时（分钟，兜底值；实际以「系统设置」为准，0=永不超时）
SESSION_COOKIE_SECURE = False          # 纯内网 HTTP 部署；若上 HTTPS 改为 True

# ---------------------------------------------------------------- 加密
# 域账号密码、系统账号密码加密存储（Fernet）。首次启动自动生成 .secret.key
KEY_FILE = os.path.join(DATA_DIR, '.secret.key')

# ---------------------------------------------------------------- SQLite 生产参数
# WAL + NORMAL：读写并发不锁库；busy_timeout 让写等待而非直接报错
SQLITE_TIMEOUT = 30.0                  # 连接等待秒数
SQLITE_PRAGMAS = [
    'PRAGMA journal_mode=WAL',
    'PRAGMA synchronous=NORMAL',
    'PRAGMA cache_size=10000',
    'PRAGMA foreign_keys=ON',
    'PRAGMA temp_store=MEMORY',
    'PRAGMA busy_timeout=30000',
]
SYNC_BATCH_SIZE = 200                  # 分批事务大小（每 200 条 commit）
MAX_DOMAINS = int(os.environ.get('ADM_MAX_DOMAINS', '20'))
MAX_USERS_PER_DOMAIN = int(os.environ.get('ADM_MAX_USERS_PER_DOMAIN', '20000'))

# ---------------------------------------------------------------- AD 连接
AD_CONNECT_TIMEOUT = 5                 # 秒，建连超时
AD_RECEIVE_TIMEOUT = 20                # 秒，读超时
AD_PAGE_SIZE = 1000                    # 分页搜索每页条数
AD_HEALTH_TTL = 20                     # 域健康状态缓存秒数，避免每次请求都探测域控
AD_WRITE_HEALTH_TTL = 60               # 写操作前健康检查结果缓存秒数
AD_AUTH_MODE = os.environ.get('ADM_AUTH_MODE', 'auto')   # auto | simple | ntlm

# ---------------------------------------------------------------- 定时任务
SYNC_INCREMENT_INTERVAL_MIN = 15       # 增量同步间隔（每域独立任务）
SYNC_FULL_HOUR = 2                     # 每日全量同步时间
SYNC_FULL_MINUTE = 0
TRUST_REFRESH_INTERVAL_MIN = 30        # 信任关系状态刷新间隔
LOG_RETENTION_DAYS = 90                # 操作日志保留 3 个月
LOG_ARCHIVE_ENABLED = True
SCHEDULER_TIMEZONE = os.environ.get('ADM_TZ', 'Asia/Shanghai')
# 增量同步抖动，避免 10 个域同一秒并发拉取
SYNC_JITTER_SECONDS = 45
ENABLE_SCHEDULER = os.environ.get('ADM_ENABLE_SCHEDULER', '1') != '0'

# ---------------------------------------------------------------- 操作限制
BATCH_LIMIT = 500                      # 单次批量操作对象上限，超过则拒绝
EXPORT_ROW_LIMIT = 100000              # 导出上限
DELETE_ACCOUNT_HARD_DELETE = False     # 删除用户默认走"删除"（AD delete），不做软删除
PROTECTED_GROUPS = {
    'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
    'Domain Controllers', 'Account Operators', 'Backup Operators',
    'Server Operators', 'Print Operators', 'Group Policy Creator Owners',
    'Read-only Domain Controllers', 'Cert Publishers', 'DnsAdmins',
}

# ---------------------------------------------------------------- WinRM / 林信任
WINRM_OP_TIMEOUT = 60                  # 单条命令操作超时
WINRM_READ_TIMEOUT = 300               # netdom 可能较久
TRUST_CREATE_TIMEOUT = 420
# 创建信任的预检端口：LDAP 389/636 + WinRM 5985/5986 + DNS 53
PRECHECK_TCP_PORTS = (389, 636, 5985, 5986, 53)
PRECHECK_TIMEOUT = 3

# ---------------------------------------------------------------- 固定调试环境
# 仅开发联调使用：默认关闭，客户交付版不会自动录入、也不展示任何调试域信息。
# 需联调时通过环境变量 ADM_ENABLE_DEBUG_DOMAIN=1 开启（示例值请按实际环境修改）。
ENABLE_DEBUG_DOMAIN = os.environ.get('ADM_ENABLE_DEBUG_DOMAIN', '0') != '0'
DEBUG_DOMAIN = {
    'name': '开发调试域',
    'domain_name': 'corp.example.com',
    'netbios_name': 'CORP',
    'dc_host': '192.168.1.10',
    'username': 'administrator',
    'password': 'ChangeMe@2025',
    'ldap_port': 389,
    'use_ssl': 0,
    'is_debug': 1,
    'remark': '固定调试域（开发联调环境）',
}

# ---------------------------------------------------------------- 默认系统账号
DEFAULT_ADMIN_USER = os.environ.get('ADM_ADMIN_USER', 'admin')
DEFAULT_ADMIN_PASSWORD = os.environ.get('ADM_ADMIN_PASSWORD', 'powershell@2025')

# ---------------------------------------------------------------- 日志文件
APP_LOG_FILE = os.path.join(LOG_DIR, 'app.log')

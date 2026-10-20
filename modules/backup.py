# -*- coding: utf-8 -*-
"""
备份与还原
================================
1. 备份：用 SQLite 在线 backup API 生成一致快照（WAL 模式下直接复制 db 文件会丢未 checkpoint 数据），
   连同 Fernet 密钥 .secret.key 与元数据 manifest.json 打包成 zip。
2. 还原：校验（manifest 版本 / SQLite integrity / 密钥格式）→ 自动做"还原前快照"→
   在线覆盖当前库 + 替换密钥 → 重载密钥缓存 → 迁移补齐 schema（版本兼容）→ 审计日志。
3. 语义：还原为「整体覆盖」当前数据（含账号/角色/许可/域配置/缓存/审计日志），非表级合并。
"""
import base64
import hashlib
import io
import json
import os
import shutil
import sqlite3
import tempfile
import zipfile
from datetime import datetime

import config
from modules import db
from modules.applog import get_logger

log = get_logger('backup')

BACKUP_FORMAT_VERSION = 1          # 备份包格式版本（向前兼容：更高版本拒绝还原）
APP_VERSION = config.APP_VERSION    # 与 app.py 注入的 version 保持一致（单一来源 config.APP_VERSION）
MANIFEST_NAME = 'manifest.json'
DB_ENTRY = 'ad_cache.db'
KEY_ENTRY = '.secret.key'
BACKUP_DIR_NAME = 'backups'        # 还原前自动快照的存放子目录


def _backup_dir() -> str:
    d = os.path.join(config.DATA_DIR, BACKUP_DIR_NAME)
    os.makedirs(d, exist_ok=True)
    return d


# ---------------------------------------------------------------- 备份
def create_backup() -> tuple:
    """生成备份 zip。返回 (zip_bytes, manifest)。"""
    tmpdir = tempfile.mkdtemp(prefix='adm_bak_')
    try:
        db_snap = os.path.join(tmpdir, DB_ENTRY)
        _snapshot_db(db_snap)

        sha = hashlib.sha256(open(db_snap, 'rb').read()).hexdigest()
        key_present = os.path.exists(config.KEY_FILE)
        manifest = {
            'format_version': BACKUP_FORMAT_VERSION,
            'app_version': APP_VERSION,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'db_sha256': sha,
            'key_present': key_present,
            'stats': _snapshot_stats(),
        }

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(MANIFEST_NAME, json.dumps(manifest, ensure_ascii=False, indent=2))
            zf.write(db_snap, DB_ENTRY)
            if key_present:
                zf.write(config.KEY_FILE, KEY_ENTRY)
        return buf.getvalue(), manifest
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _snapshot_db(path: str) -> None:
    """在线备份当前库到 path（一致快照）。"""
    src = db.get_conn()
    dst = sqlite3.connect(path)
    try:
        src.backup(dst)
    finally:
        dst.close()


def _snapshot_stats() -> dict:
    try:
        return {
            'domains': db.scalar('SELECT COUNT(*) FROM ad_domain_conf', (), 0),
            'users': db.scalar('SELECT COUNT(*) FROM ad_user_cache', (), 0),
            'logs': db.scalar('SELECT COUNT(*) FROM ad_operation_log', (), 0),
        }
    except Exception:
        return {}


# ---------------------------------------------------------------- 还原
def restore_backup(zip_bytes: bytes, operator: str = '') -> dict:
    """校验并还原备份包。返回 {ok, message, pre_backup, key_matched, ...}。"""
    tmpdir = tempfile.mkdtemp(prefix='adm_res_')
    try:
        manifest, db_file, key_file, key_present = _extract_and_verify(zip_bytes, tmpdir)

        # 还原前自动做一次快照，供后悔回滚
        pre_backup = _make_pre_restore_snapshot()

        # 在线覆盖当前数据库
        _overwrite_db(db_file)

        # 替换密钥（备份不含密钥时保留当前密钥，避免域凭据无法解密）
        if key_present:
            _write_key(open(key_file, 'rb').read())

        # 重载密钥缓存 + 迁移补齐 schema（版本兼容：旧备份缺列自动补）
        _reload_crypto_key()
        db.init_db()

        key_matched = _check_key_match()

        return {
            'ok': True,
            'message': '备份已还原，数据已整体覆盖',
            'pre_backup': os.path.basename(pre_backup),
            'key_matched': key_matched,
            'stats': manifest.get('stats', {}),
            'backup_created_at': manifest.get('created_at', ''),
            'backup_app_version': manifest.get('app_version', ''),
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _extract_and_verify(zip_bytes: bytes, tmpdir: str):
    """解压并校验备份包，返回 (manifest, db_file, key_file, key_present)。"""
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except Exception:
        raise ValueError('不是有效的 ZIP 压缩包')

    with zf:
        names = zf.namelist()
        if MANIFEST_NAME not in names:
            raise ValueError('无效的备份包：缺少 manifest.json')
        try:
            manifest = json.loads(zf.read(MANIFEST_NAME).decode('utf-8'))
        except Exception:
            raise ValueError('无效的备份包：manifest.json 无法解析')

        fmt = manifest.get('format_version')
        if not isinstance(fmt, int) or fmt < 1 or fmt > BACKUP_FORMAT_VERSION:
            raise ValueError(f'备份格式版本不受支持（{fmt}），当前程序支持 ≤ {BACKUP_FORMAT_VERSION}')

        if DB_ENTRY not in names:
            raise ValueError('无效的备份包：缺少数据库文件')

        db_file = os.path.join(tmpdir, DB_ENTRY)
        with open(db_file, 'wb') as f:
            f.write(zf.read(DB_ENTRY))

        key_present = KEY_ENTRY in names
        key_file = None
        if key_present:
            key_file = os.path.join(tmpdir, KEY_ENTRY)
            with open(key_file, 'wb') as f:
                f.write(zf.read(KEY_ENTRY))
            _verify_key_file(key_file)

    _verify_sqlite(db_file)
    return manifest, db_file, key_file, key_present


def _verify_sqlite(path: str) -> None:
    try:
        conn = sqlite3.connect(path)
        try:
            row = conn.execute('PRAGMA integrity_check').fetchone()
            if not row or row[0] != 'ok':
                raise ValueError('备份数据库完整性校验失败：' + str(row[0] if row else '无法读取'))
        finally:
            conn.close()
    except sqlite3.DatabaseError as e:
        raise ValueError('备份文件不是合法的 SQLite 数据库：' + str(e))


def _verify_key_file(path: str) -> None:
    data = open(path, 'rb').read().strip()
    if not data:
        raise ValueError('密钥文件为空')
    try:
        raw = base64.urlsafe_b64decode(data + b'=' * (-len(data) % 4))
    except Exception:
        raise ValueError('密钥文件不是合法的 Fernet 密钥')
    if len(raw) != 32:
        raise ValueError('密钥文件长度不合法（应为 32 字节）')


def _make_pre_restore_snapshot() -> str:
    """还原前自动快照，返回文件绝对路径。"""
    data, _ = create_backup()
    fn = 'pre_restore_%s.zip' % datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(_backup_dir(), fn)
    with open(path, 'wb') as f:
        f.write(data)
    return path


def _overwrite_db(src_path: str) -> None:
    """把备份库内容在线覆盖到当前打开的库（backup API，无需关连接/重启）。"""
    src = sqlite3.connect(src_path)
    dst = db.get_conn()
    try:
        src.backup(dst)
    finally:
        src.close()
    # 重建当前线程连接，避免旧 schema 缓存
    db.close_conn()


def _write_key(key_data: bytes) -> None:
    if os.path.exists(config.KEY_FILE):
        try:
            shutil.copyfile(config.KEY_FILE, config.KEY_FILE + '.bak')
        except Exception:
            pass
    os.makedirs(os.path.dirname(config.KEY_FILE), exist_ok=True)
    with open(config.KEY_FILE, 'wb') as f:
        f.write(key_data)
    try:
        os.chmod(config.KEY_FILE, 0o600)
    except Exception:
        pass


def _reload_crypto_key() -> None:
    import modules.security as sec
    sec._fernet = None


def _check_key_match() -> bool:
    """抽样验证当前密钥能解密库内域凭据（判断 key 与 db 是否配对）。"""
    try:
        from modules.security import decrypt_secret
        row = db.query_one("SELECT password_enc FROM ad_domain_conf WHERE password_enc LIKE 'enc:%' LIMIT 1")
        if not row:
            return True          # 无加密凭据，无所谓是否匹配
        decrypt_secret(row['password_enc'])
        return True
    except Exception:
        return False

# -*- coding: utf-8 -*-
"""文件日志：滚动写入 logs/app.log，供排错与现场取证。"""
import logging
import logging.handlers
import os

import config

_configured = False


def setup_logging(level=logging.INFO) -> None:
    global _configured
    if _configured:
        return
    os.makedirs(config.LOG_DIR, exist_ok=True)
    root = logging.getLogger('adm')
    root.setLevel(level)
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s %(threadName)s: %(message)s')

    fh = logging.handlers.RotatingFileHandler(
        config.APP_LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding='utf-8')
    fh.setFormatter(fmt)
    root.addHandler(fh)

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)

    # 第三方库降噪
    logging.getLogger('apscheduler.executors.default').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    setup_logging()
    return logging.getLogger('adm.' + name)

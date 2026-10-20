# -*- coding: utf-8 -*-
"""告警中心：集中展示锁定账号、密码到期、离线域、长期离线设备等异常（全部读缓存，不实时查 AD）。"""
from datetime import datetime, timedelta

from flask import Blueprint, render_template

from modules import db
from modules import ad_ldap as L
from routes.common import login_required, feature_guard

bp = Blueprint('alerts', __name__, url_prefix='/alerts')
bp.before_request(feature_guard('alerts'))


@bp.route('/')
@login_required
def index():
    now = datetime.now()
    soon = (now + timedelta(days=14)).strftime('%Y-%m-%d %H:%M:%S')
    now_str = now.strftime('%Y-%m-%d %H:%M:%S')
    idle_line = (now - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

    locked = db.query(
        'SELECT id, domain_id, sam_account_name, display_name, dn FROM ad_user_cache '
        'WHERE locked=1 ORDER BY domain_id, sam_account_name LIMIT 200')
    pwd_soon = db.query(
        'SELECT id, domain_id, sam_account_name, display_name, pwd_expires_at FROM ad_user_cache '
        "WHERE pwd_expires_at<>'' AND pwd_expires_at>? AND pwd_expires_at<=? "
        'ORDER BY pwd_expires_at LIMIT 200', (now_str, soon))
    pwd_expired = db.query(
        'SELECT id, domain_id, sam_account_name, display_name, pwd_expires_at FROM ad_user_cache '
        "WHERE pwd_expires_at<>'' AND pwd_expires_at<=? ORDER BY pwd_expires_at LIMIT 200", (now_str,))
    offline_domains = [d for d in L.load_domains() if not d.enabled or d.status == 'offline']
    idle_computers = db.query(
        'SELECT id, domain_id, name, last_logon FROM ad_computer_cache '
        "WHERE last_logon='' OR last_logon IS NULL OR last_logon<? ORDER BY last_logon LIMIT 200", (idle_line,))
    dm = L.domain_map()

    return render_template('alerts.html', locked=locked, pwd_soon=pwd_soon, pwd_expired=pwd_expired,
                           offline_domains=offline_domains, idle_computers=idle_computers, dm=dm,
                           now_str=now_str)

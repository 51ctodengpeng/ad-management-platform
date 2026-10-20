# -*- coding: utf-8 -*-
"""
Excel 导入导出服务
================================
- 导出：用户台账（可单选/全选域）、操作日志、计算机清单。表头中文，冻结首行，自动列宽。
- 导入：先全量校验（必填、登录名格式/重复、OU 是否存在、密码复杂度），
  全部合法才执行；执行时逐条直连 AD，失败逐条记录，最后给出成功/失败明细。
"""
import io
import re
from datetime import datetime

import config
from modules import db
from modules import ad_ldap as L
from modules.applog import get_logger
from modules.security import password_strength_error

log = get_logger('excel')

try:
    from openpyxl import Workbook, load_workbook
    from openpyxl.styles import Alignment, Font, PatternFill, Border, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
    _HAS_OPENPYXL = True
except Exception:                                                  # pragma: no cover
    _HAS_OPENPYXL = False
    ILLEGAL_CHARACTERS_RE = None


def _clean_cell(v):
    """清洗 Excel 单元格非法控制字符（如 AD 错误消息里混入的 \\x00 等）。"""
    if isinstance(v, str):
        if ILLEGAL_CHARACTERS_RE is not None:
            v = ILLEGAL_CHARACTERS_RE.sub('', v)
    return v

USER_HEADERS = [
    ('domain', '所属域'), ('sam_account_name', '登录名'), ('display_name', '显示名称'),
    ('cn', 'CN'), ('user_principal_name', 'UPN'), ('mail', '邮箱'), ('telephone', '电话'),
    ('mobile', '手机'), ('title', '职位'), ('department', '部门'), ('company', '公司'),
    ('ou_dn', '所属OU'), ('status', '账号状态'), ('locked', '锁定状态'),
    ('pwd_expires_at', '密码过期时间'), ('last_logon', '最后登录时间'),
    ('when_created', '创建时间'), ('description', '备注'), ('dn', 'DN'),
]


def _style_header(ws, headers: list, widths: list = None):
    fill = PatternFill('solid', fgColor='1F4E79')
    font = Font(color='FFFFFF', bold=True, size=10)
    thin = Side(style='thin', color='D9D9D9')
    for i, h in enumerate(headers, 1):
        c = ws.cell(row=1, column=i, value=h)
        c.fill = fill
        c.font = font
        c.alignment = Alignment(horizontal='center', vertical='center')
        c.border = Border(bottom=thin)
        if widths:
            ws.column_dimensions[get_column_letter(i)].width = widths[i - 1]
    ws.freeze_panes = 'A2'
    ws.row_dimensions[1].height = 22


def _autosize(ws, headers, rows, min_w=10, max_w=48):
    for idx, h in enumerate(headers, 1):
        longest = len(str(h)) * 2
        for r in rows[:300]:
            v = r[idx - 1] if idx - 1 < len(r) else ''
            length = sum(2 if ord(ch) > 127 else 1 for ch in str(v or ''))
            longest = max(longest, length)
        ws.column_dimensions[get_column_letter(idx)].width = max(min_w, min(max_w, longest + 2))


def _describe_filters(filters: dict) -> str:
    parts = []
    if filters.get('keyword'):
        parts.append(f"关键词={filters['keyword']}")
    if filters.get('enabled') not in (None, '', 'all'):
        parts.append('状态=' + ('启用' if str(filters['enabled']) == '1' else '禁用'))
    if filters.get('locked') not in (None, '', 'all'):
        parts.append('锁定=' + ('是' if str(filters['locked']) == '1' else '否'))
    if filters.get('ou_dn'):
        parts.append(f"OU={filters['ou_dn']}")
    if filters.get('department'):
        parts.append(f"部门={filters['department']}")
    if filters.get('title'):
        parts.append(f"职位={filters['title']}")
    if filters.get('created_from') or filters.get('created_to'):
        parts.append(f"注册时间={filters.get('created_from') or '起始'}~{filters.get('created_to') or '至今'}")
    if filters.get('tag'):
        parts.append(f"标签={filters['tag']}")
    return '；'.join(parts) or '无（全部）'


def export_users(domain_ids: list, filters: dict = None) -> bytes:
    """导出用户台账（读缓存）。支持按筛选条件选择性导出，分批查询避免大数据量内存峰值。"""
    if not _HAS_OPENPYXL:
        raise RuntimeError('缺少 openpyxl 依赖')
    from modules import query_service as Q
    filters = filters or {}
    where, params = [], []
    if domain_ids:
        where.append('domain_id IN (%s)' % ','.join('?' * len(domain_ids)))
        params += list(domain_ids)
    kw = (filters.get('keyword') or '').strip()
    if kw:
        like = f'%{kw}%'
        where.append('(sam_account_name LIKE ? OR display_name LIKE ? OR mail LIKE ? '
                     'OR user_principal_name LIKE ?)')
        params += [like, like, like, like]
    if filters.get('enabled') not in (None, '', 'all'):
        where.append('enabled = ?')
        params.append(int(filters['enabled']))
    if filters.get('locked') not in (None, '', 'all'):
        where.append('locked = ?')
        params.append(int(filters['locked']))
    if filters.get('ou_dn'):
        where.append('ou_dn LIKE ?')
        params.append(filters['ou_dn'] + '%')
    if filters.get('department'):
        where.append('department = ?')
        params.append(filters['department'])
    if (filters.get('title') or '').strip():
        where.append('title LIKE ?')
        params.append('%' + filters['title'].strip() + '%')
    if filters.get('created_from'):
        where.append('when_created >= ?')
        params.append(str(filters['created_from']) + ' 00:00:00')
    if filters.get('created_to'):
        where.append('when_created <= ?')
        params.append(str(filters['created_to']) + ' 23:59:59')
    if filters.get('tag'):
        frag, extra = Q._tag_conditions(filters['tag'])
        if frag:
            where.append('(' + frag + ')')
            params += extra

    sql = 'SELECT * FROM ad_user_cache'
    if where:
        sql += ' WHERE ' + ' AND '.join(where)
    sql += ' ORDER BY domain_id, id'
    dm = L.domain_map()

    wb = Workbook()
    ws = wb.active
    ws.title = 'AD用户台账'
    headers = [h[1] for h in USER_HEADERS]
    _style_header(ws, headers)

    # 分批读取（游标 fetchmany），避免大数据量一次性加载进内存
    total = 0
    sample = []
    cur = db.get_conn().execute(sql, tuple(params))
    while True:
        batch = cur.fetchmany(1000)
        if not batch:
            break
        for r in batch:
            total += 1
            if total > config.EXPORT_ROW_LIMIT:
                break
            ou_name = r['ou_dn'].split(',')[0][3:] if r['ou_dn'] else ''
            ws.append([
                dm[r['domain_id']].domain_name if r['domain_id'] in dm else str(r['domain_id']),
                r['sam_account_name'], r['display_name'], r['cn'], r['user_principal_name'],
                r['mail'], r['telephone'], r['mobile'], r['title'], r['department'], r['company'],
                ou_name, '启用' if r['enabled'] else '禁用', '已锁定' if r['locked'] else '正常',
                r['pwd_expires_at'] or ('永不过期' if r['pwd_never_expires'] else ''),
                r['last_logon'], r['when_created'], r['description'], r['dn'],
            ])
            if len(sample) < 300:
                sample.append(r)
        if total >= config.EXPORT_ROW_LIMIT:
            break

    for idx, (key, title) in enumerate(USER_HEADERS, 1):
        longest = len(title) * 2
        for row in sample:
            if key == 'domain':
                val = dm[row['domain_id']].domain_name if row['domain_id'] in dm else ''
            elif key == 'status':
                val = '启用' if row['enabled'] else '禁用'
            elif key == 'locked':
                val = '已锁定' if row['locked'] else '正常'
            elif key == 'ou_dn':
                val = (row['ou_dn'] or '').split(',')[0][3:]
            else:
                try:
                    val = row[key] or ''
                except Exception:
                    val = ''
            longest = max(longest, sum(2 if ord(ch) > 127 else 1 for ch in str(val)))
        ws.column_dimensions[get_column_letter(idx)].width = max(10, min(48, longest + 2))

    ws2 = wb.create_sheet('导出说明')
    ws2.append(['导出时间', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    ws2.append(['数据来源', '本地 SQLite 缓存（非实时 AD 查询）'])
    ws2.append(['记录数', total])
    ws2.append(['域范围', '、'.join(dm[i].domain_name for i in domain_ids if i in dm) or '全部域'])
    ws2.append(['筛选条件', _describe_filters(filters)])
    ws2.column_dimensions['A'].width = 16
    ws2.column_dimensions['B'].width = 60
    bio = io.BytesIO()
    wb.save(bio)
    return bio.getvalue()


def export_logs(filters: dict) -> bytes:
    if not _HAS_OPENPYXL:
        raise RuntimeError('缺少 openpyxl 依赖')
    from modules import log_service
    rows = log_service.export_rows(filters)
    headers = ['时间', '所属域', '模块', '操作', '对象', '结果', '操作人', 'IP', '客户端', '耗时(ms)', '详情/错误']
    wb = Workbook()
    ws = wb.active
    ws.title = '操作日志'
    _style_header(ws, headers)
    module_names = log_service.MODULE_NAMES
    for r in rows:
        ws.append([_clean_cell(r['created_at']), _clean_cell(r['domain_name']) or '-',
                   module_names.get(r['module'], r['module']),
                   _clean_cell(r['action']), _clean_cell(r['target']),
                   '成功' if r['result'] == 'success' else '失败',
                   _clean_cell(r['operator']), _clean_cell(r['ip']), _clean_cell(r['client_type']) or '-',
                   r['duration_ms'],
                   (_clean_cell(r['message']) or '') + (('\n' + _clean_cell(r['detail'])) if r['detail'] else '')])
    _autosize(ws, headers, [[r['created_at'], r['domain_name'], r['action'], r['target'], r['operator']]
                            for r in rows[:300]])
    bio = io.BytesIO()
    wb.save(bio)
    return bio.getvalue()


def export_health(domains: list) -> bytes:
    """导出域控巡检结果（Excel）。"""
    if not _HAS_OPENPYXL:
        raise RuntimeError('缺少 openpyxl 依赖')
    wb = Workbook()
    ws = wb.active
    ws.title = '域控巡检'
    headers = ['域', '域控地址', '状态', 'LDAP', 'TCP', '复制状态', 'CPU(%)', '内存(%)',
               '系统盘剩余(GB)', '运行天数', '异常项', '巡检时间']
    _style_header(ws, headers)
    status_map = {'healthy': '健康', 'warning': '告警', 'critical': '严重', 'offline': '离线'}
    for d in domains:
        conn = d.get('connection') or {}
        repl = d.get('replication') or {}
        res = d.get('resource') or {}
        repl_txt = '无法采集' if not repl.get('collected') else ('有失败' if repl.get('has_failure') else '正常')
        ws.append([
            _clean_cell(f"{d.get('name')}({d.get('domain_name')})"), _clean_cell(d.get('dc_host')),
            _clean_cell(status_map.get(d.get('status'), d.get('status'))),
            '正常' if conn.get('ldap_ok') else '失败',
            '正常' if conn.get('tcp_ok') else '失败',
            _clean_cell(repl_txt),
            res.get('cpu'), res.get('mem'), res.get('disk_free_gb'), res.get('up_days'),
            _clean_cell('；'.join(d.get('issues') or []) or '—'), _clean_cell(d.get('checked_at')),
        ])
    _autosize(ws, headers, [[d.get('name'), d.get('dc_host'), d.get('status')] for d in domains[:300]])
    bio = io.BytesIO()
    wb.save(bio)
    return bio.getvalue()


def export_computers(domain_ids: list) -> bytes:
    if not _HAS_OPENPYXL:
        raise RuntimeError('缺少 openpyxl 依赖')
    rows = db.query('SELECT * FROM ad_computer_cache WHERE domain_id IN (%s) ORDER BY domain_id, name'
                    % ','.join('?' * max(1, len(domain_ids))), tuple(domain_ids or [0]))
    dm = L.domain_map()
    headers = ['所属域', '计算机名', 'DNS名称', '操作系统', '版本', 'OU', '状态', '最后登录', '备注']
    wb = Workbook()
    ws = wb.active
    ws.title = '域计算机'
    _style_header(ws, headers)
    for r in rows:
        ws.append([dm[r['domain_id']].domain_name if r['domain_id'] in dm else r['domain_id'],
                   r['name'], r['dns_host_name'], r['operating_system'], r['os_version'],
                   (r['ou_dn'] or '').split(',')[0][3:], '在线' if r['enabled'] else '禁用',
                   r['last_logon'], r['remark']])
    _autosize(ws, headers, [list(r) for r in rows[:50]])
    bio = io.BytesIO()
    wb.save(bio)
    return bio.getvalue()


def user_import_template() -> bytes:
    """导入模板（带说明页）。"""
    if not _HAS_OPENPYXL:
        raise RuntimeError('缺少 openpyxl 依赖')
    wb = Workbook()
    ws = wb.active
    ws.title = '用户导入'
    headers = ['登录名*', '显示名称*', '初始密码*', 'OU路径(可选)', '邮箱', '手机',
               '职位', '部门', '公司', '描述']
    _style_header(ws, headers, [18, 18, 16, 42, 24, 16, 16, 16, 16, 24])
    ws.append(['zhangsan', '张三', 'Init@12345', 'OU=User,DC=example,DC=local',
               'zhangsan@example.local', '13800000000', '工程师', '信息技术部', '', '示例行，导入前请删除'])
    tip = wb.create_sheet('填写说明')
    lines = [
        ['字段', '说明'],
        ['登录名*', 'AD sAMAccountName，≤20 位，仅字母数字点下划线短横线，不可重复'],
        ['显示名称*', '用户显示名；同名对象在该 OU 下会被拒绝'],
        ['初始密码*', '≥7 位且包含大写/小写/数字/符号中至少 3 类，导入后默认要求下次登录修改'],
        ['OU路径', '目标 OU 的 DN，留空则创建在域根；必须已存在于 AD 中'],
        ['邮箱/手机/职位/部门/公司/描述', '选填，直接写入 AD 对应属性'],
        ['说明', '导入会先做全量校验，全部合法才逐条创建；失败行会在结果页列出原因，可修正后重试'],
    ]
    for line in lines:
        tip.append(line)
    tip.column_dimensions['A'].width = 26
    tip.column_dimensions['B'].width = 80
    bio = io.BytesIO()
    wb.save(bio)
    return bio.getvalue()


def _read_rows(file_bytes: bytes) -> list:
    wb = load_workbook(io.BytesIO(file_bytes), read_only=True, data_only=True)
    ws = wb['用户导入'] if '用户导入' in wb.sheetnames else wb.worksheets[0]
    rows = []
    for i, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
        if not row or not any(v not in (None, '') for v in row[:4]):
            continue
        rows.append({'row': i, 'values': [('' if v is None else str(v).strip()) for v in row]})
    return rows


def validate_import(file_bytes: bytes, domain_ids: list) -> dict:
    """全量预校验，返回 {'valid': [...], 'errors': [...], 'total': n}"""
    rows = _read_rows(file_bytes)
    errors, valid = [], []
    dm = L.domain_map()
    # 已有账号集合（全量，用于重复校验）
    existing = {}
    for r in db.query('SELECT domain_id, sam_account_name FROM ad_user_cache'):
        existing[(r['domain_id'], (r['sam_account_name'] or '').lower())] = True
    seen = set()
    for row in rows:
        v = row['values'] + [''] * 10
        sam, display, pwd, ou, mail, mobile, title, dept, company, desc = v[:10]
        if not sam and not display:
            continue
        errs = []
        if not sam:
            errs.append('登录名必填')
        elif not re.match(r'^[A-Za-z0-9._\-]{1,20}$', sam):
            errs.append('登录名不合法（≤20位，仅字母数字点下划线短横线）')
        if not display:
            errs.append('显示名称必填')
        if not pwd:
            errs.append('初始密码必填')
        else:
            pe = password_strength_error(pwd)
            if pe:
                errs.append(pe)
        for target_id in domain_ids:
            if (target_id, sam.lower()) in existing:
                errs.append(f'{dm[target_id].domain_name if target_id in dm else target_id} 已存在登录名 {sam}')
        key = (sam.lower())
        if key in seen:
            errs.append('文件内登录名重复')
        seen.add(key)
        item = {'row': row['row'], 'sam_account_name': sam, 'display_name': display,
                'password': pwd, 'ou_dn': ou, 'mail': mail, 'mobile': mobile, 'title': title,
                'department': dept, 'company': company, 'description': desc}
        if errs:
            errors.append({'row': row['row'], 'sam': sam, 'errors': errs})
        else:
            valid.append(item)
    return {'valid': valid, 'errors': errors, 'total': len(rows)}


def export_import_errors(errors: list) -> bytes:
    """导出导入校验的错误明细（行号 + 登录名 + 错误原因），便于离线修正。"""
    if not _HAS_OPENPYXL:
        raise RuntimeError('缺少 openpyxl 依赖')
    wb = Workbook()
    ws = wb.active
    ws.title = '导入错误明细'
    headers = ['Excel 行号', '登录名', '错误原因']
    _style_header(ws, headers, [12, 22, 70])
    for e in errors:
        ws.append([e.get('row', ''), e.get('sam', '') or '—', '；'.join(e.get('errors', []))])
    _autosize(ws, headers, [[e.get('row', ''), e.get('sam', '') or '—', '；'.join(e.get('errors', []))]
                            for e in errors[:200]])
    bio = io.BytesIO()
    wb.save(bio)
    return bio.getvalue()


def export_security_report(res: dict) -> bytes:
    """导出安全态势体检报告（Excel）：总览 + 逐域风险明细。"""
    if not _HAS_OPENPYXL:
        raise RuntimeError('缺少 openpyxl 依赖')
    wb = Workbook()
    # Sheet 1：总览
    ws = wb.active
    ws.title = '体检总览'
    _style_header(ws, ['域', '安全评分', '高危', '中危', '低危', '巡检时间'], [28, 12, 10, 10, 10, 20])
    sev_map = {'high': '高危', 'medium': '中危', 'low': '低危'}
    for d in res['domains']:
        ws.append([f"{d.get('name')}({d.get('domain')})", d.get('score'),
                   sum(1 for f in d['findings'] if f['severity'] == 'high'),
                   sum(1 for f in d['findings'] if f['severity'] == 'medium'),
                   sum(1 for f in d['findings'] if f['severity'] == 'low'),
                   d.get('checked_at')])
    ws.append([])
    ws.append(['综合评分', res.get('overall_score'), '高危', res.get('high'),
               '中危', res.get('medium'), '低危', res.get('low')])

    # Sheet 2：风险明细
    ws2 = wb.create_sheet('风险明细')
    _style_header(ws2, ['域', '级别', '检查项', '数量', '明细'], [24, 10, 28, 8, 80])
    for d in res['domains']:
        for f in d['findings']:
            ws2.append([_clean_cell(d.get('domain')), _clean_cell(sev_map.get(f['severity'], f['severity'])),
                        _clean_cell(f['title']), f.get('count'), _clean_cell('；'.join(f.get('items') or []) or '—')])
    bio = io.BytesIO()
    wb.save(bio)
    return bio.getvalue()


def run_import(valid_rows: list, domain_ids: list, operator: str, ip: str = '') -> dict:
    """逐条创建（写直达 AD，成功后单条刷新缓存）。"""
    from modules import sync_task, log_service
    results = {'success': [], 'failed': []}
    for target_id in domain_ids:
        try:
            d = L.get_domain(target_id, only_enabled=True)
        except L.ADError as e:
            results['failed'].append({'sam': '-', 'error': f'域 {target_id} 不可用：{e.message}'})
            continue
        ok_flag, hmsg = L.health(d, ttl=config.AD_WRITE_HEALTH_TTL)
        if not ok_flag:
            results['failed'].append({'sam': '-', 'error': f'{d.label} 当前离线：{hmsg}'})
            continue
        for item in valid_rows:
            try:
                created = L.create_user(d, item)
                sync_task.refresh_user_by_dn(d, created['dn'])
                results['success'].append({'sam': item['sam_account_name'],
                                           'domain': d.domain_name, 'dn': created['dn']})
                log_service.write('user', 'import_user', target=created['dn'], result='success',
                                  detail=f'批量导入至 {d.domain_name}', operator=operator, ip=ip,
                                  domain_id=d.id, domain_name=d.label)
            except Exception as e:
                msg = e.message if isinstance(e, L.ADError) else str(e)
                results['failed'].append({'sam': item['sam_account_name'], 'error': msg})
                log_service.write('user', 'import_user', target=item['sam_account_name'],
                                  result='failed', message=msg, operator=operator, ip=ip,
                                  domain_id=d.id, domain_name=d.label)
    return results

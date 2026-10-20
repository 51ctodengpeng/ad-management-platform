# AD 域控管理系统

基于 **Flask + ldap3 + pywinrm + SQLite** 的 Active Directory Web 管理平台，用于在浏览器中集中管理多套 AD 域的用户、组织单位（OU）、安全组与计算机，并支持跨林信任的一键建立。

设计上遵循一条铁律：**所有写操作直连真实 AD，只有 AD 返回成功后才会更新本地缓存；所有读操作（列表、搜索、分页、筛选、仪表盘、导出）只读本地缓存。** 这样既保证了数据一致性，也让页面在域控不可达时仍可快速响应。

---

## 0. 直接下载安装包

不想装 Python、不想看源码的，用打包好的安装程序：

**下载地址：<https://github.com/51ctodengpeng/ad-management-platform/releases>**

| 文件 | 说明 |
| --- | --- |
| `AD域控管理系统_安装程序_v1.0.3.exe` | Windows 安装包（约 24.7 MB），内含运行时，目标机无需 Python |
| `AD域控管理系统用户操作手册.docx` | 运维操作手册 |
| `用户文档与许可协议.html` | 安装向导内的用户文档与许可协议 |

校验值与安装前须知见 [`dist/v1.0.3/README.md`](dist/v1.0.3/README.md)，**装之前请先看一眼**。

> 安全提示：这是内网运维工具，不要直接映射到公网；对外提供服务时必须启用 HTTPS。理由见 [`SECURITY.md`](SECURITY.md)。

---

## 1. 快速开始

### 1.1 环境要求

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Windows Server 2012 R2 及以上 / Windows 10 及以上 |
| Python | 3.10 ~ 3.13（已在 3.13 上验证） |
| 域控开放端口 | LDAP 389、LDAPS 636（写密码必需）、WinRM 5985（信任建立必需） |
| 浏览器 | Chrome / Edge 最新版 |

### 1.2 安装与启动（源码方式）

```bat
pip install -r requirements.txt
python app.py
```

启动后访问 <http://127.0.0.1:8000>，使用首次运行自动生成的运维账号登录（默认 `admin` / `powershell@2025`，可通过环境变量 `ADM_ADMIN_USER` / `ADM_ADMIN_PASSWORD` 覆盖）。

> 生产环境请加 `--prod` 参数启动，此时使用 waitress 多线程承载：
>
> ```bat
> python app.py --prod
> ```
>
> 若未安装 waitress 会回退到 Flask 内置服务器并打印告警（不建议生产使用）。

### 1.3 打包为可执行程序

```bat
deploy\build_portable.bat
```

产物为 `dist\AD域控管理系统\AD域控管理系统.exe`（onedir 形式，启动约 1 秒）。配套的 Inno Setup 脚本 `deploy\installer.iss` 可进一步生成安装包。详细说明见 `deploy\README_部署说明.txt`。

---

## 2. 功能概览

- **多域管理**：同时纳管最多 20 个域，每个域独立配置域控地址、Base DN、管理员凭据与连接方式；支持连通性测试与在线状态巡检。
- **用户管理**：浏览、搜索、分页、排序、条件筛选（禁用 / 锁定 / 密码过期 / 即将过期 / 从未登录 / 90 天未登录 / 密码永不过期）、新建、编辑、启用停用、解锁、重置密码、移动 OU、加退组、删除、批量操作、Excel 导入导出。
- **用户详情**：基础资料读缓存；**锁定状态、密码到期时间、最后登录时间等敏感实时字段直连该域 AD 单条查询**，并标注数据获取时间。
- **OU 管理**：树形浏览、新建子 OU、新建根级 OU、重命名、改描述、批量迁移用户、递归删除（需输入名称确认）。
- **安全组管理**：按域 / 关键字 / 作用域 / 类别筛选，组详情内实时读写成员，受保护组禁止删除。
- **计算机管理**：列表、备注、描述回写、启用停用，超过 30 天未登录标记为离线。
- **跨林信任**：通过 WinRM 调用 `netdom` 一键建立双向或出站信任，创建前连通性预检、支持试运行、需输入确认文本、失败时逐步骤返回原因且**不修改任何缓存**。
- **操作审计**：所有写操作记录操作人、来源 IP、目标对象、结果、耗时与详细报错，支持按模块 / 关键字 / 域 / 日期检索与 Excel 导出。
- **系统维护**：系统账号管理、修改自身密码、后台任务查看、定时任务状态、日志清理。

---

## 3. 目录结构

```
AD域控管理系统/
├── app.py                  应用入口：蓝图注册、调度器/任务队列启动、控制台编码修正
├── config.py               集中配置：路径、端口、SQLite PRAGMA、容量上限、调试域信息
├── requirements.txt
├── database/               SQLite 数据文件（首次运行自动创建）
├── logs/                   运行日志（按天滚动）
├── modules/                业务与基础设施
│   ├── db.py               连接池（线程本地）、PRAGMA、事务、租约锁、建表与迁移
│   ├── security.py         凭据 Fernet 加密、PBKDF2 口令哈希、密码策略、随机密码
│   ├── ad_ldap.py          LDAP 封装：连接、搜索、用户/组/OU/计算机 CRUD、实时状态
│   ├── ad_trust.py         跨林信任：预检、netdom 调用、结果解析、验证与撤销
│   ├── sync_task.py        同步引擎：主动/增量/全量三种同步与脏数据清理
│   ├── query_service.py    查询服务：用户检索、OU 树、组/计算机列表、统计
│   ├── excel_service.py    Excel 导入导出与导入校验
│   ├── domain_service.py   域配置读写、状态健康度、凭据加解密
│   ├── auth_service.py     登录、会话、改密
│   ├── log_service.py      操作日志写入与检索
│   ├── scheduler.py        APScheduler 定时任务注册
│   ├── task_queue.py       后台任务队列 worker
│   └── applog.py           统一日志器
├── routes/                 蓝图（HTTP 层）
│   ├── common.py           登录态装饰器、统一响应、写保护、二次确认、DN 转义工具
│   ├── auth.py dashboard.py user.py ou.py group.py computer.py
│   ├── domain.py trust.py log.py config.py
├── templates/              Jinja2 模板（Bootstrap 5 + AdminLTE 风格）
├── static/                 CSS / JS / 本地化的 Bootstrap 资源
├── deploy/                 打包与部署脚本、Inno Setup 脚本、部署说明
├── dist/                   已发布的安装包与配套文档（按版本分目录）
├── tests/                  自动化验证脚本
├── SECURITY.md             安全策略与漏洞报告方式
└── LICENSE                 MIT 许可
```

---

## 4. 数据模型

| 表 | 说明 |
| --- | --- |
| `sys_user` | 运维账号（PBKDF2 哈希、角色、状态、最后登录） |
| `ad_domain_conf` | 域配置（域控地址、Base DN、加密凭据、连接方式、健康状态） |
| `ad_user_cache` | 用户缓存，含 `domain_id`、DN、OU、账号控制位、密码到期、登录时间等 |
| `ad_ou_cache` | OU 缓存，含父子关系与层级 |
| `ad_group_cache` | 安全组缓存，含作用域、类别、成员数 |
| `ad_computer_cache` | 计算机缓存，含操作系统、最后登录、备注 |
| `ad_trust_cache` | 信任关系缓存（方向、类型、状态、验证结果） |
| `ad_operation_log` | 操作审计日志 |
| `task_queue` | 后台任务队列（同步/批量任务状态跟踪） |
| `app_lock` | 跨进程租约锁（同步互斥、批量写互斥） |
| `sys_setting` | 键值配置（如增量同步水位） |

初始化时统一设置 SQLite 生产参数：

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = 10000;
PRAGMA busy_timeout = 30000;
```

WAL 允许读写并发，配合租约锁与批量分片提交，避免大事务造成的锁库与页面卡顿。

---

## 5. 同步机制（三保险）

| 层级 | 触发时机 | 作用 |
| --- | --- | --- |
| 主动同步 | 每次写 AD 成功后 | 单条 upsert，页面立即可见最新结果 |
| 增量同步 | 每 15 分钟，按域独立任务 | 以 `uSNChanged` 水位拉取变更，只处理变动对象 |
| 全量同步 | 每日 02:00 | 全量比对 + 清理已删除的脏数据 + 校正计数 |

- 每域使用独立租约锁 `sync:domain:<id>`，手动同步与定时任务互斥，不会重复拉取。
- 批量写 AD 共用 `sync:global` 锁，禁止并发批量写。
- 单域失败只影响该域，事务回滚，缓存保持上一次一致状态，并在日志中标注具体域名。
- 每 200 条提交一次，避免长事务阻塞读取。

---

## 6. 安全设计

- **凭据保护**：域管理员密码使用 Fernet（AES-128-CBC + HMAC）加密存储，带 `enc:` 前缀；兼容历史明文数据，读取时自动识别。
- **口令哈希**：运维账号口令使用 PBKDF2-HMAC-SHA256 + 随机盐，比对使用常量时间比较。
- **会话**：登录态存于服务端会话，默认空闲 120 分钟失效；登录失败信息不区分「账号不存在」与「密码错误」。
- **写保护**：域处于离线状态时自动进入只读模式，写接口直接拒绝，避免误操作堆积。
- **二次确认**：重置密码、删除用户、删除组、删除 OU、建立/撤销信任等高危操作，前端弹窗 + 后端 `require_confirm()` 双重校验；部分操作还要求手动输入对象名。
- **受保护组**：`Domain Admins`、`Enterprise Admins`、`Schema Admins` 等关键组禁止删除。
- **审计**：所有写操作落库，含操作人、IP、目标、结果、耗时、错误摘要。

---

## 7. 关键接口

统一返回格式 `{"ok": true, "data": ..., "message": "..."}`，失败返回 `{"ok": false, "message": "...", "code": "..."}`。

### 认证
| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET/POST | `/login` | 登录（仅接受表单） |
| GET/POST | `/logout` | 注销 |
| GET | `/profile` | 个人中心 |
| POST | `/api/profile/password` | 修改自身密码 |

### 域与信任
| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/domains/` | 域列表 |
| POST | `/domains/save` | 新增/保存域配置 |
| POST | `/domains/<id>/test` | 连通性测试 |
| POST | `/domains/<id>/sync` | 单域同步 |
| POST | `/domains/sync-all` | 全量同步所有域 |
| POST | `/domains/refresh-status` | 刷新在线状态 |
| GET | `/domains/api/status` | 状态轮询 |
| GET | `/trust/` | 信任列表 |
| POST | `/trust/preflight` | 建立前连通性预检 |
| POST | `/trust/create` | 创建信任（试运行 / 正式） |
| POST | `/trust/refresh` | 刷新信任状态 |
| POST | `/trust/remove` | 撤销信任 |

### 用户
| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/users/` | 用户列表（缓存） |
| GET | `/users/api/list` | 列表 JSON |
| GET | `/users/facets` | 筛选候选值（部门 / OU 数 / 域名 / Base DN） |
| GET | `/users/<id>` | 用户详情（基础信息缓存 + 实时状态直连） |
| POST | `/users/create` | 新建用户 |
| POST | `/users/<id>/update` | 编辑 |
| POST | `/users/<id>/toggle` | 启用/停用 |
| POST | `/users/<id>/unlock` | 解锁 |
| POST | `/users/<id>/reset-password` | 重置密码 |
| POST | `/users/<id>/move` | 移动 OU |
| POST | `/users/<id>/groups` | 加入/移出组 |
| POST | `/users/<id>/delete` | 删除 |
| POST | `/users/batch` | 批量操作 |
| POST | `/users/import/validate` | 导入校验 |
| POST | `/users/import/run` | 执行导入 |
| GET | `/users/export` | 导出 Excel |

### OU / 组 / 计算机
| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/ous/api/tree` | OU 树 |
| POST | `/ous/create` `/update` `/delete` | OU 增改删 |
| POST | `/ous/move-users` | 批量迁移用户 |
| GET | `/groups/` `/groups/<id>` | 组列表 / 详情 |
| GET | `/groups/api/options` | 组下拉选项 |
| POST | `/groups/<id>/members` | 成员维护 |
| GET | `/computers/` | 计算机列表 |

### 日志与维护
| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/logs/` | 操作日志（多条件检索） |
| GET | `/logs/export` | 导出 Excel |
| POST | `/logs/maintain` | 清理历史日志 |
| GET | `/config/` | 系统配置与运维面板 |
| GET | `/config/jobs` | 定时任务列表 |
| POST | `/config/prune-tasks` | 清理任务队列 |

---

## 8. 容量与性能

- 单域 ≤ 20000 用户、≤ 20 个域（默认配置上限，可在 `config.py` 调整）。
- 列表查询走缓存并配合索引（`domain_id`、`sam_account_name`、`ou_dn`），分页查询稳定在毫秒级。
- OU 树构建为 O(n) 单次遍历，不做递归查询。
- 搜索支持 6 个字段的关键字匹配与白名单字段排序，避免任意字段拼接 SQL。
- 导出分块写入，单次导出上限可配置，避免大结果集耗尽内存。

---

## 9. 验证脚本

所有脚本均在真实域控与本地缓存上跑通：

| 脚本 | 用途 |
| --- | --- |
| `tests/smoke_pages.py` | 登录后遍历 22 个页面，断言 HTTP 200 且无模板错误 |
| `tests/test_cache_layer.py` | 缓存层、事务、租约锁、查询、导出、加密、密码策略（49 项） |
| `tests/e2e_api.py` | 端到端：OU/用户/组创建改名、启停、重置密码、移动、批量、导入导出 |
| `tests/verify_exe.py` | 启动打包后的 exe，验证页面与静态资源可访问 |

```bat
python tests\smoke_pages.py
python tests\test_cache_layer.py
```

---

## 10. 常见问题

**Q：提示「凭据认证失败」，但域控是通的？**
域管理员密码可能已在 AD 侧被修改。到「域管理 → 编辑」中更新管理员密码并保存，再点「测试连通性」。期间缓存数据不受影响，页面仍可正常浏览。

**Q：提示「网络不可达 / 连接超时 / 端口被拒绝」？**
这是网络层问题，不是密码问题。连通性测试会先做 TCP 预探测再尝试绑定，因此能区分三种情况：

| 提示 | 含义与处理 |
| --- | --- |
| 地址解析失败 | 主机名写错或 DNS 不可用，改填域控 IP |
| 连接超时 | 域控服务未运行 / 防火墙拦截 / 路由不通 |
| 端口被拒绝 | 目标端口未监听，AD 服务可能已停止 |
| 凭据认证失败 | 网络通，但账号或密码错误 |

快速自查：`Test-NetConnection 192.168.31.96 -Port 389`。若 5985 通而 389 不通，通常是 AD 服务重启中或防火墙策略变更。

**Q：重置密码报 `unwillingToPerform`？**
AD 要求 `unicodePwd` 必须在加密通道上写入。系统会自动尝试 LDAPS(636)，失败后回退 STARTTLS。请确认域控已部署证书且 636 端口放通。

**Q：建立信任失败？**
先点「预检」，确认 WinRM 5985 可达、对方森林域名解析正常、双方管理员凭据正确。`netdom` 仅在 Windows 域环境可用；失败时页面会逐步骤列出原因，且不会修改缓存。

**Q：页面数据不更新？**
缓存刷新依赖同步。可手动点「同步」或等待 15 分钟增量同步。若域处于离线状态，同步会被跳过，页面进入只读模式。

---

## 11. 许可与安全

本项目以 **MIT License** 发布，可自由使用、修改与再分发，保留版权声明即可，详见 [`LICENSE`](LICENSE)。

软件按「现状」提供，不附带任何担保。**它能对真实 Active Directory 执行写操作**，请先在测试域验证再用于生产。

发现安全问题请走私下渠道（仓库 **Security → Report a vulnerability**，或邮件 `dengpeng@powershell.com.cn`），不要开公开 Issue。范围界定、响应时效与部署硬性要求见 [`SECURITY.md`](SECURITY.md)。

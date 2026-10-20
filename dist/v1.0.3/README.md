# AD 域控管理系统 · 发布产物

安装包与配套文档统一通过 **GitHub Releases** 分发，不放进 git 历史（单个 exe 约 25 MB，进版本库会让每次克隆都变慢）。本目录只保留每个版本的说明与校验值。

**下载地址：<https://github.com/51ctodengpeng/ad-management-platform/releases>**

---

## v1.0.3

| 文件 | 用途 | 大小 | SHA256 |
| --- | --- | --- | --- |
| `AD域控管理系统_安装程序_v1.0.3.exe` | Windows 安装包（Inno Setup），内含运行时，目标机无需装 Python | 24.7 MB | `d44922452abe6330bc65acf54b1cf99485793ae48d2ac043edc187058bfd271a` |
| `AD域控管理系统用户操作手册.docx` | 面向运维的操作手册：登录、域接入、用户/OU/组管理、同步、常见故障 | 23 KB | `6fa06d195ae9b881ddeba4d13d8f41874218978f595f147395247c69793ba9af` |
| `用户文档与许可协议.html` | 安装向导中展示的用户文档与许可协议原文 | 22 KB | `184cc42595411e33d9c5b03e1a81720b07fca9657d16634895b94d20259bb457` |

校验方式（Windows PowerShell）：

```powershell
Get-FileHash .\AD域控管理系统_安装程序_v1.0.3.exe -Algorithm SHA256
```

哈希与上表不一致时**不要安装**。

---

## 安装前须知

1. **环境**：Windows Server 2012 R2 及以上 / Windows 10 及以上；域控需放通 LDAP 389、LDAPS 636、WinRM 5985。
2. **以管理员身份运行安装程序**。默认安装到 `C:\Program Files\AD域控管理系统`，数据目录在安装目录下的 `database/`。
3. **首次启动会生成随机管理员口令**，只在控制台窗口打印一次。请当场记录，登录后立即修改。
4. **不要暴露到公网**。本系统是内网运维工具，远程访问请走 VPN 或堡垒机；对外提供服务时务必在反向代理上启用 HTTPS。
5. 升级前请备份 `database/` 目录，其中包含配置、加密后的域凭据与业务缓存。

完整的安全部署要求见仓库根目录的 [`SECURITY.md`](../../SECURITY.md)。

---

## 版本记录

### v1.0.3

- 首个发布版本：安装程序 + 用户操作手册 + 用户文档与许可协议
- 源码对应 `main` 分支 `v1.0.3` tag

> 发布新版本时：先在 Releases 建 tag 并上传文件，再在本目录新建 `<版本>/README.md` 记录校验值，最后在 `.gitignore` 的「发布产物例外」段落追加该目录的放行规则。

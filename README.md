# drcom4scut — Windows 命令行版本

基于华南理工大学第三方 DrCOM 客户端改造，面向大学城校区有线网络。

目标：无人登录 Windows 时也能自动认证，断线自动恢复，平时无需打开控制台，故障时可查询日志。

## 首次使用

需要 Windows x64 和 [Npcap](https://npcap.com/#download)。不要求将 Npcap 添加到系统 PATH，也不要求重新安装为 WinPcap 兼容模式。

将 `drcom4scut.exe` 和 `drcom4scut-worker.exe` 保存在同一目录。使用 PowerShell：

从 GitHub Releases 下载 `drcom4scut-v0.4.0-windows-x64.zip` 并解压即可得到两个程序、说明、许可证和配置示例。**压缩包不包含真实账号密码。** 需要从当前电脑迁移配置时，单独复制原来的 `config.yml`，不要将其上传到 GitHub。

```powershell
.\drcom4scut.exe doctor
.\drcom4scut.exe init
```

编辑生成的 `config.yml`，填写：

```yaml
mac: 'xx:xx:xx:xx:xx:xx'  # doctor 列表中物理有线网卡的 MAC
username: '你的学号'
password: '你的密码'
```

保留其余默认配置。账号和密码应使用引号；单引号字符串内的单引号写成两个单引号。

```powershell
# 仅测试驱动能否打开指定网卡，不发认证包、不需要账号。
.\drcom4scut.exe doctor --mac xx:xx:xx:xx:xx:xx
# 前台认证；Ctrl+C 结束。
.\drcom4scut.exe run
.\drcom4scut.exe logs
```

多个网卡都有 IPv4 地址时，需要显式填写有线网卡 MAC，避免误选 Wi-Fi、VMware 或 VPN。实际认证需要有线网卡已有可用 IPv4 地址；尚未获得地址时会等待并重试。

认证服务器的 DNS 查询及 UDP 心跳都绑定到选中的有线 IPv4 地址，避免同时连接 Wi-Fi 时心跳从另一张网卡发出。

## 开机自动联网（Windows 服务）

先完成前台认证验证，再在**管理员 PowerShell** 中执行：

```powershell
.\drcom4scut.exe service install
.\drcom4scut.exe service start
.\drcom4scut.exe service status
.\drcom4scut.exe logs --service
.\drcom4scut.exe logs --service --supervisor
```

服务以 LocalSystem 身份自动启动，不依赖用户登录。安装会将两个程序和配置复制到 `%ProgramData%\drcom4scut`，并将该目录的访问权限限制为管理员和 SYSTEM；配置包含密码，不写入程序参数或日志。

安装只注册服务，不立即发起认证；`service start` 才开始运行。安装后的配置与原目录配置独立，后续修改服务账号或网卡，请用管理员权限编辑 `%ProgramData%\drcom4scut\config.yml`，然后停止并重新启动服务。

服务固定使用安装目录内的 `logs`，开启 INFO 文件日志，关闭控制台输出。`service status` 表示 Windows 服务的运行状态，**不等于认证成功或已能访问互联网**；认证和心跳结果请查看 `logs --service`。

恢复机制：

- 开机时网卡或 IPv4 尚未就绪：按 `reconnect` 秒等待后重试。
- 协议认证失败：沿用原有重试机制和校园网时段限制处理。
- 网卡消失或原 IPv4 地址不再存在：最多 5 秒发现，然后重启认证进程。
- UDP 心跳持续超时：重新启动完整认证流程。
- 认证进程异常退出：服务等待 15 秒后重启；服务自身崩溃：由 Windows 服务恢复策略重启。
- 停止服务：终止认证进程；服务进程异常退出时，通过 Windows Job Object 清理认证进程。

```powershell
.\drcom4scut.exe service stop
.\drcom4scut.exe service uninstall
```

卸载保留配置、程序和日志。此版安装拒绝覆盖已有安装目录；重新安装前，先停止并卸载服务，再由管理员备份、重命名原目录。不要同时运行多个认证客户端。

## 常见问题

| 现象 | 排查方法 |
| --- | --- |
| Npcap Packet.dll 缺失 | 安装 x64 Npcap，然后运行 `doctor` |
| 无法打开网卡 / 拒绝访问 | 检查 Npcap 驱动；若安装时启用了仅管理员访问，用管理员终端测试 |
| 多个候选网卡 | 用 `doctor` 找到物理有线网卡，将其 MAC 写入配置 |
| 网卡没有可用 IPv4 | 检查网线、网卡是否启用、校园网地址分配 |
| 服务未安装或管理权限不足 | 查看错误中的 Windows 原因；安装、启停和卸载需要管理员权限 |
| 服务在运行但无法联网 | 查看认证日志和心跳；再看 `logs --service --supervisor` 中的进程重启原因 |
| 认证进程启动后退出 | 查看 `%ProgramData%\drcom4scut\logs\worker-errors.log` 和 `latest.log` |

认证日志每 1 MiB 滚动，保留 10 个压缩历史文件。服务日志在 1 MiB 后保留一个历史文件，进程错误日志在下次启动时检查并轮转。不要公开含账号信息的配置和日志。

## 构建与测试

Rust 1.92 或更高版本。Windows 需要 C/C++ 链接工具及 [Npcap SDK](https://npcap.com/guide/npcap-devguide.html)。把 SDK 的 `Lib/x64/Packet.lib` 放到项目根目录，或者将环境变量 `NPCAP_SDK_DIR` 指向 SDK 根目录。

```powershell
cargo build --release --locked
# 认证进程的测试需要加载 Packet.dll；管理入口不依赖这个 DLL。
$env:PATH = "$env:WINDIR\System32\Npcap;$env:PATH"
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
./scripts/package-windows.ps1
```

构建结果位于 `target/release`。打包脚本会构建并输出 `dist/drcom4scut-v0.4.0-windows-x64.zip` 及 SHA-256 校验文件；压缩包同时包含两个可执行文件。管理入口为 Npcap 设置认证子进程的 DLL 搜索路径，不修改系统 PATH。

将源码推到 fork 的 `master` 分支后，GitHub Actions 自动构建并提供本次运行的临时构建附件，并按 `Cargo.toml` 中的版本号创建 GitHub Release 与同名标签，提供长期可下载的 Windows 压缩包和校验文件。以后的版本先修改 `Cargo.toml` 和 `Cargo.lock` 中的版本号，再构建、提交和推送。不要把 `config.yml`、`logs`、`target` 或 `dist` 提交到 Git；它们已被忽略。

`--no-default-features` 保留前台简易日志模式，不支持安装后台服务。原客户端参数可以通过 `drcom4scut-worker --help` 查看（直接启动 worker 时需自行设置 Npcap DLL 路径）。完整配置模板见 [src/default_config.yml](src/default_config.yml)。

Linux 保留前台认证入口；Windows 服务仅在 Windows 可用。本次改造的实机验证以 Windows 为准。

## 验收范围

已复现原版在未设置 Npcap DLL 路径时的启动失败，并验证新入口能够枚举、打开本机 Realtek 有线网卡。无账号检查不会发送认证包。

2026-10-01 本机实测：真实账号通过 802.1X 认证、UDP 初始握手及连续心跳；通过指定有线源地址访问联网检测页面成功。测试中发现多网卡环境下原版 UDP 可能走 Wi-Fi，绑定有线源地址后心跳恢复正常。

同日完成 Windows 服务实测：以 LocalSystem 身份自动启动配置安装成功；服务启动、停止时清理认证进程、再次启动均通过。分别强制结束认证进程和服务进程后，均在 35 秒内观察到重新认证和两轮 UDP 心跳完成，随后有线联网检测通过。测试结束时服务保持运行。10 项自动测试及静态检查通过；原有依赖固定网卡地址的测试仍忽略，实际网卡已单独验证。

仍需实际操作验收：拔插网线后恢复、休眠唤醒后恢复，以及重启后不登录 Windows 时的自动联网。

## 上游与许可证

上游项目：[SeaLoong/drcom4scut](https://github.com/SeaLoong/drcom4scut)。保留仓库现有 [LICENSE](LICENSE)；感谢原作者及贡献者。

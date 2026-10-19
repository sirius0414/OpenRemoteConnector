# OpenRemoteConnector

让设备所有者将指定能力、在有限期限内授权给 Agent，并在终端保留授权、审批与停止任务的最终控制。

当前仓库已包含 Rust 实现和测试，处于 **P0 开发验证阶段，尚未达到 P0 发布验收**。Linux Ubuntu 24.04 x86_64 是执行目标；macOS 可运行控制层和开发测试，不提供宿主执行后备。实际完成范围、功能缺口与未验收项目见 [P0 状态](docs/validation/P0-STATUS.md)。

## 构建与使用

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
cargo run -p orc-cli -- --help
```

[快速开始](docs/QUICKSTART.md) 说明角色初始化、TLS、客户端登录、设备信任和本机 grant。开发者可运行 `cargo run -p orc-cli -- setup --role complete --root /absolute/private/orc` 生成独立配置；初始化不自动开放执行权限，缺少证书、连接或授权时保持不可执行。源码构建需要固定 Rust 工具链；离线安装器支持核验指定发布者签名和包摘要，仓库尚无公开发行包下载地址。

交付二进制：

- `orc`：角色初始化、诊断、签名离线包校验/安装和本地管理。
- `orc-mcp`：OAuth、原生 MCP、设备目录与转发；不包含执行后端。
- `orc-endpoint`：终端授权、策略、审批、异步任务、快照与文本回写。
- `orc-runner` 与 `orc-watchdog`：Linux 任务监督、受控入口执行与独立停止核实。

MCP 和终端各有独立 SQLite 与安全 journal。设备主动连接 MCP 的双向 TLS 入口；Agent 使用原生 HTTP MCP 与 OAuth。公开 Agent 入口需自行配置可达 HTTPS 反向代理，设备 TLS 在 MCP 终止。无可达入口时不会自动购买服务器、创建账户或寻找中继。

## 权限与任务语义

登录、登记设备和安装 MCP 均不授予执行权限。授权绑定主体、设备、UID、环境、动作、策略和期限；两种执行环境各自支持自动、规则和逐次审批策略。Agent 无权创建 grant 或批准自己的请求。

宿主模式使用执行账户的真实文件与工具，工作目录与规则不是文件隔离。隔离模式使用批准快照和固定离线环境；gVisor、专用 rootless 引擎或验证证据缺失时拒绝执行，不转为宿主模式。执行后端仍需在实际目标环境完成资源与停止验收。

任务接受后不依赖单次 HTTP 请求存活。相同 UUIDv7 和相同请求用于重试；同 ID 不同内容拒绝。取消请求与终止确认分别显示，未知启动不会自动重跑。输出有界并视为不可信数据。隔离回写必须本地审批、核对基线和受管工作区排他约定；多文件失败逐项报告。

## 文档与样例

- [PRD](docs/PRD.md)、[架构契约](docs/ARCHITECTURE.md)、[详细设计](docs/DESIGN.md)
- [当前验证与缺口](docs/validation/P0-STATUS.md)、[执行后端验证](docs/validation/EXECUTION.md)
- [实现决策与偏离](docs/decisions/0001-rust-implementation.md)
- [Agent 单入口 Skill](skills/orc/SKILL.md)
- [离线工作流样例](examples/README.md)、[Python 环境](environments/python/README.md)

`docs/history/` 和旧 `docs/LINUX_SANDBOX.md` 仅作历史参考。MCP 是客户端身份与数据处理可信方；MCP 失陷仍可能冒用已获准主体。宿主同账户任意代码不在管理 socket 的隔离保证内；云端 Agent 收到的结果进入其服务商的数据处理链路。

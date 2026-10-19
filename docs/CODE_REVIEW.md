# P0 代码阅读与 review 指南

本文对应 `dev-P0` 的当前实现，帮助 reviewer 沿调用链检查权限、持久化顺序和失败语义。它不代表发布验收；实际缺口和平台验证范围见 [P0 状态](validation/P0-STATUS.md)。总体契约见 [架构](ARCHITECTURE.md) 和 [详细设计](DESIGN.md)。

## 从哪里开始

| 阅读目标 | 入口与后续路径 | 重点 |
| --- | --- | --- |
| 身份与权限 | [domain](../crates/orc-domain/src/lib.rs)：`Principal`、`Grant`、`RuleSet` | 登录身份与执行 grant 分开；规则使用解析后的入口摘要 |
| Agent 调用 | [mcp](../crates/orc-mcp/src/lib.rs)：`authenticate` → `invoke` → `forward` | 主体来自认证中间件；服务允许转发不等于终端允许执行 |
| 设备连接 | [transport](../crates/orc-transport/src/lib.rs) → MCP `device_session` → [endpoint](../crates/orc-endpoint/src/lib.rs) `session` | 证书固定、身份签名、连接代数、撤销同步 |
| 接受与执行 | endpoint `submit` → `resolve` → `tick` → [execution](../crates/orc-execution/src/lib.rs) | 请求去重、有效规格绑定、审批消费与单次启动 |
| 崩溃恢复 | [store](../crates/orc-store/src/lib.rs)：`commit`、`apply_event`；endpoint `open`、`load_body` | journal 先持久化；旧任务不重新获得启动资格 |
| 宿主执行 | [host backend](../crates/orc-backend-host-linux/src/lib.rs) → [runner](../crates/orc-runner/src/main.rs) | systemd 等待实例、单次 gate、入口 FD、整组停止证据 |
| 隔离执行 | [gVisor backend](../crates/orc-backend-gvisor/src/lib.rs) | 环境验证、固定镜像、停止后采集与分阶段清理 |
| 独立停止 | [watchdog](../crates/orc-watchdog/src/main.rs) | 实例绑定租约、期限、停止确认；没有启动路径 |
| 快照与回写 | [workspace](../crates/orc-workspace/src/lib.rs) → endpoint `apply_changes` | 固定字节、目录 FD、全量基线检查、逐文件授权及部分结果 |
| 所有者控制 | [admin](../crates/orc-admin/src/lib.rs)、[CLI](../crates/orc-cli/src/main.rs)、[installer](../crates/orc-installer/src/lib.rs) | 本地 UID 边界、配置与信任切换、维护停止证据 |

## 一次任务提交的顺序

1. MCP 的 HTTP 中间件验证访问令牌，并把服务端构造的 `Principal` 放入请求上下文。工具参数不能替换这个主体。
2. `Mcp::forward` 检查服务可见范围、设备登记和能力。提交使用原始请求摘要记录投递意图，信封再绑定设备、主体、连接代数及服务策略版本。
3. `Endpoint::session` 验证信封，`submit` 先按 `(principal_id, device_id, submission_id)` 查询原提交。同 ID、同摘要返回原任务；同 ID、不同摘要拒绝。仅新提交检查 UUIDv7 时窗。
4. `resolve` 检查 grant，固定环境、cwd、入口身份及脚本字节，再按真实入口摘要评估规则。策略预览也走这条解析路径。
5. `submit` 获得 `gate` 后重新读取 grant，确认解析期间权限没有变化。Store 将去重记录、任务和可选待审批记录作为一次接受事件持久化，然后返回任务状态。
6. 独立 `tick` 处理已接受任务。它持久写入 `starting`，释放 `gate` 做后端准备，保存实例关联，再重新取得锁复核授权、取消、期限和连接条件。
7. 如需审批，先持久消费审批，再持久记录启动尝试，最后生成 `LaunchPermit` 调用后端 `start`。这几步不是一个跨数据库与运行时的原子事务；中途失败必须保留原实例并核实，不能自动重跑。

原始请求摘要用于提交去重；有效审批摘要还绑定主体、grant 与解析后的执行规格。后端的 `spec_digest` 又用于绑定实际实例。review 时需要区分这些摘要的用途。

## 并发与持久化边界

| 机制 | 保护范围 | 修改时需要保持的约束 |
| --- | --- | --- |
| OAuth actor | 授权码消费、令牌轮换及家族撤销 | 持久化成功后才替换内存状态；重放错误中的撤销也必须提交 |
| Store 专用线程 | 数据库操作的串行顺序 | 入队后响应接收者断开不撤销写入；控制队列保留优先处理机会 |
| MCP `permissions` | 服务权限、转发签名入队、同步后的连接发布 | 等响应时释放锁；回传结果前复核权限；控制队列满则关闭连接要求重同步 |
| Endpoint `body_lock` | 正文对象引用建立与留存 GC | 提交同时需要授权锁时按 `body_lock` → `gate` 获取 |
| Endpoint `gate` | 本地权限变化、最终启动、每个文件的回写 | 慢速 prepare 在锁外，启动前重新取得锁复核；回写 guard 覆盖实际修改和结果记录 |
| `InstanceControl` | endpoint 与 watchdog 跨进程运行时控制 | 停止意图先落盘，且永久禁止尚未放行的实例再启动 |
| `WorkspaceGuard` | 遵守约定的编辑器和 ORC 写入 | 编辑器继承锁 FD；不声称约束同 UID 任意程序 |

`Database::commit` 先追加并同步安全 journal，再提交 SQLite 事务。若 journal 已写入而 SQL 失败，实例会拒绝继续处理，要求重新打开并恢复。恢复旧数据库时保留当前 journal，才能保住撤销、审批消费、提交去重及正文过期事实。任务事件的 journal 副本剔除正文，恢复流程只恢复事实，不执行命令。

## 容易误读的状态

| 状态或响应 | 实际含义 | 后续处理 |
| --- | --- | --- |
| `accepted` | 已持久接受 | 调度器仍需检查当前授权并启动 |
| `delivery_unknown` | MCP 没拿到确定投递响应 | 查询原 `submission_id`，不能换 ID 重跑 |
| `execution_state=unknown` | 启动或运行证据不足 | 核实/停止原实例，不能回到 accepted |
| `stop_state=requested` | 停止意图已记录 | 后端继续核实，不能展示为已停止 |
| `RevokeAck` / `delivered` | 终端已持久接收撤销 | 是否停止要看任务与后端证据 |
| runner 主命令退出 | 主命令已有退出结果 | 后代进程仍可能存在，须由后端确认整个实例停止 |
| 回写 `Unknown` / 部分成功 | 某些文件结果不能确定或整批尚未完成 | 核对当前内容和 apply journal，禁止整批重放 |

## 回写和维护的检查重点

`ManagedWorkspace::apply` 持工作区锁，先校验整批基线和新对象，再创建防重放 journal、消费审批，逐文件重新获取授权。一次文件修改的授权 guard 覆盖基线复核、文件操作、同步和结果记录。文件之间没有原子事务；撤销或错误发生后保留部分结果，`reconcile` 只核对当前内容。

信任更换先撤销旧信任、使旧 grant 失效并确认任务停止。endpoint 的 `trust_set` 持久更新信任后仍保持当前进程不可用，CLI 才激活新配置并要求重启。配置文件与数据库并非一个事务，失败信息会保留恢复线索。

维护流程位于 [maintenance](../crates/orc-installer/src/maintenance.rs)。升级/回退切换程序，安全状态原位保留；离线 MCP 无法证明远端停止，因此不允许该路径。维护记录和停止证据需要一起读，程序链接切换成功不代表整个维护流程成功。

## 注释与可读性约定

- 模块开头使用 `//!` 说明职责、主要调用顺序、信任边界和相关子模块。面向本仓库 reviewer 的说明优先用中文，类型和协议名保留原文。
- 关键类型和函数使用 `///` 写契约：输入来自哪里、调用前提、锁/事务要求、副作用、失败后能否重试。简单访问器不需要逐行复述代码。
- 行内 `//` 说明顺序不能调整的原因，尤其是审批消费、journal/fsync、单次启动标记、锁释放与重新复核、未知状态和部分写入。
- `unsafe` 附近用 `SAFETY` 说明指针/FD 有效性、所有权和线程前提；只写“安全调用”没有 review 价值。
- `tokio::select!` 等宏内分支手工保持多行：每个状态更新、等待、错误返回独立呈现。`cargo fmt` 通过不代表宏内可读性已经合格。
- 修改状态机、锁顺序、持久化顺序或协议语义时，同步更新相邻注释和本指南。不要以注释声称尚无实测证据的保证，也不以注释代替运行时检查。

## 如何验证改动

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

已有测试可按链路定位：domain/protocol 检查权限和信封，auth 检查单次消费与刷新重放，store 检查去重/CAS/journal 恢复，endpoint/MCP 检查任务控制与撤销，workspace 检查基线、排他和部分回写。Linux runner 与 systemd 集成测试需 Linux 环境；macOS 测试通过不能替代 gVisor、资源限制或整组停止的实际验收。

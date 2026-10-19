# 执行后端实施与验证记录

更新：2026-10-18。当前开发宿主为 macOS。Linux 真实运行证据尚缺，不能将跨平台 Rust 单元测试当作 Ubuntu/systemd/gVisor 验收通过。

已实现：独立非 Clone 启动许可、固定规格摘要及 cwd/ELF 身份、一次持久启动标记、systemd 用户单元适配、单线程 FD exec、密封脚本 memfd、有界 stdin/stdout/stderr、独立 deadline、stop-only watchdog、rootless gVisor profile 检查、固定镜像工具解析、停止后独立文本收集器、三类离线输入。

实现偏离：初始 systemd/Docker 控制使用 Rust 的固定 argv 子进程适配器；未使用设计指定的 zbus/Bollard。没有 shell 字符串拼接，控制输出和等待均有预算。这是待迁移的适配层，不代表 M0 已批准此替换。宿主同 UID 代码可越出受管 cgroup 或修改同账户控制状态；停止证据只覆盖记录的实例。

## Linux 发布门槛

在 Ubuntu 24.04 LTS x86_64 非 root 账户及可用 systemd user manager 上运行并保存命令、版本、摘要和实际结果：

1. 正常/非零 ELF argv；空格、变量、管道符保持字面值；argv 拒绝 shebang；脚本文本/文件入口改变被拒绝；显式环境不继承服务秘密；替换 cwd 或程序后启动拒绝。
2. 批准前撤销、批准单次消费、启动返回丢失、runner 崩溃和重启。未知启动不能重新执行。系统中只出现原任务单元。
3. stdout/stderr 合计 8 MiB、有界 stdin、EOF、洪泛；期限、取消、派生进程与 runner 正常退出后的 cgroup 空证据。
4. 杀死 endpoint 后 watchdog 停止原实例；kill watchdog 后 endpoint 不再接收隔离任务。租约/启动 ID/boot ID 不匹配不得停止无关实例。
5. 专用 rootless 引擎、runsc systrap/network=none、固定镜像摘要和普通 workload UID。分别实测 IPv4/IPv6/DNS/宿主/metadata 不可达，CPU/内存、来宾进程/线程、runtime 线程及 tmpfs 硬上限。
6. scratch 必须是记录的独立 tmpfs mount，不把普通磁盘目录当硬配额。rootless UID 映射实际允许受信准备器和收集器工作；不向任务挂载真实项目、控制 socket 或凭据。
7. 杀死全部工作负载后才能启动只读收集器。链接、特殊文件、路径穿越、无效 UTF-8/NUL、超量文件和篡改摘要均拒绝；保留逐项固定对象供后续审批。
8. 两台独立 Linux 与原生 Codex/ChatGPT 客户端走完六种环境/策略组合与三个样例。

隔离配置的 `validation_record` 必须来自以上实际测试，匹配准确的 `engine_version`、`kernel_release`、`runsc_sha256`、`image_digest`、`engine_data_root`、`scratch_mount_id`。必需检查键见 `orc-backend-gvisor` 的 `REQUIRED_CHECKS`；缺任何一项均不开放该环境。没有真实证据时，保持隔离不可用并报告缺项，不能自动转成宿主模式。

## 本机执行的检查

开发机已通过执行相关 crate 的 25 个单元测试，以及 x86_64 Linux target 的全部目标编译检查与严格 clippy。另提供 5 个真正运行 Linux runner 的集成测试、旧 boot 身份恢复测试，以及显式调用真实 systemd user manager 的集成 fixture，均已做 Linux 编译检查，未在当前 macOS 执行。CI 为 systemd fixture 建立普通用户会话，缺 user manager 时失败，不视为跳过后通过。Docker Desktop daemon 当前未运行，因此没有容器运行或 gVisor 运行结果。上述结果不替代本文件的 Linux 发布门槛。

清理恢复增加了定向验证：完整证据绑定原任务、规格摘要、boot ID 和不可变 container ID，并核对本地 runtime 记录；布尔标记、错任务、错容器、非私有文件及链接均拒绝。scratch 删除重复调用成功且不删除相邻任务；容器已清理但任务状态写入竞争失败时，inspect/stop 从完整清理证据恢复已停止状态，原产物仍可查询。

生命周期审阅另修复：启动与独立停止共享跨进程锁，先持久化停止意图再向运行时发停止，停止后的 prepared 实例永不启动；隔离输出实时发送有界帧，强制停止后仅保留完整帧并标记结果不完整；收集器及输出解析支持失败重试。watchdog 不再只扫描最前 1024 个保留目录，租约与停止记录绑定完整实例。host 旧 boot 以已记录 boot 结束为证据收敛，不查询或停止当前同名单元；gVisor 旧 boot 且无完整清理凭据时仍保持 Unknown，需原不可变容器身份核验后的显式恢复，不自动重跑。

# Linux 沙箱选型与验收条件

> **历史参考，不作为实现或选型依据。** 自 2026-10-18 起，以 [PRD v0.4](PRD.md) 和 [当前架构](ARCHITECTURE.md) 为需求与行为契约依据。隔离环境已改为可选；下文的具体运行时、依赖、参数及第三方 provider 范围未重新确认，也不适用于宿主模式；新技术栈尚未选定。

原文更新日期：2026-10-15。历史状态：MVP 架构决策，尚未完成 Linux 运行验证。关联：[归档 MVP](history/MVP-2026-10-15.md)、[归档技术架构](history/ARCHITECTURE-2026-10-15.md)。

首版选择 **Rootless Docker Engine + gVisor runsc / systrap**。以 Ubuntu 24.04 LTS x86_64 为验证基线，每个任务和第三方 MCP provider 使用独立沙箱。原生宿主命令、普通 runc 容器和其他隔离后端均不作为失败时的自动后备。

## 1 选型比较

| 方案 | 隔离机制 | 对个人 Linux 设备的适用性 | 决策 |
| --- | --- | --- | --- |
| bubblewrap / sandbox-runtime | namespace、文件视图、系统调用及网络限制，仍直接共享宿主内核 | 轻量，易运行本机工具；ORC 需定义与验证完整策略 | P2 原生执行研究，不作默认不可信代码后端 |
| Rootless Docker / Podman + 普通 OCI runtime | user namespace、capabilities、seccomp、cgroup 等 | 兼容与运维成熟，但 rootless 本身不隔离应用对宿主内核的系统调用面 | 作为管理层有价值，单独使用不满足本项目选定边界 |
| **Rootless Docker + gVisor** | Sentry 实现应用系统接口，限制对宿主内核的直接交互；结合 rootless 和 cgroup | 无 KVM VPS 也可采用 systrap；代价是兼容性和部分 I/O/系统调用负载开销 | **P0 唯一默认后端** |
| 直接调用 `runsc --rootless` | gVisor 的特定 rootless 启动路径 | 与引擎创建 user namespace 的方式不同，存在生命周期、网络和 cgroup 限制 | 不以最短演示命令代替生产集成 |
| Firecracker microVM | KVM、独立 guest kernel、jailer | 适合需要硬件虚拟化边界的部署；增加 KVM 权限、guest 镜像和运维要求 | P2 独立 profile；普通 VPS 不应被迫开启嵌套虚拟化 |
| Apple container | macOS 上的轻量 Linux VM | Apple Silicon 后端，不能直接作为 Linux 宿主方案 | **macOS P1**，共享产品契约、独立实现 |

bubblewrap 官方说明它是构建沙箱的工具，保护程度取决于调用方制定的策略。[bubblewrap 安全说明](https://github.com/containers/bubblewrap/security)

gVisor 在应用与宿主之间引入用户态系统接口实现；这不是硬件 VM，也不是绝对隔离。systrap 不需要 KVM，但仍需兼容宿主内核与安全配置。[安全模型](https://gvisor.dev/docs/architecture_guide/security/)、[平台选择](https://gvisor.dev/docs/user_guide/platforms/)

Firecracker 的生产部署还涉及 jailer、宿主安全配置和 KVM 设备管理；这些工作不适合同时并入首版。[Firecracker 部署要求](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)

选 Docker Engine 而非同时支持 Docker/Podman，是为了只维护一套实例管理、诊断和验收路径。使用开源 Linux Engine，不要求 Docker Desktop、Docker Hub 登录或商用订阅；固定镜像可来自自托管 registry 或离线导入。没有安装任何依赖，本文件只描述拟采用方案。

## 2 支持基线和安装检查

产品交付目标是一条命令启动安装和初始化：安装器核验固定依赖、配置专用引擎与 runsc 并执行下列探测，用户不必手工拼装运行时。必要系统前置设置集中说明并按需提权，不静默改整机策略；检测失败不降级隔离。安装网络下载与 Agent 直连是不同路径，不因此允许任何任务流量中继。签名失败、重复安装、升级回退和卸载保留用户项目均需验收。

P0 验证 Ubuntu 24.04 LTS x86_64，内核选受维护的 6.8 或更高版本，最终记录精确发行包、安全补丁、Engine、RootlessKit、runsc 和镜像摘要。不把发行版名称当兼容性证明；arm64、其他发行版、WSL2 与嵌套容器另行验证。

| 检查项 | 必须满足 | 失败处理 |
| --- | --- | --- |
| 非 root 执行链 | ORC、专用 dockerd、runsc 运行在宿主普通用户权限下 | 拒绝连接 rootful daemon；不自动加入 docker 组 |
| user namespace | 引擎可建立隔离，subuid/subgid 分配与 UID/GID 映射有效 | 报告缺失条件，不自动关闭系统级安全开关 |
| cgroup | v2 + systemd 驱动；cpu、memory、pids 等所需控制器实际委派 | 不接受忽略资源参数的运行模式 |
| LSM | AppArmor/SELinux 策略允许已批准的 rootless 执行链 | 提供精确诊断；需要管理员调整时给出范围明确的配置，不建议全局禁用 |
| 独立引擎 | 专用 socket、配置、data-root、exec-root 和 systemd 用户单元 | 不修改默认 Docker context，不复用用户现有引擎 |
| 运行时 | 固定 runsc 发行版及摘要，命名 runtime 固定为 systrap、network none | 缺失、配置漂移或启动失败即拒绝任务 |
| 文件系统 | 本地受支持存储；运行目录、快照、日志权限正确 | 不把共享 NFS home 或任意挂载作为首版支持条件 |

Docker rootless 需要预先满足 UID 映射等条件；管理员安装必要组件不等于运行时必须使用宿主 root。[Docker rootless 前置条件](https://docs.docker.com/engine/security/rootless/)

需要使用“引擎先建立 user namespace，再调用 runsc”的集成方式。不要简单把 `--rootless` 加到官方普通 Docker 示例中；gVisor 文档对不同 rootless 启动路径列出了不同限制。[gVisor rootless 模式](https://gvisor.dev/docs/user_guide/rootless/)

资源检查必须读取实际 cgroup 和运行结果。Docker 文档指出，在不满足 cgroup v2/systemd 条件时，rootless 可能忽略相关资源参数。[Docker 资源限制](https://docs.docker.com/engine/security/rootless/tips/#limiting-resources)

不采用在特权容器里运行设备服务或 Docker-in-Docker 的安装捷径。独立 Linux VM 可作为测试宿主，但 Mac 上的 Docker Desktop 测试不能替代目标 Linux 主机验收。

## 3 必须由设备端固定的执行策略

### 3.1 身份和运行时

- 每任务独立容器和 gVisor sandbox，provider 也独立；不跨 grant 共享可写目录、PID/IPC/network namespace 或持续会话。
- 工作负载使用固定非 root UID/GID、清空 capabilities、no-new-privileges。运行时内部为建立隔离所需的 namespace 权限不传给任务。
- 固定 rootfs 镜像摘要与受控 entrypoint；只把任务命令和工作区标识作为数据传入。Agent 不能控制 `runtime`、OCI annotations、挂载、设备、镜像、Dockerfile 或引擎配置。
- 通过宿主侧受信配置、二进制摘要、引擎元数据和运行时实例交叉核验后端。任务返回的 `uname`/`dmesg` 不能证明正在使用 gVisor。[gVisor runtime 核验提示](https://gvisor.dev/docs/user_guide/quick_start/docker/#verify-the-runtime)
- 保留 runsc 自身的宿主 seccomp 防御；不把给 runc 设计的 seccomp JSON 当作 gVisor 沙箱内系统调用策略自动生效的证明。两种运行时的实际限制分别验证。

### 3.2 网络与 IPC

引擎设置独立 `network=none`，专用 runsc runtime 同时设置 `--network=none`；只允许沙箱内部 loopback。不能用禁止 DNS、环境变量或域名黑名单代替网络隔离。[gVisor 关闭外部网络](https://gvisor.dev/docs/user_guide/networking/#disabling-external-networking)

禁止宿主网络、端口发布、网络代理、任意设备、可访问宿主的 socket，以及 Docker、ORC、SSH agent、D-Bus、X11/Wayland 等 IPC。测试 IPv4、IPv6、宿主 loopback、抽象 Unix socket、局域网和云元数据地址。正常 MCP stdio 由受控管道承载，不给 provider 一个可任意调用的宿主管理 API。

镜像拉取和更新发生在用户批准的控制层，不在任务中。P0 不支持在线安装依赖、私有 registry 凭据注入、联网 provider 或任意出站白名单。后续网络 profile 需要独立授权与防绕过测试。

### 3.3 文件和产物

真实工作区先由宿主文件代理复制为获准快照，作为只读 `/input` 提供给沙箱。rootfs 只读；任务在有上限的临时 `/work` 中处理副本，并有独立受限 `/tmp`、`/dev/shm`。不提供用户 home、ORC 状态、引擎目录或宿主可写 bind mount。

产物通过受限流式通道导出，所有文件名、长度、内容摘要和类型均视为不可信；禁止直接把返回 tar 包解压到宿主项目。只接受限量普通文件和已定义的文本修改，拒绝链接、特殊文件、绝对路径与路径穿越。任务完成后先停止其全部工作进程，再完成产物收集；提取期间若不能证明文件稳定，拒绝提交不一致结果。

临时内容在实例销毁后丢弃；远端回写仍走设备审批与基线冲突检查。无网络任务仍可以通过工具输出把获准输入返回云端，这个数据通道必须在授权说明中明确。

### 3.4 资源和拒绝服务

以下为初始产品上限，待 M0 压力测试调整；不是已测性能数据。单设备默认一个活动任务，另有受限 provider 配额，避免无限创建实例。

| 资源 | 初始目标 | 强制执行与验证 |
| --- | --- | --- |
| CPU | 单任务最多 2 个核的 CPU 时间配额 | cgroup v2 cpu 控制器；测量忙循环实际占用 |
| 内存 | 单任务 2 GiB，单独记录 runtime 开销 | cgroup memory 限制覆盖 Sentry、Gofer 等关联进程；测试 swap 和 OOM，不只限制任务声明值 |
| 进程和线程 | 沙箱内任务预算 128，宿主 runtime 线程另设上限 | 非 root 工作负载的硬限制与后端支持需实测；fork/thread 压力是发布门槛 |
| 临时写入 | `/work` 512 MiB、`/tmp` 64 MiB、共享内存 64 MiB | 有容量限制的 tmpfs，并验证实际计入资源预算；不以轮询目录大小冒充硬配额 |
| 输入和产物 | 输入快照 128 MiB；产物总量 64 MiB，另限文件数 | 文件代理在复制前及复制中计数；溢出拒绝，不无限落盘 |
| 时间 | 最长 10 分钟且不超过 grant 剩余有效期 | 宿主单调时钟监督；到期停止整个实例 |
| 输出和日志 | 每任务 stdout/stderr 合计保留 10 MiB | 有界缓冲和读写预算，超过即截断/停止；关闭引擎默认无限日志或配置硬轮转 |

gVisor 内部进程和线程与宿主进程并非一一对应。因此不能把 `--pids-limit=128` 当作“沙箱最多 128 个进程”的证明；必须验证沙箱内限制以及宿主资源限制的组合。[gVisor 资源模型](https://gvisor.dev/docs/architecture_guide/resources/)

还需限制整台设备的任务总数、快照与输出保留空间、排队长度、请求速率和镜像缓存。rootfs 只读不限制引擎日志、产物和宿主缓存；这些路径需各自预算。若选定 runsc 版本无法强制所需临时存储或进程预算，M0 不通过，需明确修改后端或能力范围后再发布。

## 4 权限与故障边界

本地 grant 固定 `linux-gvisor` profile、设备、工作区、客户端和时限。请求不能用 `unsafe=true`、另一个 runtime 或新镜像绕过权限。后端与策略变更使旧执行许可失效，不能静默降级。

专用 rootless 引擎仍是高权限的本用户服务，必须放在可信计算基础中；任何持有其 API socket 的程序都可能操控该用户可访问的资源。只有 ORC 监督器使用它，Skill、任务、provider 和设备网络认证模块不获得 socket。rootless 不防御已经控制宿主同一用户的攻击者。

gVisor 兼容性以实际工具链和 provider 验收。P0 选择固定 Python、Node 和常用文本处理环境，按镜像摘要测试；不承诺 GPU、eBPF、FUSE、内核模块、宿主 systemd 管理或 Docker-in-Docker。失败应返回能力不足，不建议 Agent 自行安装或绕过沙箱。[gVisor 应用兼容性](https://gvisor.dev/docs/user_guide/compatibility/)

## 5 生命周期与无人值守

设备服务、专用引擎和独立 watchdog 由 systemd 用户服务管理。控制端退出 CLI/SSH 与停止服务是不同动作：正常退出管理终端不撤销授权；是否允许登出后继续运行由明确的 lingering 设置决定，默认不替用户启用。

监督器创建实例前持久化任务意图、grant、截止时间和实例标识，创建后记录真实 container ID。自动重启关闭；任务完成、取消、授权到期或撤销都停止整个 sandbox，并确认 runtime、provider 和子进程终止。不能仅杀 `docker run` 客户端或任务父 PID。

独立 watchdog 从沙箱外读取授权和监督器租约：监督器无心跳达到初始 30 秒目标即清理其 ORC 实例。watchdog 不健康时停止接收新任务，监督器主动停止现有任务。启动和恢复时对专用引擎、持久化任务记录与实例所有权做对账，再开放新任务。未登记的 ORC 创建中实例按受信命名和本地创建记录进入隔离清理；不盲信任务可伪造的标签。

租约机制针对监督器等单组件故障，不承诺在内核挂死或整个控制面失效时仍按时清理。引擎不可用导致不能确认终止时记录 `termination_failed/unknown`，明确提示设备所有者，不报告成功。测试包括停止 daemon 后容器是否存活；不能将 daemon 停止直接等同于任务结束。

清理只针对专用引擎内 ORC 拥有的实例，禁止全局 prune、删除用户 Docker 数据目录或停止用户无关容器。重启后不重放写操作，不自动恢复旧进程；用户重新发起任务需重新检查授权。

## 6 M0 验证矩阵

| 验证组 | 场景 | 通过条件 |
| --- | --- | --- |
| 环境 | Ubuntu 工作站与无 KVM 的 VPS；另测不满足 cgroup/userns 条件的环境 | 支持组合可运行；缺失隔离条件的组合拒绝，不修改全局安全开关 |
| 后端身份 | runsc 缺失、配置改成 runc、引擎指向 rootful socket | 拒绝执行，不能凭任务自报运行时通过 |
| 文件 | 测试秘密、home、socket、路径穿越、链接、目录替换竞争 | 未导出文件不可读，真实项目不可直接写，回写冲突不覆盖 |
| 网络 | 公网、DNS、IPv4/IPv6、宿主 loopback、Unix socket、局域网、云元数据 | 除沙箱内部 loopback 与既定 stdio 外均不可达 |
| 资源 | fork/thread、内存、CPU、tmpfs、产物、日志洪泛 | 限制实际生效，宿主保持可管理；资源饱和仍可撤销 |
| 生命周期 | 任务双重 fork、CLI 退出、服务 SIGKILL、watchdog 故障、daemon 故障、宿主重启 | 无静默重跑；单故障按策略清理；无法确认时明确失败 |
| 隔离粒度 | 两个 grant、两个工作区、恶意 provider | 不共享可写目录、凭据或 namespace；不能访问管理 IPC |
| 真实工作负载 | Python/Node 离线任务与固定 filesystem MCP provider | 输出、文件修改、取消、回写审批完整闭环；记录不兼容项 |

性能记录冷启动、热启动、文件读写耗时、宿主内存、取消延迟，先形成实测基线，再决定是否增加 Firecracker 或其他后端。不要为了基准数字而关闭安全控制。

## 7 macOS P1 衔接

Apple container 后端实现同一 `SandboxBackend` 接口，复用 grant、工作区、工具 schema、审批、幂等与审计。系统安装、进程隔离、密钥存储、资源限制和清理方式各自实现。首先验证 Apple Silicon/macOS 26 与 27，再验证 Linux 与 Mac 混合设备访问。

这份 Linux 决策没有为 macOS 提供默认的 gVisor 嵌套运行方案，也不把 Linux 已通过的测试自动标为 macOS 通过。旧 macOS/Intel 的 Lima、Windows WSL2 和其他 Linux 发行版在后续独立验收。

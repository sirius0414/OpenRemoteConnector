# 开发版快速开始

这份指南面向验证当前代码的开发者。目标执行平台为 Ubuntu 24.04 LTS x86_64、普通用户和可用的 systemd 用户管理器。当前尚无公开签名发行包，下面使用源码构建；这不满足 PRD 中终端用户无需 Cargo 的最终安装目标。完整缺口见 [P0 状态](validation/P0-STATUS.md)。

宿主模式允许命令访问执行账户的真实文件和工具。请选用专门的普通测试账户和无秘密的测试目录。工作目录不是文件隔离，管理员授予 MCP 登录也不会自动创建执行 grant。

## 1 构建与初始化

从仓库根目录执行：

```sh
cargo build --locked --release
cargo test --workspace
umask 077
export ORC_ROOT="$HOME/.local/share/orc-dev"
target/release/orc setup --role complete --root "$ORC_ROOT"
mkdir -p "$ORC_ROOT/bin"
install -m 700 target/release/orc target/release/orc-mcp target/release/orc-endpoint target/release/orc-runner target/release/orc-watchdog "$ORC_ROOT/bin/"
```

`setup --role mcp` 和 `--role endpoint` 分别只初始化所选角色；不安装 Docker、runsc、不创建 grant、不启用 linger，也不启动未配置的服务。再次执行保留原身份和配置。源码开发步骤中的 `install` 是明确的本地构建安装；有可信发行包后应改用下述签名校验安装。

```sh
orc install --role complete --root "$ORC_ROOT" --bundle /path/to/release \
  --manifest /path/to/release/release-manifest.json \
  --signature /path/to/release/release-manifest.sig \
  --public-key /path/to/independently-verified-release-public-key.txt
```

签名和公钥文件为 Base64 编码；Ed25519 签名覆盖 manifest 的原始字节。公钥必须从独立可信渠道核对，不能无条件信任包自带的公钥。加 `--verify-only` 只校验，不安装。没有已发布的官方签名或下载地址可供本指南填写。

## 2 为同机验证准备设备 TLS

下面命令是**所有者的安装准备**，不是 Agent 任务。执行端只取得自己的私钥/证书、CA 公钥与固定 MCP 公钥；远程部署时不能把 CA 私钥复制到执行端。以下 localhost 证书仅适合同机验证；远程时把 SAN 和配置改为真实 DNS 名称。

```sh
umask 077
openssl req -x509 -newkey ed25519 -nodes \
  -keyout "$ORC_ROOT/mcp/tls/ca-key.pem" -out "$ORC_ROOT/mcp/tls/ca.pem" \
  -subj '/CN=ORC development device CA' -days 30 \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'

openssl req -new -newkey ed25519 -nodes \
  -keyout "$ORC_ROOT/mcp/tls/server-key.pem" -out "$ORC_ROOT/mcp/tls/server.csr" \
  -subj '/CN=localhost'
cat > "$ORC_ROOT/mcp/tls/server.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EXT
openssl x509 -req -in "$ORC_ROOT/mcp/tls/server.csr" \
  -CA "$ORC_ROOT/mcp/tls/ca.pem" -CAkey "$ORC_ROOT/mcp/tls/ca-key.pem" -CAcreateserial \
  -out "$ORC_ROOT/mcp/tls/server.pem" -days 7 -extfile "$ORC_ROOT/mcp/tls/server.ext"

openssl req -new -newkey ed25519 -nodes \
  -keyout "$ORC_ROOT/endpoint/tls/client-key.pem" -out "$ORC_ROOT/endpoint/tls/client.csr" \
  -subj '/CN=ORC development endpoint'
cat > "$ORC_ROOT/endpoint/tls/client.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EXT
openssl x509 -req -in "$ORC_ROOT/endpoint/tls/client.csr" \
  -CA "$ORC_ROOT/mcp/tls/ca.pem" -CAkey "$ORC_ROOT/mcp/tls/ca-key.pem" -CAcreateserial \
  -out "$ORC_ROOT/endpoint/tls/client.pem" -days 7 -extfile "$ORC_ROOT/endpoint/tls/client.ext"
cp "$ORC_ROOT/mcp/tls/ca.pem" "$ORC_ROOT/endpoint/tls/ca.pem"
```

不关闭证书校验。MCP 设备监听器直接终止 mTLS，不能只在反向代理添加 `X-Device-ID` 冒充设备证书。

## 3 核对并配置身份

这两个命令只输出公钥、身份 ID 和证书摘要，不输出私钥：

```sh
"$ORC_ROOT/bin/orc" identity show --kind mcp --file "$ORC_ROOT/mcp/identity.json" \
  --certificate "$ORC_ROOT/mcp/tls/server.pem"
"$ORC_ROOT/bin/orc" identity show --kind device --file "$ORC_ROOT/endpoint/identity.json" \
  --certificate "$ORC_ROOT/endpoint/tls/client.pem"
```

在私有的 `endpoint/config.json` 中替换以下字段，核对来源为预期 MCP：

- `mcp_id`：第一个命令的 `id`；`mcp_public_key`：对应 `public_key`。
- `mcp_certificate_digest`：第一个命令的 `certificate_digest`。
- 同机保留 `mcp_address: "127.0.0.1:8788"`、`mcp_server_name: "localhost"`。
- `execution_uid` 必须等于当前普通用户的 `id -u`，不能为 0。
- 明确选择 `host_context_id`、`host_profile_id`、`environment`，给该配置设置稳定的 `host_environment_digest`，例如 `host-env-v1`。修改环境必须使用新授权上下文，不能让旧 grant 静默继承。
- 保留 `gvisor: null`，表示尚未配置隔离环境；不会将隔离任务回退到宿主。

完整 JSON 字段已经由 `setup` 生成，不要删除 TLS、runner、状态目录等字段。身份或执行 UID 变化后，旧端侧信任不会被配置文件直接覆盖；必须先处理旧任务、撤销旧权限并重新登记。

## 4 启动独立服务并登记终端

首次验证可在三个独立终端中分别前台启动，便于观察失败原因：

```sh
"$ORC_ROOT/bin/orc-mcp" --config "$ORC_ROOT/mcp/config.json"
```

```sh
"$ORC_ROOT/bin/orc-watchdog" --config "$ORC_ROOT/endpoint/watchdog-config.json"
```

设备登记使用十分钟内有效的一次性签名邀请。以下示例使用 `jq` 组装公开 JSON；文件始终保存在私有目录中。两台机器部署时，通过所有者认可的渠道传递这些文件并独立核对 MCP 指纹，不传递身份私钥。

```sh
umask 077
"$ORC_ROOT/bin/orc" endpoint enrollment-request \
  --identity "$ORC_ROOT/endpoint/identity.json" \
  --certificate "$ORC_ROOT/endpoint/tls/client.pem" > "$ORC_ROOT/enrollment-request.json"
jq '{name:"ubuntu-test",request:.}' "$ORC_ROOT/enrollment-request.json" > "$ORC_ROOT/invite-input.json"
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/mcp/run/admin.sock" mcp invite-device \
  --file "$ORC_ROOT/invite-input.json" > "$ORC_ROOT/invitation.json"
```

核对 invitation 的 `mcp_id`、`mcp_public_key` 与第 3 步独立查看的 MCP 身份完全一致，并检查其中设备 ID、证书摘要与本机相符，再生成设备私钥签名的兑换证明：

```sh
"$ORC_ROOT/bin/orc" endpoint enrollment-proof \
  --identity "$ORC_ROOT/endpoint/identity.json" \
  --invitation "$ORC_ROOT/invitation.json" > "$ORC_ROOT/redemption.json"
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/mcp/run/admin.sock" mcp redeem-device \
  --file "$ORC_ROOT/redemption.json"
"$ORC_ROOT/bin/orc-endpoint" --config "$ORC_ROOT/endpoint/config.json"
```

邀请超时、重复兑换、设备已有登记或签名/身份不符均拒绝。成功后为 `trusted_ungranted`，没有执行权限；证书目前仍由所有者准备，内嵌 CA 自动签发和续签尚未实现。

检查两端：

```sh
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/mcp/run/admin.sock" status
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" endpoint show
"$ORC_ROOT/bin/orc" doctor --root "$ORC_ROOT"
```

`doctor` 是本地配置和前提检查，不会把云端可达性标成已验证。正常验证后，先停止三个前台进程，确认任务已停止，再检查并安装生成的用户服务单元。只复制实际所选角色的单元；以下为 complete 示例：

```sh
mkdir -p "$HOME/.config/systemd/user"
install -m 600 "$ORC_ROOT/systemd/orc-mcp.service" "$ORC_ROOT/systemd/orc-endpoint.service" \
  "$ORC_ROOT/systemd/orc-watchdog.service" "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now orc-watchdog.service orc-mcp.service orc-endpoint.service
```

不要让同一角色的前台进程和 systemd 服务同时使用一份状态。用户退出后的运行行为由系统的用户服务/linger 设置决定；安装器不会代替管理员启用 linger。

## 5 原生 MCP 登录与有限 grant

在客户端原生 MCP 配置中添加 `http://127.0.0.1:8787/mcp` 并开始 OAuth。所有者在 MCP 机器上查看待确认登录，核对客户端、回调地址、资源标识与期限，再批准指定 ID：

```sh
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/mcp/run/admin.sock" mcp auth pending
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/mcp/run/admin.sock" mcp auth approve LOGIN_ID
```

CLI 批准登录不授予设备执行权限。在客户端调用 `orc_connection_status` 获得已认证 `principal_id`，以该稳定 ID 创建服务允许列表和端侧 grant。不要让 Agent 自填其他主体，不把 token 复制到聊天或 Skill。

`service.allow` 只接受扩大设备允许列表；缩小范围会拒绝，须先 `mcp auth revoke CLIENT_ID` 撤销该客户端全部设备权限并确认停止，再用新客户端身份重新授权。已撤销主体不能直接恢复允许列表。

`service-allow.json`：

```json
{"principal_id":"principal_REPLACE","device_ids":["dev_REPLACE"]}
```

```sh
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/mcp/run/admin.sock" mcp allow --file /private/path/service-allow.json
```

`host-grant.json` 示例，ID、UID 与时间需填入当前实际值。`issued_at`/`expires_at` 为 Unix 秒，可用 `date +%s` 查看当前时间；到期必须有限。

```json
{
  "id":"grant-host-review-1",
  "principal_id":"principal_REPLACE",
  "device_id":"dev_REPLACE",
  "execution_uid":1000,
  "actions":["device.discover","task.submit","task.inspect","result.read"],
  "environment":"host",
  "environment_profile_id":"linux-host-v1",
  "environment_digest":"host-env-v1",
  "host_context_id":"host-default",
  "workspace_ids":[],
  "allowed_env":[],
  "policy":{"kind":"review"},
  "revision":1,
  "issued_at":REPLACE_WITH_CURRENT_UNIX_SECONDS,
  "expires_at":REPLACE_WITH_CURRENT_UNIX_SECONDS_PLUS_3600,
  "status":"active"
}
```

上面的时间占位符不是有效 JSON，填写后再提交。初次试验建议逐次确认；只有所有者明确选择时才将策略改为 `{"kind":"automatic"}`。宿主自动执行可直接修改该账户真实文件，不增加差异审批或自动回滚。

```sh
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" grant create --file /private/path/host-grant.json
```

客户端接着调用 `orc_devices_list`，使用稳定 `device_id` 选择目标；`orc_task_submit` 前生成并保存一次提交 ID：

```sh
"$ORC_ROOT/bin/orc" submission-id
```

任务请求示例（同样需要替换身份、目录及期限）：

```json
{
  "submission_id":"REPLACE_WITH_UUIDV7",
  "device_id":"dev_REPLACE",
  "grant_id":"grant-host-review-1",
  "environment_profile_id":"linux-host-v1",
  "context":{"host_context_id":"host-default","cwd":"/home/tester/orc-work"},
  "command":{"kind":"argv","program":"/usr/bin/printf","args":["%s\n","ORC host task"]},
  "limits":{"wall_time_ms":30000,"output_bytes":65536},
  "request_expires_at":REPLACE_WITH_CURRENT_UNIX_SECONDS_PLUS_300
}
```

审批和查询：

```sh
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" approval list
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" approval show APPROVAL_ID
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" approval approve APPROVAL_ID
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" task show TASK_ID
```

Agent 使用 `orc_task_get`、`orc_task_output_read` 查询原任务。提交响应丢失时查询原 `submission_id`，不要更换 ID 重跑未知任务。取消返回请求状态，只有真实停止证据才是完成。

## 6 快照、受管目录和撤销

新建受管工作区通过端侧管理入口登记：

```sh
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" workspace create \
  --path /home/tester/orc-managed --workspace-id workspace-demo
```

导出请求文件内容为 `{"path":"/home/tester/orc-managed","workspace_id":"workspace-demo"}`：

```sh
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" workspace preview --file /private/path/export.json
```

先检查返回文件清单、内容摘要和排除原因；预览内容此时不可由 Agent 读取。决定导出后，在十分钟内批准返回的精确 snapshot ID：

```sh
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" workspace approve SNAPSHOT_ID
```

批准保存预览的不可变对象，源目录之后变化不会改变这次批准。`workspace export --file ...` 是所有者明确立即批准的快捷方式。源文件变化不会更新旧快照。普通项目可以导出，但没有受管写入约定就不能自动应用差异。所有编辑、构建和外部写入都必须遵守同一排他锁约定。所有者可通过持锁的前台编辑器入口修改目录：

```sh
"$ORC_ROOT/bin/orc" workspace edit --path /home/tester/orc-managed -- /usr/bin/vi existing-file.txt
```

命令使用直接 argv，不经 shell；编辑器须以前台方式运行并等待全部写入完成，不可后台化或复用已运行的 GUI 编辑器进程。编辑器运行期间导出和 apply 均拒绝抢锁。绕过该入口的外部写入不属于受管保证。

隔离任务需要独立准备经过实测的 rootless Docker/runsc profile、固定镜像、容量受限 scratch 和对应验证记录。本指南没有可直接运行的已验证隔离镜像，因此不把上述宿主演示算作隔离验收。

```sh
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" grant revoke GRANT_ID
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" endpoint pause
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/mcp/run/admin.sock" mcp auth revoke CLIENT_REGISTRATION_ID
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/mcp/run/admin.sock" mcp auth show CLIENT_REGISTRATION_ID
```

`auth show` 展示逐设备持久撤销送达状态。`delivered` 只表示 endpoint 已持久记录撤销，不证明进程已经停止；必须继续检查该设备任务的 `stop_state`。

暂停/撤销后查询关联任务的 `stop_state`。不要在停止未知时删除状态目录、恢复旧库或卸载运行时。保留 `security-journal.jsonl`。终态且停止已知的任务在创建满 24 小时后清理正文；提交去重和安全事实保留，旧数据库恢复不能使正文重新有效。

### 更换 MCP 信任

更换 MCP 必须先通过旧 endpoint 的本地管理入口撤销信任。这个操作使旧 grant 失效并请求停止关联任务：

```sh
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" endpoint trust revoke
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" task list
```

所有任务均为终态且停止已知后，向新 MCP 完成前述签名邀请/兑换，并独立核对新 MCP 的公开身份和 TLS 证书摘要。准备 mode 0600 的 `new-peer.json`：

```json
{
  "expected_mcp_id":"mcp_REPLACE",
  "expected_mcp_public_key":"REPLACE_WITH_VERIFIED_PUBLIC_KEY",
  "mcp_certificate_digest":"sha256:REPLACE_WITH_VERIFIED_CERTIFICATE_DIGEST",
  "mcp_address":"new-mcp.example:8788",
  "mcp_server_name":"new-mcp.example"
}
```

```sh
"$ORC_ROOT/bin/orc" endpoint trust set --config "$ORC_ROOT/endpoint/config.json" \
  --invitation /private/path/new-invitation.json --peer /private/path/new-peer.json
```

成功后 CLI 原子更新对端配置并要求重启；正在运行的 endpoint 不会直接改连新 MCP。核对新的 CA/TLS 文件，再由所有者显式重启 endpoint，查看状态并恢复，重新创建有限 grant。旧 grant 不会恢复。若配置激活失败，错误会给出私有暂存配置位置；先对照持久信任修复配置，再重启。

## 7 远程与云端

远程 endpoint 只需主动连接可达的 MCP 设备 TLS 入口；配置 `mcp_address`、证书 SAN、`mcp_server_name` 及两端固定身份，不允许跳过证书校验。MCP 设备绑定默认回环，远程部署需要所有者明确调整监听与防火墙。

云端 Agent 需要另一个可达 HTTPS MCP URL 和正确 OAuth 元数据。HTTP 服务本身仅监听回环，应由用户管理的 HTTPS 入口反向代理 `/mcp`、OAuth 路由和 well-known 元数据。公网域名、证书、服务器或其他网络服务由部署者提供并承担费用。浏览器能打开、CLI 本地连通或安装成功，都不证明 ChatGPT 的实际调用路径可用。必须用真实账户完成能力查询和一次获准任务后记录该路径已验证。

## 8 升级、回退与卸载

这组命令面向通过 `orc install` 安装的签名版本目录和已安装的用户服务单元。源码步骤中的普通二进制文件不是版本链接，维护命令会拒绝覆盖；迁移时先停止服务、确认任务全部终态、备份状态，再由所有者移走原二进制并执行签名初装。没有可信签名包时，不把源码复制当作验证发行升级。

签名 manifest 必须声明 `state_schema: 1`，包含版本、Linux x86_64 target、toolchain、Cargo.lock SHA-256，以及所选角色每个文件的名称、大小和 SHA-256。回退仍要求独立可信公钥和签名，安全数据库、撤销 journal、已消费批准不会随程序一起回退。

```sh
"$ORC_ROOT/bin/orc" upgrade --role endpoint --root "$ORC_ROOT" \
  --bundle /trusted/new-release --manifest /trusted/new-release/release-manifest.json \
  --signature /trusted/new-release/release-manifest.sig --public-key /trusted/release-key.txt

"$ORC_ROOT/bin/orc" rollback --role endpoint --root "$ORC_ROOT" \
  --bundle /trusted/previous-release --manifest /trusted/previous-release/release-manifest.json \
  --signature /trusted/previous-release/release-manifest.sig --public-key /trusted/release-key.txt

"$ORC_ROOT/bin/orc" uninstall --role endpoint --root "$ORC_ROOT"
```

升级/回退维护先阻止新任务并查询已连接设备，不会自动取消在途任务。存在活动任务、离线设备无法确认停止、任务状态未知或备份失败时拒绝切换；等任务结束后重试，或由所有者另行显式取消并确认停止。准备成功后记录 SQLite 备份，校验本安装拥有的 systemd 单元，停止服务、切换程序链接并重启。失败时可能保持维护暂停；检查错误和 `$ORC_ROOT/maintenance/` 中的逐阶段记录，不要删除状态来绕过失败。

`--offline` 仅允许 endpoint：必须无法连接服务、取得数据库独占锁且所有任务终态/停止已知。离线升级/回退不操作 systemd，适合所有者已停用服务的情况，完成后仍需自行启动。离线卸载会先持久撤销全部 grant 和端侧信任，再备份并停止、禁用已核对归属的 systemd 服务。MCP 离线无法证明远端任务停止，因此拒绝该模式。

卸载先暂停新工作、持久撤销对应访问并请求停止；停止未知或撤销证据缺失时拒绝移除程序。卸载保留状态目录、安全 journal、备份、发行缓存和用户项目，不自动删除授权历史或项目内容。在线卸载会停止并禁用所选角色的用户服务、移除其程序链接；其余角色保留。完整干净 Ubuntu 的服务切换与相邻版本兼容仍需实机验收。

## 9 存储留存与容量

任务正文和已批准输入快照的默认留存为 24 小时；尚在执行或停止未知的任务继续保护其所引用输入。未引用对象有 24 小时回收宽限期。审计仅存主体/设备/任务 ID、动作、结果和时间，按七天清理，逻辑元数据预算为 128 MiB。

SQLite 和独立安全 journal 各有 256 MiB 硬上限，在 192 MiB 高水位提前拒绝新增任务、grant、审批和一般记录，为撤销、停止状态和恢复记录预留空间。已存在提交的查询/重试仍返回原记录。数据库高水位按已分配页面计算；清理后的空页不会自动收缩文件，容量达到门槛后需要所有者安排离线维护。不得通过删除安全 journal 或恢复旧数据库绕过限制。

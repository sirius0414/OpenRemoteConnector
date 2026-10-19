# Aliyun MCP + NAS 虚拟机 P0 测试环境

更新：2026-10-19（Asia/Shanghai）。本指南配套 `scripts/p0/`，用于源码开发验证，不能替代签名发行安装或完整 P0 验收。脚本使用普通账户、独立状态目录和专用 `orc-p0-*` 用户服务；不创建 grant、不自动批准 OAuth、不伪造 gVisor 验证记录。

## 本次实测结果

| 项目 | 结果 |
| --- | --- |
| Remote Desktop Commander | 已连接；设备 `iZuf66iy38nxlr6i2ileysZ`，插件 0.3.0 |
| Aliyun | Ubuntu 24.04.2 / x86_64；`cloudapp` UID 1001；systemd user manager 为 running |
| 容量 | 检查时约 1.6 GiB 内存、2 GiB swap、29 GiB 可用磁盘；默认单任务、无 debug info 的开发构建 |
| GitHub 源码 | 从 `https://github.com/sirius0414/OpenRemoteConnector.git` 成功匿名克隆到 `/home/cloudapp/orc-p0/source` |
| 测试基线 | 固定 detached commit `7f18065b388fd4473df239b10035cfa980783526`，与开始时本地提交一致；不含任务期间工作区出现的其他未提交修改 |
| 现有代理 | Nginx HTTPS 8443/9443/10443/11443；FRP 17000，反向映射仅监听 Aliyun 回环 |
| NAS SSH | `127.0.0.1:26022` 可达、已有 known_hosts；以当前账户 cloudapp 尝试，返回 `Permission denied (publickey)`；不能据此确认 NAS 的系统或用户名 |
| Rust | 官方安装器下载停滞；1 MiB range 请求在 20 秒后仅收到 316495 字节，另一次完整请求在 45 秒后收到 752223 / 21113232 字节。安装进程已停止，没有完成工具链安装 |
| 管理限制 | Remote Desktop Commander 的 blockedCommands 包含 sudo、用户管理和防火墙命令；未更改这些限制 |
| 已验证 | 10 个部署/测试文件已保存本地并复制到 Aliyun；两处 Shell/Python 语法检查通过；全部脚本 SHA-256 一致；远端 Ubuntu、账户、systemd 前置检查通过 |
| 未验证 | Rust 构建、MCP 服务启动、NAS endpoint 运行、双端登记、真实 Codex OAuth/任务、gVisor 均未通过本次实机验收 |

没有更改现有 Nginx、FRP、账户权限或安全组。最初上传本地源码的请求被自动审批拒绝；随后按所有者建议从公开 GitHub 拉取成功，没有上传被拒的源码包。新增脚本目前是工作区文件，尚未提交或推送；GitHub 上固定的旧提交不含这些脚本。Aliyun 已单独收到这些新增脚本。

## Codex 中安装与连接

Remote Desktop Commander 在当前会话已可用，无需重复安装。在其他设备的 Codex 中，打开 Plugins 插件目录，搜索 Remote Desktop Commander，安装并完成连接；在它的[设备管理页](https://mcp.desktopcommander.app/)按页面指引注册目标 Ubuntu，然后让 Codex 列出在线设备。安装插件与服务器在线是两个步骤。Codex CLI 可通过 `/plugins` 打开插件浏览器。[官方插件安装流程](https://developers.openai.com/learn/developers-codex-plugin)

本项目 OpenRemoteConnector 是待测 MCP；Remote Desktop Commander 用来准备机器。无需为这项测试安装 Aliyun 云资源管理插件，也不需要 OpenAI API Key。

待 HTTPS 入口实际可达后，连接自己的 ORC：

```sh
codex mcp add orc-p0 --url https://47.103.201.186:12443/mcp
codex mcp login orc-p0
codex mcp list
```

该 URL 是本方案的待部署入口，目前尚未启用。CLI 使用原生 HTTP MCP/OAuth；也可以在 Plugins 目录的 `+ → Add custom MCP server` 中填入自己的 HTTPS `/mcp` 地址，选择 OAuth，创建后安装个人插件。不要沿用官方无认证示例的 No authentication。[MCP 配置与 OAuth](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)、[自定义 MCP 插件流程](https://developers.openai.com/plugins/quickstart)

仓库另有 `skills/orc/SKILL.md`，在需要 Agent 工作流指引时安装为本地 skill；它本身不会建立 MCP 连接。测试中仍需所有者在 Aliyun 查看并批准特定 OAuth 登录，之后才分别配置服务允许列表与 endpoint grant。完整流程见 [QUICKSTART](../QUICKSTART.md) 第 5 节。

## 连接拓扑与端口

```text
Codex ── HTTPS :12443 ── Aliyun Nginx ── HTTP 127.0.0.1:18787 ── orc-mcp
NAS endpoint ── mTLS（可经 SSH 转发）─────────────────────────── :18788
Aliyun ── SSH 127.0.0.1:26022 ── 现有 FRP ── NAS 虚拟机 SSH
```

18787 只监听回环。18788 默认也只监听回环；SSH 恢复后，可在 **Aliyun** 前台建立以下反向转发，使 NAS 的回环 18788 到达 Aliyun 的回环 18788：

```sh
# NAS_USER 替换为真实虚拟机账户；先配置其授权密钥并核对 SSH 主机指纹。
ssh -NT -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
  -R 127.0.0.1:18788:127.0.0.1:18788 -p 26022 NAS_USER@127.0.0.1
```

该终端必须保持运行；断开会使设备通道失联。此路径证明的是“FRP + SSH 隧道内的 mTLS”，不能算作原生公网出站或防火墙验收。当前没有可用 NAS 用户名/授权密钥，因此还不能执行此步骤。可以在 NAS 虚拟机控制台安装 Remote Desktop Commander，并在同一账户下注册它，作为另一种管理入口。

如需测试 NAS 直接出站到 Aliyun，则初始化 MCP 时显式配置 `ORC_DEVICE_BIND=0.0.0.0:18788`、真实 DNS 的 `ORC_DEVICE_NAME`、`ORC_DEVICE_ADDRESS=真实DNS:18788`，并由所有者设置安全组/防火墙。证书 SAN 与 server name 必须匹配。不要用 HTTP proxy 或 X-Device-ID 代替设备 mTLS。

## 准备依赖与源码

目标是两台独立 Ubuntu 24.04 x86_64。NAS 宿主本身不必是 Ubuntu；需要的是虚拟机内部满足条件。建议 NAS 使用专门的普通测试账户，宿主任务能访问该账户真实文件。

缺少依赖时，由管理员在相应机器的管理终端运行；Remote Desktop Commander 当前策略不允许执行 sudo：

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config ca-certificates curl git python3 openssl jq dbus-user-session
# 只有希望用户退出后服务继续运行时才启用（TEST_USER 替换为测试账户）：
sudo loginctl enable-linger TEST_USER
sudo systemctl start user@"$(id -u TEST_USER)".service
```

普通账户获取源码；不要在已存在的目录重新 clone：

```sh
mkdir -p "$HOME/orc-p0"
git clone https://github.com/sirius0414/OpenRemoteConnector.git "$HOME/orc-p0/source"
cd "$HOME/orc-p0/source"
git checkout --detach 7f18065b388fd4473df239b10035cfa980783526
# 将本次 scripts/p0 目录放入此源码目录；Aliyun 已有该目录。
bash scripts/p0/bootstrap-user.sh
```

脚本从 `rust-toolchain.toml` 读取固定的 Rust 1.99.1；不降级工具链或修改 Cargo.lock。官方 Rust 下载恢复前应停在此步。若自行选择镜像，先确认来源可信；脚本不偷偷改下载源。安装器和工具链下载分别有 600/900 秒上限。所有后续构建默认 `CARGO_BUILD_JOBS=1`，产物在 `target/p0/debug`，属于开发构建。

## Aliyun：MCP 初始化、反向代理与测试

在源码根目录，以 cloudapp 运行：

```sh
export ORC_ROOT="$HOME/.local/share/orc-p0-mcp"
export ORC_PUBLIC_URL='https://47.103.201.186:12443/mcp'
bash scripts/p0/aliyun-mcp.sh
bash scripts/p0/service.sh mcp start
bash scripts/p0/test-linux.sh mcp
python3 scripts/p0/smoke-mcp.py --public-url "$ORC_PUBLIC_URL" \
  --connect-origin http://127.0.0.1:18787
```

初始化拒绝覆盖已有 root，保护身份、证书和数据库。失败后的目录需先检查；不要删除状态绕过失败。MCP 生成的 CA 私钥仅保留 Aliyun，服务器证书有效期 7 天、测试 CA 30 天。证书续期不是本组脚本的功能。

本地 smoke 即使服务的 public_url 是 HTTPS，也通过显式正确 Host 检查回环 HTTP；检查 OAuth 元数据、no-store、匿名拒绝、无效 token 拒绝、错误 Host 拒绝。成功不代表公网或客户端可用。

在 Aliyun 管理员终端执行新站点安装，使用现有证书文件（先确认其有效期及 IP SAN）：

```sh
sudo env ORC_PUBLIC_HOST=47.103.201.186 ORC_HTTPS_PORT=12443 \
  ORC_HTTPS_CERT=/etc/le-ip-cert/acme/live/aliyun-ip-47.103.201.186/fullchain.pem \
  ORC_HTTPS_KEY=/etc/le-ip-cert/acme/live/aliyun-ip-47.103.201.186/privkey.pem \
  bash /home/cloudapp/orc-p0/source/scripts/p0/install-nginx.sh
```

该脚本只新增 orc-p0 站点，先检查端口，执行 nginx -t 后 reload；配置检查失败则移除本次新文件。公网 12443 的安全组规则仍需所有者配置。设备端口 18788 不经过此 HTTP 站点。反代保留含端口的 Host，关闭 buffering 和 OAuth query access log。

然后从 Codex 所在机器验证 TLS 与公网路径（不用 `-k` 跳过验证）：

```sh
python3 scripts/p0/smoke-mcp.py --public-url https://47.103.201.186:12443/mcp
```

## NAS：终端初始化、证书与登记

在 NAS 虚拟机内、源码根目录，以普通测试账户运行：

```sh
export ORC_ROOT="$HOME/.local/share/orc-p0-endpoint"
bash scripts/p0/bootstrap-user.sh
bash scripts/p0/nas-endpoint.sh
```

只将 `$ORC_ROOT/endpoint/tls/client.csr` 复制到 Aliyun 的私有工作目录；不要复制 endpoint 私钥。在 Aliyun 签发：

```sh
export ORC_ROOT="$HOME/.local/share/orc-p0-mcp"
bash scripts/p0/sign-client.sh /absolute/client.csr /absolute/new-nas-public-bundle
"$ORC_ROOT/bin/orc" identity show --kind mcp --file "$ORC_ROOT/mcp/identity.json" \
  --certificate "$ORC_ROOT/mcp/tls/server.pem"
```

将 bundle 的 client.pem、ca.pem、peer.json 返回 NAS，并与 Aliyun 直接查看的 MCP 公钥/ID/证书摘要独立核对。在 NAS 执行：

```sh
export ORC_ROOT="$HOME/.local/share/orc-p0-endpoint"
bash scripts/p0/configure-endpoint.sh /absolute/verified-public-bundle
```

脚本验证证书链、用途及本机私钥匹配，并生成 enrollment-request.json。接下来在十分钟邀请有效期内完成：

1. 将 NAS 的 enrollment-request.json 放到 Aliyun 私有目录。Aliyun：

   ```sh
   export ORC_ROOT="$HOME/.local/share/orc-p0-mcp"
   umask 077
   jq '{name:"p0-nas",request:.}' /absolute/enrollment-request.json > "$ORC_ROOT/invite-input.json"
   "$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/mcp/run/admin.sock" mcp invite-device \
     --file "$ORC_ROOT/invite-input.json" > "$ORC_ROOT/invitation.json"
   ```

2. 将 invitation.json 返回 NAS，核对其身份/证书与已验证 peer，再生成签名证明：

   ```sh
   export ORC_ROOT="$HOME/.local/share/orc-p0-endpoint"
   "$ORC_ROOT/bin/orc" endpoint enrollment-proof --identity "$ORC_ROOT/endpoint/identity.json" \
     --invitation /absolute/invitation.json > "$ORC_ROOT/redemption.json"
   ```

3. 将 redemption.json 返回 Aliyun，用 MCP 本地管理 socket 兑换：

   ```sh
   export ORC_ROOT="$HOME/.local/share/orc-p0-mcp"
   "$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/mcp/run/admin.sock" mcp redeem-device \
     --file /absolute/redemption.json
   ```

4. 确认设备通道（SSH 转发或直接 mTLS）已就绪，在 NAS 启动并测试：

   ```sh
   export ORC_ROOT="$HOME/.local/share/orc-p0-endpoint"
   bash scripts/p0/service.sh endpoint start
   "$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" endpoint show
   bash scripts/p0/test-linux.sh endpoint
   ```

终端测试包含工作区测试、Linux runner 测试以及显式启用的真实 systemd fixture，后者检查字面参数、派生进程停止和停止后禁止启动。环境缺失报失败，不以跳过算通过。`gvisor: null` 始终保留，因此隔离任务不可用；本指南不宣称完成六组合验收。

## 授权、证据与停止

原生客户端登录成功后，通过 `orc_connection_status` 获得真实 principal；由所有者在两端设置服务 allow 与有期限的 review grant。NAS 配置使用 `host_context_id=p0-nas`、`host_profile_id=p0-host-v1`，环境摘要取实际 config.json，不能照抄 QUICKSTART 的示例值。按 QUICKSTART 提交短时 `/usr/bin/printf` 任务，所有者批准，再查询输出和 stop_state。登录、证书签发、设备登记均不授予执行权。

测试日志位于各自 `$ORC_ROOT/evidence/时间-随机值/`，包含提交、Cargo.lock 摘要、工具链、实际命令输出及 exit-code。exit-code 非 0 或缺失不算成功。继续保存真实客户端测试与跨机器网络结果；两端单元测试通过也不能代替双端任务验收。

查看日志与 MCP 停止：

```sh
journalctl --user -u orc-p0-mcp -n 100 --no-pager
bash scripts/p0/service.sh mcp stop
```

停止 NAS 前，由所有者暂停新任务，处理已有任务并核对终态/停止证据，再停止 endpoint，最后停止 watchdog：

```sh
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" endpoint pause
"$ORC_ROOT/bin/orc" --socket "$ORC_ROOT/endpoint/run/admin.sock" task list
# 全部任务终态且停止已知后才执行：
systemctl --user stop orc-p0-endpoint.service
systemctl --user stop orc-p0-watchdog.service
```

保留数据库、安全 journal 和证据目录，不用删除状态处理未知任务。专用服务名是实验环境约定；这些源码复制产物不属于签名发行升级/卸载验收。

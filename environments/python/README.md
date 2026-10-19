# 离线 Python 环境

此目录提供镜像构建入口，不提供未经验证的镜像摘要。所有者在准备阶段选择固定 `linux/amd64` Python 基础镜像（必须带 `@sha256:…`），把同版本 Linux `orc-runner` 放入构建上下文后构建。记录最终镜像 RepoDigest、Python 版本及实际程序的规范绝对 ELF 路径（解析 symlink 后）与 SHA-256，写入隔离配置的 `image`、`image_digest`、`tools`。

任务不运行包管理器、不下载镜像或依赖。三个样例只需 Python 标准库。镜像或工具缺失时，终端返回能力缺失，不能切换到宿主执行。

隔离环境启用前必须完成 `docs/validation/EXECUTION.md` 的 Linux 检查，保存与当前 runsc 摘要、镜像摘要、专用引擎 data-root 和 scratch mount ID 一致的验证记录。不能手工把未验证检查标为通过。rootless 映射后的 UID 必须能写入独立 tmpfs scratch 池；受信准备器以该 UID 为每个任务建立副本。批准输入只读挂载到 `/input`，任务副本写入 `/work`。

镜像内包含的 runner 和 glibc 必须兼容；本机 macOS 构建产物不能用于 Linux 镜像。

//! endpoint、执行后端、runner 和 watchdog 共用的执行契约。
//!
//! `ExecutionSpec` 是输入，`ResolvedSpec` 固定入口身份，`InstanceRef` 标识实际运行实例。
//! 生命周期为 probe → prepare → start → inspect/stop → cleanup；prepare 可以创建等待实例，
//! 只有 start 消费 `LaunchPermit` 后才放行用户命令。调用方负责事先持久化授权和启动尝试。
//! 进程内 permit、跨进程控制锁和磁盘上的单次标记分别处理复用、并发停止和崩溃重放。
//! 控制命令失败可能已产生外部副作用，必须保留 Unknown 并核实原实例。

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::io::AsyncReadExt;

pub const MAX_STDIN: usize = 64 * 1024;
pub const MAX_SCRIPT: usize = 64 * 1024;
pub const MAX_OUTPUT: u64 = 8 * 1024 * 1024;
pub const MAX_SPEC: u64 = 256 * 1024;

#[derive(Error, Debug)]
pub enum BackendError {
    #[error("BACKEND_UNAVAILABLE: {0}")]
    Unavailable(String),
    #[error("CAPABILITY_MISSING: {0}")]
    CapabilityMissing(String),
    #[error("INVALID_REQUEST: {0}")]
    Invalid(String),
    #[error("ENTRY_CHANGED: {0}")]
    EntryChanged(String),
    #[error("LAUNCH_ALREADY_ATTEMPTED")]
    AlreadyAttempted,
    #[error("DEADLINE_EXCEEDED")]
    Deadline,
    #[error("SIDE_EFFECT_UNKNOWN: {0}")]
    Unknown(String),
    #[error("IO_ERROR: {0}")]
    Io(#[from] std::io::Error),
    #[error("INVALID_DATA: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionCommand {
    Argv {
        program: String,
        args: Vec<String>,
    },
    Script {
        interpreter: String,
        #[serde(default)]
        interpreter_args: Vec<String>,
        source: String,
        #[serde(default)]
        source_path: Option<PathBuf>,
        args: Vec<String>,
    },
}
/// 已选定 UID、cwd、显式环境和预算的执行输入；不从服务进程继承用户环境。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSpec {
    pub task_id: String,
    pub execution_uid: u32,
    pub command: ExecutionCommand,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub stdin: Vec<u8>,
    pub deadline_unix_ms: u64,
    pub output_limit_bytes: u64,
}
impl ExecutionSpec {
    pub fn validate(&self, now_ms: u64) -> Result<(), BackendError> {
        if self.task_id.is_empty()
            || self.task_id.len() > 128
            || !self
                .task_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(BackendError::Invalid("invalid task ID".into()));
        }
        if self.execution_uid == 0 {
            return Err(BackendError::Invalid(
                "execution UID must be non-root".into(),
            ));
        }
        if !self.cwd.is_absolute() {
            return Err(BackendError::Invalid("cwd must be absolute".into()));
        }
        if self.deadline_unix_ms <= now_ms || self.deadline_unix_ms - now_ms > 600_000 {
            return Err(BackendError::Deadline);
        }
        if self.stdin.len() > MAX_STDIN
            || self.output_limit_bytes == 0
            || self.output_limit_bytes > MAX_OUTPUT
        {
            return Err(BackendError::Invalid("input/output budget exceeded".into()));
        }
        let (program, args) = match &self.command {
            ExecutionCommand::Argv { program, args } => (program, args),
            ExecutionCommand::Script {
                interpreter,
                source,
                args,
                interpreter_args,
                source_path,
            } => {
                if source_path.as_ref().is_some_and(|p| !p.is_absolute())
                    || interpreter_args.iter().any(|a| a.contains('\0'))
                    || interpreter_args.iter().map(String::len).sum::<usize>() > 32 * 1024
                {
                    return Err(BackendError::Invalid(
                        "invalid interpreter arguments or script path".into(),
                    ));
                }
                if source.len() > MAX_SCRIPT || source.contains('\0') {
                    return Err(BackendError::Invalid("script size or encoding".into()));
                }
                (interpreter, args)
            }
        };
        if program.is_empty()
            || program.contains('\0')
            || args.iter().any(|a| a.contains('\0'))
            || args.iter().map(String::len).sum::<usize>() + program.len() > 32 * 1024
        {
            return Err(BackendError::Invalid("invalid program or arguments".into()));
        }
        if self.env.len() > 128
            || self
                .env
                .iter()
                .any(|(k, v)| k.is_empty() || k.contains(['=', '\0']) || v.contains('\0'))
            || self
                .env
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
                > 32 * 1024
        {
            return Err(BackendError::Invalid("invalid environment".into()));
        }
        Ok(())
    }
}

/// 已打开 ELF 入口的路径、文件身份和内容摘要；runner 在执行前再次比较。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EntryIdentity {
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub modified_ns: u128,
    pub sha256: String,
}
/// 供审批与启动绑定的有效执行规格，包含解析后的入口、cwd 身份和环境摘要。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSpec {
    pub spec: ExecutionSpec,
    pub entry: EntryIdentity,
    pub cwd_device: u64,
    pub cwd_inode: u64,
    #[serde(default)]
    pub environment_digest: Option<String>,
    pub digest: String,
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

/// 从当前文件游标读取完整 ELF 并取摘要，调用方应传入刚打开、游标为零的文件。
/// 读取前后核对元数据；仅解释器入口走 ELF 校验，脚本字节单独冻结。
pub fn inspect_entry_file(
    file: &mut fs::File,
    path: PathBuf,
) -> Result<EntryIdentity, BackendError> {
    let before = file.metadata()?;
    if !before.is_file() || before.len() > 512 * 1024 * 1024 {
        return Err(BackendError::Invalid(
            "entry must be a bounded regular ELF file".into(),
        ));
    }
    let mut magic = [0; 4];
    file.read_exact(&mut magic)?;
    if magic != *b"\x7fELF" {
        return Err(BackendError::Invalid(
            "argv/interpreter requires ELF; use explicit script form for scripts".into(),
        ));
    }
    let mut hash = Sha256::new();
    hash.update(magic);
    let mut buf = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    let after = file.metadata()?;
    let modified_ns = before
        .modified()?
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    if before.len() != after.len() || before.modified()? != after.modified()? {
        return Err(BackendError::EntryChanged(
            "entry changed during hashing".into(),
        ));
    }
    #[cfg(unix)]
    let (device, inode) = {
        use std::os::unix::fs::MetadataExt;
        (before.dev(), before.ino())
    };
    #[cfg(not(unix))]
    let (device, inode) = (0, 0);
    Ok(EntryIdentity {
        path,
        device,
        inode,
        bytes: before.len(),
        modified_ns,
        sha256: format!("{:x}", hash.finalize()),
    })
}
/// 按规格内的 PATH 解析宿主程序，固定入口与 cwd 身份并计算有效摘要。
pub fn resolve_spec(mut spec: ExecutionSpec) -> Result<ResolvedSpec, BackendError> {
    spec.validate(unix_ms())?;
    let program = match &spec.command {
        ExecutionCommand::Argv { program, .. } => program,
        ExecutionCommand::Script { interpreter, .. } => interpreter,
    };
    let candidate = if program.contains('/') {
        if Path::new(program).is_absolute() {
            PathBuf::from(program)
        } else {
            spec.cwd.join(program)
        }
    } else {
        let search = spec
            .env
            .get("PATH")
            .map(String::as_str)
            .unwrap_or("/usr/local/bin:/usr/bin:/bin");
        let candidates: Vec<_> = search
            .split(':')
            .filter(|p| Path::new(p).is_absolute())
            .map(|p| Path::new(p).join(program))
            .filter(|p| p.is_file())
            .collect();
        candidates.into_iter().next().ok_or_else(|| {
            BackendError::Invalid("program does not exist in the configured PATH".into())
        })?
    };
    let path = fs::canonicalize(candidate)?;
    let mut file = fs::File::open(&path)?;
    let entry = inspect_entry_file(&mut file, path)?;
    spec.cwd = fs::canonicalize(&spec.cwd)?;
    let cwd_metadata = fs::metadata(&spec.cwd)?;
    if !cwd_metadata.is_dir() {
        return Err(BackendError::Invalid("cwd is not a directory".into()));
    }
    #[cfg(unix)]
    let (cwd_device, cwd_inode) = {
        use std::os::unix::fs::MetadataExt;
        (cwd_metadata.dev(), cwd_metadata.ino())
    };
    #[cfg(not(unix))]
    let (cwd_device, cwd_inode) = (0, 0);
    let digest = sha256(&serde_json::to_vec(&(
        &spec,
        &entry,
        cwd_device,
        cwd_inode,
        Option::<String>::None,
    ))?);
    Ok(ResolvedSpec {
        spec,
        entry,
        cwd_device,
        cwd_inode,
        environment_digest: None,
        digest,
    })
}
impl ResolvedSpec {
    pub fn validate_digest(&self) -> Result<(), BackendError> {
        if sha256(&serde_json::to_vec(&(
            &self.spec,
            &self.entry,
            self.cwd_device,
            self.cwd_inode,
            &self.environment_digest,
        ))?) != self.digest
        {
            return Err(BackendError::Invalid(
                "resolved specification digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    Enforced,
    BestEffort,
    Unsupported,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capabilities {
    pub available: bool,
    pub platform: String,
    pub limits: BTreeMap<String, Enforcement>,
    pub checked_at_ms: u64,
    pub evidence: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    HostLinux,
    Gvisor,
}
/// 持久运行实例身份，供 endpoint 重启恢复及独立 watchdog 使用。
/// invocation_id 绑定实际 systemd 调用或不可变容器 ID，不能仅凭运行时名称停止任务。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstanceRef {
    pub task_id: String,
    pub backend: BackendKind,
    pub runtime_id: String,
    /// 原宿主启动周期；系统重启后不能按同名服务去停止新的实例。
    pub boot_id: String,
    /// prepare 早期可为空，随后固定为 systemd InvocationID 或不可变容器 ID。
    pub invocation_id: String,
    #[serde(default)]
    pub cgroup_path: String,
    pub directory: PathBuf,
    pub spec_digest: String,
    pub deadline_unix_ms: u64,
}
pub struct PreparedInstance {
    pub resolved: ResolvedSpec,
    pub instance: InstanceRef,
}
/// 一次启动的进程内许可，按值消费且不可 Clone；跨重启防重放还依赖持久标记。
pub struct LaunchPermit {
    task_id: String,
    digest: String,
}
impl LaunchPermit {
    /// 仅由 endpoint 的串行授权调度器调用：先持久消费审批（如需），再持久记录启动尝试。
    /// 两次写入不是一个跨后端事务；中途崩溃只能核实/停止，不能自动重跑。
    /// 所有权阻止进程内复用，后端的持久启动标记阻止崩溃后重放。
    pub fn after_durable_authorization(task_id: String, digest: String) -> Self {
        Self { task_id, digest }
    }
    pub fn consume(self, prepared: &PreparedInstance) -> Result<(), BackendError> {
        if self.task_id != prepared.instance.task_id || self.digest != prepared.resolved.digest {
            return Err(BackendError::Invalid(
                "launch permit does not match prepared instance".into(),
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    Waiting,
    Running,
    Exited,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeEvidence {
    pub state: RuntimeState,
    pub exit_code: Option<i32>,
    pub checked_at_ms: u64,
    pub detail: String,
}
/// 停止核实结果；confirmed=false 必须保留实例继续核对，不能上报完成或直接清理。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StopEvidence {
    pub confirmed: bool,
    pub checked_at_ms: u64,
    pub detail: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Cancelled,
    Deadline,
    GrantRevoked,
    GrantExpired,
    ControlLost,
    EndpointPaused,
    SupervisorLost,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StopIntent {
    instance: InstanceRef,
    reason: StopReason,
    requested_at_ms: u64,
}

/// Serializes the launch gate with stop requests from other processes. A stop
/// intent is durable before contacting the runtime, so even an ambiguous stop
/// permanently prevents a prepared instance from subsequently being launched.
#[must_use = "hold this guard throughout the runtime control operation"]
pub struct InstanceControl {
    _file: fs::File,
    instance: InstanceRef,
}
impl Drop for InstanceControl {
    fn drop(&mut self) {
        // A concurrent process spawn can temporarily inherit this descriptor
        // until exec closes it. Explicit unlock releases our completed operation
        // immediately even during that fork/exec window.
        let _ = self._file.unlock();
    }
}
impl InstanceControl {
    pub fn lock(instance: &InstanceRef) -> Result<Self, BackendError> {
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(instance.directory.join("control.lock"))?;
        if !file.metadata()?.is_file() {
            return Err(BackendError::Invalid("invalid runtime control lock".into()));
        }
        // Never block the endpoint or watchdog's async executor behind another
        // control command. The caller retains unknown state and retries stop.
        file.try_lock().map_err(|_| {
            BackendError::Unknown("another runtime control operation is in progress".into())
        })?;
        Ok(Self {
            _file: file,
            instance: instance.clone(),
        })
    }
    pub fn ensure_launch_allowed(&self) -> Result<(), BackendError> {
        for name in ["stop-intent.json", "watchdog-stop.json", "cleanup.json"] {
            match fs::symlink_metadata(self.instance.directory.join(name)) {
                Ok(_) => {
                    return Err(BackendError::Unknown(
                        "instance has a permanent stop intent; launch is forbidden".into(),
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
    pub fn request_stop(&self, reason: StopReason) -> Result<(), BackendError> {
        let path = self.instance.directory.join("stop-intent.json");
        let intent = StopIntent {
            instance: self.instance.clone(),
            reason,
            requested_at_ms: unix_ms(),
        };
        match write_new_json(&path, &intent) {
            Ok(()) => Ok(()),
            Err(BackendError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let old: StopIntent = read_json(&path, MAX_SPEC)?;
                let a = &old.instance;
                let b = &self.instance;
                if a.task_id != b.task_id
                    || a.backend != b.backend
                    || a.runtime_id != b.runtime_id
                    || a.boot_id != b.boot_id
                    || a.directory != b.directory
                    || a.spec_digest != b.spec_digest
                    || a.deadline_unix_ms != b.deadline_unix_ms
                    || (!a.invocation_id.is_empty()
                        && !b.invocation_id.is_empty()
                        && a.invocation_id != b.invocation_id)
                {
                    return Err(BackendError::Invalid(
                        "stop intent identity mismatch".into(),
                    ));
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunnerResult {
    pub exit_code: Option<i32>,
    pub reason: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub output_truncated: bool,
    pub finished_at_ms: u64,
}

#[cfg(test)]
mod instance_control_tests {
    use super::*;
    fn instance(directory: &Path) -> InstanceRef {
        InstanceRef {
            task_id: "task-stop-race".into(),
            backend: BackendKind::Gvisor,
            runtime_id: "original-runtime-name".into(),
            boot_id: "original-boot".into(),
            invocation_id: String::new(),
            cgroup_path: String::new(),
            directory: directory.to_owned(),
            spec_digest: "approved-spec".into(),
            deadline_unix_ms: unix_ms() + 10000,
        }
    }
    #[test]
    fn concurrent_runtime_control_is_exclusive_and_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let instance = instance(dir.path());
        let launch = InstanceControl::lock(&instance).unwrap();
        launch.ensure_launch_allowed().unwrap();
        assert!(InstanceControl::lock(&instance).is_err());
        drop(launch);
        let _unlocked = InstanceControl::lock(&instance).unwrap();
    }
    #[test]
    fn stop_before_launch_remains_forbidden_after_recovery_and_identity_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let mut instance = instance(dir.path());
        {
            let stop = InstanceControl::lock(&instance).unwrap();
            stop.request_stop(StopReason::SupervisorLost).unwrap();
        }
        instance.invocation_id = "resolved-original-container".into();
        let resumed = InstanceControl::lock(&instance).unwrap();
        assert!(resumed.ensure_launch_allowed().is_err());
        resumed.request_stop(StopReason::Cancelled).unwrap();
        drop(resumed);
        instance.spec_digest = "different-spec".into();
        let other = InstanceControl::lock(&instance).unwrap();
        assert!(other.request_stop(StopReason::Cancelled).is_err());
        assert!(other.ensure_launch_allowed().is_err());
    }
}

/// 后端只实现生命周期，不自行推导授权；Unknown 错误要求查询/停止原实例。
#[async_trait]
pub trait ExecutionBackend: Send + Sync {
    async fn probe(&self) -> Result<Capabilities, BackendError>;
    /// 准备等待中的实例并先记录身份；可以产生控制面副作用，但不能运行用户入口。
    async fn prepare(&self, spec: ResolvedSpec) -> Result<PreparedInstance, BackendError>;
    /// 消费绑定本实例的许可并尝试一次启动；响应丢失时不得再次调用以重跑任务。
    async fn start(
        &self,
        prepared: PreparedInstance,
        permit: LaunchPermit,
    ) -> Result<InstanceRef, BackendError>;
    async fn inspect(&self, instance: &InstanceRef) -> Result<RuntimeEvidence, BackendError>;
    /// 先永久记录停止意图，再操作运行时；返回值必须区分发出请求和核实成功。
    async fn stop(
        &self,
        instance: &InstanceRef,
        reason: StopReason,
    ) -> Result<StopEvidence, BackendError>;
    async fn cleanup(&self, instance: &InstanceRef) -> Result<(), BackendError>;
}

pub fn private_dir(path: &Path) -> Result<(), BackendError> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.is_dir() || metadata.file_type().is_symlink())
    {
        return Err(BackendError::Invalid(
            "state directory cannot be a symlink or file".into(),
        ));
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(BackendError::Invalid(
            "state directory cannot be a symlink".into(),
        ));
    }
    Ok(())
}
/// 以 create_new 加文件/目录 fsync 写入不可覆盖标记；AlreadyExists 是防重放信号。
pub fn write_new_json<T: Serialize>(path: &Path, value: &T) -> Result<(), BackendError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}
pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, limit: u64) -> Result<T, BackendError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(BackendError::Invalid("invalid bounded state file".into()));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(BackendError::Invalid("state file grew over budget".into()));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Bounded control-command execution. Never use this for user commands; they
/// belong to an independently supervised backend instance.
pub async fn control_command(
    program: &str,
    args: &[String],
    timeout_secs: u64,
) -> Result<String, BackendError> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| BackendError::Unknown("missing control stdout".into()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| BackendError::Unknown("missing control stderr".into()))?;
    let out_task = tokio::spawn(async move {
        let mut b = Vec::new();
        (&mut stdout)
            .take(1024 * 1024 + 1)
            .read_to_end(&mut b)
            .await
            .map(|_| b)
    });
    let err_task = tokio::spawn(async move {
        let mut b = Vec::new();
        (&mut stderr)
            .take(64 * 1024 + 1)
            .read_to_end(&mut b)
            .await
            .map(|_| b)
    });
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), child.wait()).await;
    let status = match result {
        Ok(status) => status?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            out_task.abort();
            err_task.abort();
            return Err(BackendError::Unknown("control command timed out".into()));
        }
    };
    let output = out_task
        .await
        .map_err(|_| BackendError::Unknown("stdout reader failed".into()))??;
    let errors = err_task
        .await
        .map_err(|_| BackendError::Unknown("stderr reader failed".into()))??;
    if output.len() > 1024 * 1024 || errors.len() > 64 * 1024 {
        return Err(BackendError::Unknown(
            "control command response over budget".into(),
        ));
    }
    if !status.success() {
        return Err(BackendError::Unavailable(format!(
            "{} returned {}",
            program, status
        )));
    }
    String::from_utf8(output)
        .map_err(|_| BackendError::Unknown("control command returned non-UTF8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn spec() -> ExecutionSpec {
        ExecutionSpec {
            task_id: "task-1".into(),
            execution_uid: 1000,
            command: ExecutionCommand::Argv {
                program: "echo".into(),
                args: vec!["$HOME | cat".into()],
            },
            cwd: "/tmp".into(),
            env: BTreeMap::new(),
            stdin: vec![],
            deadline_unix_ms: unix_ms() + 10000,
            output_limit_bytes: 1024,
        }
    }
    #[test]
    fn validation_is_literal_and_bounded() {
        let mut s = spec();
        assert!(s.validate(unix_ms()).is_ok());
        s.stdin = vec![0; MAX_STDIN + 1];
        assert!(s.validate(unix_ms()).is_err());
        s = spec();
        s.execution_uid = 0;
        assert!(s.validate(unix_ms()).is_err());
        s = spec();
        s.task_id = "../other".into();
        assert!(s.validate(unix_ms()).is_err());
    }
    #[test]
    fn command_unknown_fields_rejected() {
        assert!(
            serde_json::from_str::<ExecutionCommand>(
                r#"{"kind":"argv","program":"id","args":[],"shell":true}"#
            )
            .is_err()
        );
    }
    #[test]
    fn scripts_cannot_enter_argv_path() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("script");
        fs::write(&p, b"#!/bin/sh\necho unsafe").unwrap();
        let mut f = fs::File::open(&p).unwrap();
        assert!(inspect_entry_file(&mut f, p).is_err());
    }
    #[test]
    fn create_new_gate_is_not_replayed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("gate");
        write_new_json(&p, &"approved").unwrap();
        assert!(write_new_json(&p, &"approved").is_err());
    }
    #[tokio::test]
    async fn control_command_has_a_deadline() {
        let args = vec!["2".into()];
        assert!(control_command("/bin/sleep", &args, 0).await.is_err());
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRequest {
    pub spec: ExecutionSpec,
    pub expected_entry_sha256: String,
    pub expected_entry_path: PathBuf,
    pub image_digest: String,
    pub guest_process_limit: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorLease {
    pub instance: InstanceRef,
    pub updated_at_ms: u64,
}
/// Atomic owner heartbeat; an endpoint reboot does not renew an old instance.
pub fn refresh_lease(instance: &InstanceRef) -> Result<(), BackendError> {
    let temporary = instance
        .directory
        .join(format!("lease-{}.tmp", uuid::Uuid::now_v7()));
    write_new_json(
        &temporary,
        &SupervisorLease {
            instance: instance.clone(),
            updated_at_ms: unix_ms(),
        },
    )?;
    fs::rename(&temporary, instance.directory.join("lease.json"))?;
    fs::File::open(&instance.directory)?.sync_all()?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactFrame {
    File {
        path: String,
        bytes: u64,
        sha256: String,
    },
    Chunk {
        bytes: Vec<u8>,
    },
    End,
    Done,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollectedArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub local_path: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutputFrame {
    Chunk { stream: String, bytes: Vec<u8> },
    Complete { result: RunnerResult },
}

pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), BackendError> {
    let parent = path
        .parent()
        .ok_or_else(|| BackendError::Invalid("state file requires parent".into()))?;
    let temporary = parent.join(format!(".state-{}.tmp", uuid::Uuid::now_v7()));
    write_new_json(&temporary, value)?;
    fs::rename(temporary, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Remove one stopped task's copy in an owner-selected scratch pool. The caller
/// must have verified whole-instance termination before invoking this function.
/// Missing task directories are successful retries; links never widen the scope.
pub fn remove_stopped_task_scratch(root: &Path, task_id: &str) -> Result<(), BackendError> {
    if task_id.is_empty()
        || task_id.len() > 128
        || !task_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(BackendError::Invalid("invalid scratch task ID".into()));
    }
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(BackendError::Invalid(
            "scratch pool must be a directory, not a link".into(),
        ));
    }
    let task = root.join(task_id);
    match fs::symlink_metadata(&task) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(&task)?
        }
        Ok(_) => {
            return Err(BackendError::Invalid(
                "unexpected scratch task object type".into(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::File::open(root)?.sync_all()?;
    Ok(())
}
#[cfg(test)]
mod scratch_cleanup_tests {
    use super::*;
    #[test]
    fn cleanup_retries_and_never_removes_neighbor_tasks() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("task-a")).unwrap();
        fs::write(root.path().join("task-a/file"), b"result").unwrap();
        fs::create_dir(root.path().join("task-b")).unwrap();
        remove_stopped_task_scratch(root.path(), "task-a").unwrap();
        remove_stopped_task_scratch(root.path(), "task-a").unwrap();
        assert!(root.path().join("task-b").exists());
        assert!(remove_stopped_task_scratch(root.path(), "../task-b").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn links_cannot_expand_cleanup_scope() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"private").unwrap();
        symlink(outside.path(), root.path().join("task-link")).unwrap();
        assert!(remove_stopped_task_scratch(root.path(), "task-link").is_err());
        fs::create_dir(root.path().join("task-a")).unwrap();
        symlink(outside.path(), root.path().join("task-a/child-link")).unwrap();
        remove_stopped_task_scratch(root.path(), "task-a").unwrap();
        assert!(outside.path().join("keep").exists());
    }
}

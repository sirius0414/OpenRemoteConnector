//! 终端的最终授权边界：接受任务、推进生命周期、提供结果和本地管理。
//!
//! 远程调用链为 session → invoke → submit/resolve → Store；submit 只持久化接受，
//! 独立 supervise/tick 循环负责审批消费、准备实例、最终复核和启动。
//! 人工 review 优先看 submit 的去重顺序、tick 的启动关口以及 apply_changes 的逐文件授权。
//! `gate` 串行协调本地权限变化与启动/回写；`body_lock` 协调正文引用建立和留存清理。
//! 重启后不重跑旧任务，停止请求必须等后端证据确认。信任更换与正文清理见子模块。

use orc_backend_gvisor::{GvisorBackend, GvisorConfig};
use orc_backend_host_linux::{HostBackend, HostConfig};
use orc_domain::*;
use orc_execution::{
    ExecutionBackend, ExecutionCommand, ExecutionSpec, InstanceRef, LaunchPermit, ResolvedSpec,
    RuntimeState, StopReason,
};
use orc_store::{Store, StoredApproval, StoredGrant, StoredTask, SubmissionKey, SubmissionRecord};
use orc_transport::{AnyError, Frame, IdentityFile, TlsFiles, now};
use orc_workspace::{ObjectStore, Snapshot};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub state_dir: PathBuf,
    pub admin_socket: PathBuf,
    pub identity_file: PathBuf,
    pub mcp_address: String,
    pub mcp_server_name: String,
    pub mcp_id: String,
    pub mcp_public_key: String,
    pub mcp_certificate_digest: String,
    pub tls: TlsFiles,
    pub execution_uid: u32,
    pub runner_path: PathBuf,
    pub host_context_id: String,
    pub host_profile_id: String,
    pub host_environment_digest: String,
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub gvisor: Option<GvisorConfig>,
    #[serde(default)]
    pub continue_on_disconnect: bool,
}
/// 接受时固定的请求、授权版本和解析规格；load_body 另合并可恢复的运行实例引用。
#[derive(Clone, Serialize, Deserialize)]
struct TaskBody {
    request: TaskRequest,
    principal: Principal,
    resolved: ResolvedSpec,
    grant_revision: u64,
    policy_revision: u64,
    approval_id: Option<String>,
    instance: Option<InstanceRef>,
    isolated: Option<GvisorConfig>,
}
#[derive(Clone)]
pub struct Endpoint {
    pub config: Config,
    pub store: Store,
    pub device_id: String,
    identity: IdentityFile,
    // 保护本地权限变化与启动/逐文件回写关口；慢速 prepare 在释放锁后执行。
    gate: Arc<Mutex<()>>,
    // 保护正文引用建立与 GC；同时需要两把锁时遵循 body_lock → gate。
    body_lock: Arc<Mutex<()>>,
    paused: Arc<std::sync::atomic::AtomicBool>,
    connected: Arc<std::sync::atomic::AtomicBool>,
    objects: ObjectStore,
    maintenance: Arc<std::sync::atomic::AtomicBool>,
    trust_revoked: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    test_backend: Option<Arc<dyn ExecutionBackend>>,
}
fn field<'a>(v: &'a Value, k: &str) -> std::result::Result<&'a str, AnyError> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {k}").into())
}
fn val<T: Serialize>(v: T) -> std::result::Result<Value, AnyError> {
    Ok(serde_json::to_value(v)?)
}
impl Endpoint {
    /// 校验本地 UID 和既有信任，加载持久状态，并将遗留任务转为待核实或未启动终态。
    /// 重启不会重新调度旧 accepted/starting 任务，避免未知副作用被重复执行。
    pub async fn open(config: Config) -> std::result::Result<Self, AnyError> {
        if config.execution_uid == 0 || config.execution_uid != orc_admin::current_uid() {
            return Err("EXECUTION_UID_MISMATCH".into());
        }
        if config
            .gvisor
            .as_ref()
            .is_some_and(|g| g.state_dir != config.state_dir.join("tasks"))
        {
            return Err(
                "gVisor and host must share the watchdog-owned task state directory".into(),
            );
        }
        orc_admin::secure_dir(&config.state_dir)?;
        let store = Store::open(&config.state_dir)?;
        let identity = IdentityFile::load(&config.identity_file)?;
        if orc_transport::key_id(
            "mcp",
            &orc_transport::verifying_key(&config.mcp_public_key)?,
        ) != config.mcp_id
        {
            return Err("MCP_IDENTITY_MISMATCH".into());
        }
        let trust = json!({"mcp_id":config.mcp_id,"execution_uid":config.execution_uid,"mcp_public_key":config.mcp_public_key,"mcp_certificate_digest":config.mcp_certificate_digest});
        match store.get_record("trust", "current").await? {
            Some(previous) if previous != trust => {
                return Err("TRUST_CHANGE_REQUIRES_REVOKE_AND_REENROLL".into());
            }
            None => store.put_record("trust", "current", trust).await?,
            _ => {}
        }
        let objects = ObjectStore::open(config.state_dir.join("objects"))?;
        let paused = store
            .get_record("config", "paused")
            .await?
            .is_some_and(|v| v == true);
        let maintenance = store
            .get_record("config", "maintenance")
            .await?
            .is_some_and(|v| v == true);
        let trust_revoked = store
            .get_record("config", "trust_revoked")
            .await?
            .is_some_and(|v| v == true);
        let this = Self {
            device_id: identity.id("dev")?,
            config,
            store,
            identity,
            gate: Default::default(),
            body_lock: Default::default(),
            paused: Arc::new(std::sync::atomic::AtomicBool::new(paused)),
            connected: Default::default(),
            objects,
            maintenance: Arc::new(std::sync::atomic::AtomicBool::new(maintenance)),
            trust_revoked: Arc::new(std::sync::atomic::AtomicBool::new(trust_revoked)),
            #[cfg(test)]
            test_backend: None,
        };
        // Old accepted/starting work is never automatically launched on restart.
        for mut task in this.store.list_tasks(None).await? {
            if matches!(
                task.execution_state.as_str(),
                "accepted" | "starting" | "running" | "pending_approval"
            ) {
                task.execution_state =
                    if task.execution_state == "running" || task.execution_state == "starting" {
                        "unknown"
                    } else {
                        "not_started"
                    }
                    .into();
                task.finish_reason = Some("supervisor_lost".into());
                task.stop_state = if task.execution_state == "not_started" {
                    "confirmed"
                } else {
                    "requested"
                }
                .into();
                let revision = task.revision;
                this.update(task, revision).await?;
            }
        }
        Ok(this)
    }
    fn watchdog_healthy(&self) -> bool {
        #[cfg(test)]
        if self.test_backend.is_some() {
            return true;
        }
        orc_execution::read_json::<u64>(
            &self.config.state_dir.join("tasks/watchdog-heartbeat.json"),
            1024,
        )
        .is_ok_and(|t| {
            t <= orc_execution::unix_ms() + 1000
                && orc_execution::unix_ms().saturating_sub(t) < 10_000
        })
    }
    pub async fn shutdown(&self) -> std::result::Result<(), AnyError> {
        let status = self.maintenance_status().await?;
        if status["active_tasks"] == 0 && status["unresolved_tasks"] == 0 {
            return Ok(());
        }
        self.owner(orc_admin::Request {
            method: "pause".into(),
            params: json!({}),
        })
        .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            self.tick().await?;
            if self.store.list_tasks(None).await?.iter().all(|t| {
                matches!(t.execution_state.as_str(), "exited" | "not_started")
                    && matches!(t.stop_state.as_str(), "none" | "confirmed")
            }) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("STOP_NOT_CONFIRMED: watchdog remains responsible; local reconciliation required".into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    async fn update(
        &self,
        mut task: StoredTask,
        revision: u64,
    ) -> std::result::Result<StoredTask, AnyError> {
        task.updated_at = now();
        Ok(self.store.update_task(task, revision).await?)
    }
    async fn grant(&self, id: &str) -> std::result::Result<Grant, AnyError> {
        let stored = self.store.get_grant(id).await?.ok_or("GRANT_UNKNOWN")?;
        let mut grant: Grant = serde_json::from_value(stored.payload)?;
        if stored.status != "active" {
            grant.status = GrantStatus::Revoked;
        }
        Ok(grant)
    }
    fn backend(&self, body: &TaskBody) -> Arc<dyn ExecutionBackend> {
        #[cfg(test)]
        if let Some(backend) = &self.test_backend {
            return backend.clone();
        }
        match &body.isolated {
            Some(config) => Arc::new(GvisorBackend::new(config.clone())),
            None => Arc::new(HostBackend::new(HostConfig {
                state_dir: self.config.state_dir.join("tasks"),
                runner_path: self.config.runner_path.clone(),
                execution_uid: self.config.execution_uid,
            })),
        }
    }
    async fn discover(&self, principal: &Principal) -> std::result::Result<Value, AnyError> {
        let mut grants = vec![];
        for stored in self.store.list_grants().await? {
            let grant = self.grant(&stored.grant_id).await?;
            if grant
                .check_access(
                    &principal.id(),
                    &DeviceId(self.device_id.clone()),
                    Action::DeviceDiscover,
                    now(),
                )
                .is_ok()
            {
                grants.push(grant)
            }
        }
        if grants.is_empty() {
            return Err("ACCESS_DENIED".into());
        }
        let host = HostBackend::new(HostConfig {
            state_dir: self.config.state_dir.join("tasks"),
            runner_path: self.config.runner_path.clone(),
            execution_uid: self.config.execution_uid,
        })
        .probe()
        .await;
        Ok(
            json!({"device_id":self.device_id,"execution_uid":self.config.execution_uid,"paused":self.paused.load(std::sync::atomic::Ordering::SeqCst),"grants":grants,"host":match host{Ok(c)=>serde_json::to_value(c)?,Err(e)=>json!({"available":false,"reason":e.to_string()})},"isolated_configured":self.config.gvisor.is_some(),"host_boundary":"commands can access real files and tools of the execution account; cwd is not isolation"}),
        )
    }
    /// 接收已验证信封中的 Principal，调用本地授权路径并记录不含正文的审计结果。
    pub async fn invoke(
        &self,
        principal: Principal,
        tool: &str,
        args: Value,
    ) -> std::result::Result<Value, AnyError> {
        let principal_id = principal.id().0;
        let result = self.invoke_inner(principal, tool, args).await;
        self.audit_operation(Some(principal_id), tool, &result)
            .await;
        result
    }
    async fn invoke_inner(
        &self,
        principal: Principal,
        tool: &str,
        args: Value,
    ) -> std::result::Result<Value, AnyError> {
        if self.trust_revoked.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("MCP_TRUST_REVOKED".into());
        }
        if principal.mcp_id.0 != self.config.mcp_id || field(&args, "device_id")? != self.device_id
        {
            return Err("IDENTITY_OR_TARGET_MISMATCH".into());
        }
        if self
            .store
            .get_record("revoked_principal", &principal.id().0)
            .await?
            .is_some()
        {
            return Err("ACCESS_REVOKED".into());
        }
        match tool {
            "orc_device_inspect" => self.discover(&principal).await,
            "orc_task_submit" => {
                self.submit(principal, serde_json::from_value(args)?, false)
                    .await
            }
            "orc_policy_preview" => {
                self.submit(principal, serde_json::from_value(args)?, true)
                    .await
            }
            "orc_submission_get" => {
                let key = SubmissionKey {
                    principal_id: principal.id().0,
                    device_id: self.device_id.clone(),
                    submission_id: field(&args, "submission_id")?.into(),
                };
                let record = self
                    .store
                    .get_submission(key)
                    .await?
                    .ok_or("SUBMISSION_NOT_FOUND")?;
                let task = self.owned_task(&principal, &record.task_id, false).await?;
                self.inspect_view(&principal, &task).await
            }
            "orc_task_get" => {
                self.inspect_view(
                    &principal,
                    &self
                        .owned_task(&principal, field(&args, "task_id")?, false)
                        .await?,
                )
                .await
            }
            "orc_task_list" => {
                let mut tasks = vec![];
                for task in self.store.list_tasks(Some(&principal.id().0)).await? {
                    if self
                        .grant(&task.grant_id)
                        .await?
                        .check_access(
                            &principal.id(),
                            &DeviceId(self.device_id.clone()),
                            Action::TaskInspect,
                            now(),
                        )
                        .is_ok()
                    {
                        tasks.push(self.task_view(&task)?);
                    }
                }
                Ok(json!({"tasks":tasks,"next_cursor":null}))
            }
            "orc_task_cancel" => self.cancel(&principal, &args).await,
            "orc_task_output_read" => self.output(&principal, &args).await,
            "orc_snapshot_list" => {
                let mut list = vec![];
                for v in self.store.list_records("snapshot").await? {
                    let snapshot: Snapshot = serde_json::from_value(v)?;
                    if self.snapshot_access(&principal, &snapshot).await.is_ok() {
                        let mut item = val(&snapshot)?;
                        item["expires_at"] = json!(snapshot.created_at.saturating_add(86400));
                        list.push(item)
                    }
                }
                Ok(json!({"snapshots":list,"next_cursor":null}))
            }
            "orc_snapshot_read" => {
                let snapshot: Snapshot = serde_json::from_value(
                    self.store
                        .get_record("snapshot", field(&args, "snapshot_id")?)
                        .await?
                        .ok_or("SNAPSHOT_UNKNOWN")?,
                )?;
                self.snapshot_access(&principal, &snapshot).await?;
                let offset = args["offset"].as_u64().unwrap_or(0);
                let limit = args["limit"].as_u64().unwrap_or(65536).min(65536) as usize;
                let data = snapshot.read(field(&args, "path")?, &self.objects, offset, limit)?;
                self.snapshot_access(&principal, &snapshot).await?;
                Ok(
                    json!({"device_id":self.device_id,"snapshot_id":snapshot.snapshot_id,"offset":offset,"bytes":data.len(),"text":String::from_utf8_lossy(&data),"untrusted":true}),
                )
            }
            "orc_artifacts_list" | "orc_artifact_read" => {
                self.artifacts(&principal, tool, &args).await
            }
            "orc_changes_propose" | "orc_changes_get" => {
                let _gate = self.gate.lock().await;
                self.changes(&principal, tool, &args).await
            }
            _ => Err("CAPABILITY_UNAVAILABLE".into()),
        }
    }
    async fn snapshot_access(
        &self,
        principal: &Principal,
        snapshot: &Snapshot,
    ) -> std::result::Result<(), AnyError> {
        if now() >= snapshot.created_at.saturating_add(86400) {
            return Err("SNAPSHOT_EXPIRED".into());
        }
        // Export is a separate owner action; only its immutable registered ID can be read.
        for stored in self.store.list_grants().await? {
            let grant = self.grant(&stored.grant_id).await?;
            if grant.environment == Environment::Isolated
                && grant.workspace_ids.contains(&snapshot.workspace_id)
                && grant
                    .check_access(
                        &principal.id(),
                        &DeviceId(self.device_id.clone()),
                        Action::SnapshotRead,
                        now(),
                    )
                    .is_ok()
            {
                return Ok(());
            }
        }
        Err("ACCESS_DENIED".into())
    }
    /// 将原始请求解析为审批和运行共用的有效规格，然后按真实入口摘要评估规则。
    /// 隔离分支只使用获准快照及固定镜像；此函数可能物化输入，但不启动用户命令。
    async fn resolve(
        &self,
        principal: &Principal,
        request: &TaskRequest,
        grant: &Grant,
        task_id: String,
    ) -> std::result::Result<(TaskBody, PolicyDecision), AnyError> {
        grant.authorize(&principal.id(), request, Action::TaskSubmit, now())?;
        if grant.execution_uid != self.config.execution_uid {
            return Err("EXECUTION_UID_MISMATCH".into());
        }
        let mut environment = self.config.environment.clone();
        environment.extend(request.env_overrides.clone());
        environment
            .entry("PATH".into())
            .or_insert("/usr/local/bin:/usr/bin:/bin".into());
        environment.entry("LANG".into()).or_insert("C.UTF-8".into());
        let command = match &request.command {
            Command::Argv { program, args } => ExecutionCommand::Argv {
                program: program.clone(),
                args: args.clone(),
            },
            Command::Script {
                interpreter,
                interpreter_args,
                args,
                entry,
            } => {
                let (source, source_path) = match entry {
                    ScriptEntry::Inline { value } => (value.clone(), None),
                    ScriptEntry::FileEntry { path } => {
                        if grant.environment == Environment::Isolated {
                            let snapshot: Snapshot = serde_json::from_value(
                                self.store
                                    .get_record(
                                        "snapshot",
                                        &request
                                            .context
                                            .snapshot_id
                                            .as_ref()
                                            .ok_or("SNAPSHOT_REQUIRED")?
                                            .0,
                                    )
                                    .await?
                                    .ok_or("SNAPSHOT_UNKNOWN")?,
                            )?;
                            let relative = path.strip_prefix("/work/").unwrap_or(path);
                            let blob = snapshot
                                .files
                                .get(relative)
                                .ok_or("SCRIPT_NOT_IN_SNAPSHOT")?;
                            (
                                String::from_utf8(self.objects.read_all(blob, 65536)?)?,
                                None,
                            )
                        } else {
                            let p = if Path::new(path).is_absolute() {
                                PathBuf::from(path)
                            } else {
                                PathBuf::from(&request.context.cwd).join(path)
                            };
                            let mut options = std::fs::OpenOptions::new();
                            options.read(true);
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::OpenOptionsExt;
                                options.custom_flags(libc::O_NOFOLLOW);
                            }
                            let file = options.open(&p)?;
                            let meta = file.metadata()?;
                            if !meta.is_file() || meta.len() > 65536 {
                                return Err("INVALID_SCRIPT_FILE".into());
                            }
                            let mut bytes = Vec::new();
                            file.take(65537).read_to_end(&mut bytes)?;
                            if bytes.len() > 65536 {
                                return Err("SCRIPT_TOO_LARGE".into());
                            }
                            (String::from_utf8(bytes)?, Some(p))
                        }
                    }
                };
                ExecutionCommand::Script {
                    interpreter: interpreter.clone(),
                    interpreter_args: interpreter_args.clone(),
                    args: args.clone(),
                    source,
                    source_path,
                }
            }
        };
        if grant.environment == Environment::Isolated {
            environment = BTreeMap::from([
                ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
                ("HOME".into(), "/tmp".into()),
                ("TMPDIR".into(), "/tmp".into()),
                ("LANG".into(), "C.UTF-8".into()),
            ]);
            environment.extend(request.env_overrides.clone());
        }
        let mut spec = ExecutionSpec {
            task_id,
            execution_uid: grant.execution_uid,
            command,
            cwd: request.context.cwd.clone().into(),
            env: environment,
            stdin: request.stdin.bytes().to_vec(),
            deadline_unix_ms: grant.deadline(request, now()) * 1000,
            output_limit_bytes: request.limits.output_bytes,
        };
        let (resolved, isolated) = match grant.environment {
            Environment::Host => {
                if grant.environment_profile_id != self.config.host_profile_id
                    || grant.environment_digest != self.config.host_environment_digest
                    || grant.host_context_id.as_ref() != Some(&self.config.host_context_id)
                {
                    return Err("ENVIRONMENT_CHANGED".into());
                }
                spec.cwd = std::fs::canonicalize(&spec.cwd)?;
                let resolved =
                    tokio::task::spawn_blocking(move || orc_execution::resolve_spec(spec))
                        .await??;
                (resolved, None)
            }
            Environment::Isolated => {
                let mut config = self.config.gvisor.clone().ok_or("ISOLATION_UNAVAILABLE")?;
                if grant.environment_profile_id != "linux-isolated-python-v1"
                    || grant.environment_digest != config.image_digest
                {
                    return Err("ENVIRONMENT_CHANGED".into());
                }
                let snapshot: Snapshot = serde_json::from_value(
                    self.store
                        .get_record(
                            "snapshot",
                            &request
                                .context
                                .snapshot_id
                                .as_ref()
                                .ok_or("SNAPSHOT_REQUIRED")?
                                .0,
                        )
                        .await?
                        .ok_or("SNAPSHOT_UNKNOWN")?,
                )?;
                if now() >= snapshot.created_at.saturating_add(86400) {
                    return Err("SNAPSHOT_EXPIRED".into());
                }
                if request.context.workspace_id.as_ref() != Some(&snapshot.workspace_id)
                    || !grant.workspace_ids.contains(&snapshot.workspace_id)
                {
                    return Err("SNAPSHOT_OUTSIDE_GRANT".into());
                }
                config.approved_input = self
                    .config
                    .state_dir
                    .join("inputs")
                    .join(&snapshot.snapshot_id);
                self.materialize(&snapshot, &config.approved_input)?;
                let resolved = GvisorBackend::new(config.clone()).resolve_spec(spec)?;
                (resolved, Some(config))
            }
        };
        let mut rule_args = Vec::new();
        if let Command::Script {
            interpreter_args, ..
        } = &request.command
        {
            rule_args.extend(interpreter_args.clone())
        }
        rule_args.extend(request.command.args().iter().cloned());
        let principal_id = principal.id();
        let decision = grant.policy.evaluate(&RuleContext {
            principal: &principal_id,
            device: &request.device_id,
            account: grant.execution_uid,
            environment: &grant.environment_profile_id,
            action: Action::TaskSubmit,
            cwd: resolved.spec.cwd.to_str().ok_or("INVALID_CWD")?,
            command_kind: request.command.kind(),
            program: &resolved.entry.sha256,
            args: &rule_args,
        });
        let body = TaskBody {
            request: request.clone(),
            principal: principal.clone(),
            resolved,
            grant_revision: grant.revision,
            policy_revision: grant.policy.revision(),
            approval_id: None,
            instance: None,
            isolated,
        };
        Ok((body, decision))
    }
    /// 将内容寻址快照物化为只读输入；已有目录必须与获准清单完全一致才能复用。
    fn materialize(&self, snapshot: &Snapshot, target: &Path) -> std::result::Result<(), AnyError> {
        snapshot.verify()?;
        if target.exists() {
            let exported = Snapshot::export(
                target,
                &snapshot.workspace_id,
                &self.objects,
                &orc_workspace::Limits::default(),
                now(),
            )?;
            if exported.files != snapshot.files || !exported.exclusions.is_empty() {
                return Err("SNAPSHOT_CHANGED".into());
            }
            return Ok(());
        }
        let parent = target.parent().ok_or("INVALID_INPUT_PATH")?;
        std::fs::create_dir_all(parent)?;
        let temp = parent.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&temp)?;
        for (path, blob) in &snapshot.files {
            let dest = temp.join(path);
            if let Some(dir) = dest.parent() {
                std::fs::create_dir_all(dir)?;
            }
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dest)?;
            file.write_all(&self.objects.read_all(blob, 8 * 1024 * 1024)?)?;
            file.sync_all()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o444))?;
            }
        }
        fn readonly_dirs(dir: &Path) -> std::io::Result<()> {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    readonly_dirs(&entry.path())?;
                }
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555))?;
            }
            Ok(())
        }
        readonly_dirs(&temp)?;
        std::fs::rename(temp, target)?;
        Ok(())
    }
    /// 先按原始请求摘要去重，再解析和持久化新任务；preview 共用解析逻辑但不接受任务。
    /// 真正执行交给独立 tick，因此一次 HTTP 调用的结束不等于任务结束。
    async fn submit(
        &self,
        principal: Principal,
        request: TaskRequest,
        preview: bool,
    ) -> std::result::Result<Value, AnyError> {
        request.validate()?;
        let digest = orc_protocol::canonical_digest(&request)?;
        let key = SubmissionKey {
            principal_id: principal.id().0,
            device_id: self.device_id.clone(),
            submission_id: request.submission_id.0.clone(),
        };
        // 先查旧提交，再检查新请求时窗：已接受任务即使请求过期也只能返回原任务，不能重跑。
        if !preview && let Some(record) = self.store.get_submission(key.clone()).await? {
            if record.request_digest != digest {
                return Err("SUBMISSION_CONFLICT".into());
            }
            return self
                .inspect_view(
                    &principal,
                    &self
                        .store
                        .get_task(&record.task_id)
                        .await?
                        .ok_or("TASK_UNKNOWN")?,
                )
                .await;
        }
        if self.maintenance.load(std::sync::atomic::Ordering::SeqCst) && !preview {
            return Err("MAINTENANCE".into());
        }
        request
            .submission_id
            .validate_fresh(now(), request.request_expires_at)?;
        if self.paused.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("ENDPOINT_PAUSED".into());
        }
        let grant = self.grant(&request.grant_id.0).await?;
        // Keep approved input objects alive through durable task acceptance.
        let _body_lock = self.body_lock.lock().await;
        let task_id = format!("task_{}", uuid::Uuid::now_v7());
        let (mut body, decision) = self
            .resolve(&principal, &request, &grant, task_id.clone())
            .await?;
        if preview {
            return Ok(
                json!({"device_id":self.device_id,"decision":decision,"effective_spec":body.resolved,"grant_revision":grant.revision,"policy_revision":grant.policy.revision(),"execution_uid":grant.execution_uid}),
            );
        }
        if !self.watchdog_healthy() {
            return Err("WATCHDOG_UNHEALTHY".into());
        }
        if decision.effect == RuleEffect::Deny {
            return Err("POLICY_DENIED".into());
        }
        let _gate = self.gate.lock().await;
        if self.maintenance.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("MAINTENANCE".into());
        }
        if self.paused.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("ENDPOINT_PAUSED".into());
        }
        // 解析入口/快照期间可能发生权限变化；取得 gate 后重新读取并比较 grant。
        let current = self.grant(&request.grant_id.0).await?;
        current.authorize(&principal.id(), &request, Action::TaskSubmit, now())?;
        if current.revision != grant.revision || current.policy != grant.policy {
            return Err("POLICY_CHANGED".into());
        }
        let tasks = self.store.list_tasks(None).await?;
        let waiting: Vec<_> = tasks
            .iter()
            .filter(|t| {
                matches!(
                    t.execution_state.as_str(),
                    "pending_approval" | "accepted" | "starting" | "running" | "unknown"
                )
            })
            .collect();
        if waiting.len() >= 16
            || waiting
                .iter()
                .filter(|t| t.principal_id == principal.id().0)
                .count()
                >= 8
        {
            return Err("TASK_QUOTA_EXCEEDED".into());
        }
        if decision.effect == RuleEffect::Review {
            body.approval_id = Some(format!("approval_{}", uuid::Uuid::now_v7()))
        }
        // 原始请求摘要用于重试去重；此有效摘要另外绑定主体、grant 和实际执行规格，供审批使用。
        let effective_digest = orc_protocol::canonical_digest(&(
            principal.clone(),
            grant.clone(),
            body.resolved.digest.clone(),
            request.clone(),
        ))?;
        let task = StoredTask {
            task_id: task_id.clone(),
            principal_id: principal.id().0,
            device_id: self.device_id.clone(),
            grant_id: grant.id.0.clone(),
            effective_digest: effective_digest.clone(),
            execution_state: if body.approval_id.is_some() {
                "pending_approval"
            } else {
                "accepted"
            }
            .into(),
            stop_state: "none".into(),
            finish_reason: None,
            exit_code: None,
            revision: 0,
            created_at: now(),
            updated_at: now(),
            payload: val(&body)?,
        };
        let approval = body.approval_id.map(|id| StoredApproval {
            approval_id: id,
            grant_id: grant.id.0.clone(),
            effective_digest,
            grant_revision: grant.revision,
            policy_revision: grant.policy.revision(),
            expires_at: (now() + 300)
                .min(grant.expires_at)
                .min(request.request_expires_at),
            status: "pending".into(),
            consumed_by: None,
        });
        let accepted = self
            .store
            .accept_submission_with_approval(
                SubmissionRecord {
                    key,
                    request_digest: digest,
                    task_id: task_id.clone(),
                    grant_id: grant.id.0.clone(),
                    created_at: now(),
                },
                task,
                approval,
            )
            .await?;
        self.task_view(&accepted.task)
    }
    fn task_view(&self, task: &StoredTask) -> std::result::Result<Value, AnyError> {
        let body = serde_json::from_value::<TaskBody>(task.payload.clone()).ok();
        Ok(
            json!({"device_id":task.device_id,"task_id":task.task_id,"principal_id":task.principal_id,"grant_id":task.grant_id,"submission_id":body.as_ref().map(|b|&b.request.submission_id),"execution_uid":self.config.execution_uid,"environment_profile_id":body.as_ref().map(|b|&b.request.environment_profile_id),"deadline_unix_ms":body.as_ref().map(|b|b.resolved.spec.deadline_unix_ms),"approval_id":body.as_ref().and_then(|b|b.approval_id.as_ref()),"effective_digest":task.effective_digest,"execution_state":task.execution_state,"stop_state":task.stop_state,"finish_reason":task.finish_reason,"exit_code":task.exit_code,"revision":task.revision,"last_confirmed_at":task.updated_at,"delivery_state":"endpoint_acknowledged","body_expires_at":task.created_at.saturating_add(86400),"body_available":!task.payload.is_null(),"body_storage":"endpoint"}),
        )
    }
    async fn inspect_view(
        &self,
        principal: &Principal,
        task: &StoredTask,
    ) -> std::result::Result<Value, AnyError> {
        if self
            .grant(&task.grant_id)
            .await?
            .check_access(
                &principal.id(),
                &DeviceId(self.device_id.clone()),
                Action::TaskInspect,
                now(),
            )
            .is_ok()
        {
            self.task_view(task)
        } else {
            Ok(
                json!({"device_id":task.device_id,"task_id":task.task_id,"execution_state":task.execution_state,"stop_state":task.stop_state,"last_confirmed_at":task.updated_at,"access":"minimal_stop_status"}),
            )
        }
    }
    /// 将固定正文与运行实例合并；允许从 prepare 已写的 runtime.json 补回 DB 关联。
    /// 磁盘与数据库身份不一致时拒绝，不能用另一个实例补齐未知结果。
    async fn load_body(&self, task: &StoredTask) -> std::result::Result<TaskBody, AnyError> {
        let mut body: TaskBody = serde_json::from_value(task.payload.clone())?;
        body.instance = self
            .store
            .get_record("runtime", &task.task_id)
            .await?
            .map(serde_json::from_value)
            .transpose()?;
        let directory = self.config.state_dir.join("tasks").join(&task.task_id);
        if let Ok(record) = orc_execution::read_json::<InstanceRef>(
            &directory.join("runtime.json"),
            orc_execution::MAX_SPEC,
        ) {
            if record.task_id != task.task_id
                || record.spec_digest != body.resolved.digest
                || record.directory != directory
                || record.backend
                    != if body.isolated.is_some() {
                        orc_execution::BackendKind::Gvisor
                    } else {
                        orc_execution::BackendKind::HostLinux
                    }
                || body.instance.as_ref().is_some_and(|previous| {
                    record.backend != previous.backend
                        || record.boot_id != previous.boot_id
                        || record.runtime_id != previous.runtime_id
                        || record.directory != previous.directory
                })
            {
                return Err("RUNTIME_IDENTITY_CHANGED".into());
            }
            if body.instance.is_none() {
                // prepare persists its immutable reference before making any
                // external instance. Recover the crash window before DB linkage.
                self.store
                    .put_record("runtime", &task.task_id, val(&record)?)
                    .await?;
            }
            body.instance = Some(record);
        }
        Ok(body)
    }
    async fn owned_task(
        &self,
        principal: &Principal,
        id: &str,
        body_read: bool,
    ) -> std::result::Result<StoredTask, AnyError> {
        let task = self.store.get_task(id).await?.ok_or("TASK_UNKNOWN")?;
        if task.principal_id != principal.id().0 || task.device_id != self.device_id {
            return Err("ACCESS_DENIED".into());
        }
        if body_read {
            self.grant(&task.grant_id).await?.check_access(
                &principal.id(),
                &DeviceId(self.device_id.clone()),
                Action::ResultRead,
                now(),
            )?;
            if now() >= task.created_at + 86400 {
                return Err("RESULT_EXPIRED".into());
            }
        }
        Ok(task)
    }
    async fn output(
        &self,
        principal: &Principal,
        args: &Value,
    ) -> std::result::Result<Value, AnyError> {
        let task = self
            .owned_task(principal, field(args, "task_id")?, true)
            .await?;
        let body = self.load_body(&task).await?;
        let stream = field(args, "stream")?;
        if !matches!(stream, "stdout" | "stderr") {
            return Err("INVALID_STREAM".into());
        }
        let instance = body.instance.ok_or("OUTPUT_NOT_AVAILABLE")?;
        let offset = args["offset"].as_u64().unwrap_or(0);
        let limit = args["limit"].as_u64().unwrap_or(65536);
        if limit > 65536 {
            return Err("READ_LIMIT_EXCEEDED".into());
        }
        let p = instance.directory.join(stream);
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(p)?;
        if !file.metadata()?.is_file() {
            return Err("INVALID_OUTPUT".into());
        }
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = Vec::new();
        file.take(limit).read_to_end(&mut bytes)?;
        let result: Option<orc_execution::RunnerResult> =
            orc_execution::read_json(&instance.directory.join("result.json"), 65536).ok();
        self.owned_task(principal, &task.task_id, true).await?;
        Ok(
            json!({"device_id":self.device_id,"task_id":task.task_id,"stream":stream,"offset":offset,"next_offset":offset+bytes.len() as u64,"text":String::from_utf8_lossy(&bytes),"bytes":bytes.len(),"untrusted":true,"truncated":result.map(|r|r.output_truncated),"status":self.task_view(&task)?}),
        )
    }
    /// 持久记录停止意图并立即返回；后续 tick 才操作后端并更新停止证据。
    async fn request_stop(
        &self,
        mut task: StoredTask,
        reason: StopReason,
    ) -> std::result::Result<Value, AnyError> {
        if task.stop_state == "confirmed"
            || task.execution_state == "exited"
            || task.execution_state == "not_started"
        {
            return self.task_view(&task);
        }
        task.stop_state = "requested".into();
        task.finish_reason = Some(
            serde_json::to_value(reason)?
                .as_str()
                .unwrap_or("cancelled")
                .into(),
        );
        let rev = task.revision;
        let task = self.update(task, rev).await?;
        self.task_view(&task)
    }
    pub async fn supervise(self: Arc<Self>) -> std::result::Result<(), AnyError> {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        let mut last_cleanup = now();
        loop {
            tick.tick().await;
            if now().saturating_sub(last_cleanup) >= 60 {
                last_cleanup = now();
                if self.cleanup_expired().await.is_err() {
                    tracing::warn!(event = "retention_cleanup_failed");
                }
            }
            if let Err(e) = self.tick().await {
                if e.downcast_ref::<orc_store::StoreError>()
                    .is_some_and(|e| matches!(e, orc_store::StoreError::RevisionConflict))
                {
                    continue;
                }
                tracing::error!(event="supervisor_error",reason=%e);
                self.paused.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }
    /// 一次监督轮询：先处理停止/已有实例，再为可运行任务走审批、准备和最终启动关口。
    /// P0 同时只放行一个未确认停止的执行实例；Unknown 也占用执行位置。
    async fn tick(&self) -> std::result::Result<(), AnyError> {
        let tasks = self.store.list_tasks(None).await?;
        let mut active = tasks.iter().any(|t| {
            matches!(
                t.execution_state.as_str(),
                "starting" | "running" | "unknown"
            ) && t.stop_state != "confirmed"
        });
        for mut task in tasks {
            // 终态任务只补做采集/清理；这些重试不经过用户命令的启动路径。
            if matches!(task.execution_state.as_str(), "exited" | "not_started") {
                if self
                    .store
                    .get_record("collection_complete", &task.task_id)
                    .await?
                    .is_none()
                {
                    if now() < task.created_at.saturating_add(86400) {
                        if let Ok(body) = self.load_body(&task).await
                            && let Some(instance) = &body.instance
                        {
                            self.collect(&task, &body, instance).await?;
                        }
                    } else if let Some(value) =
                        self.store.get_record("runtime", &task.task_id).await?
                    {
                        let instance: InstanceRef = serde_json::from_value(value)?;
                        if instance.backend == orc_execution::BackendKind::Gvisor
                            && let Some(config) = &self.config.gvisor
                            && GvisorBackend::new(config.clone())
                                .cleanup(&instance)
                                .await
                                .is_ok()
                        {
                            self.store
                                .put_record(
                                    "collection_complete",
                                    &task.task_id,
                                    json!({"expired":true}),
                                )
                                .await?;
                        }
                    }
                }
                continue;
            }
            let Ok(mut body) = self.load_body(&task).await else {
                continue;
            };
            let grant = self.grant(&task.grant_id).await?;
            let stop = if !self.watchdog_healthy() {
                Some("supervisor_lost")
            } else if self.paused.load(std::sync::atomic::Ordering::SeqCst) {
                Some("endpoint_paused")
            } else if grant.status != GrantStatus::Active {
                Some("grant_revoked")
            } else if now() >= grant.expires_at {
                Some("grant_expired")
            } else if orc_execution::unix_ms() >= body.resolved.spec.deadline_unix_ms
                || (body.instance.is_none() && now() >= body.request.request_expires_at)
            {
                Some("deadline")
            } else if !self.connected.load(std::sync::atomic::Ordering::SeqCst)
                && !self.config.continue_on_disconnect
            {
                Some("control_lost")
            } else {
                None
            };
            if let Some(reason) = stop {
                task.stop_state = "requested".into();
                task.finish_reason = Some(reason.into());
            }
            let backend = self.backend(&body);
            // 停止优先于正常推进。没有实例引用也不代表未启动：starting/unknown
            // 可能对应准备过程的崩溃窗口，只能继续保留未知证据。
            if matches!(task.stop_state.as_str(), "requested" | "failed" | "unknown") {
                if let Some(instance) = &body.instance {
                    match backend.stop(instance, StopReason::Cancelled).await {
                        Ok(e) if e.confirmed => {
                            task.stop_state = "confirmed".into();
                            task.execution_state = "exited".into();
                            self.collect(&task, &body, instance).await?;
                            task.exit_code =
                                orc_execution::read_json::<orc_execution::RunnerResult>(
                                    &instance.directory.join("result.json"),
                                    65536,
                                )
                                .ok()
                                .and_then(|r| r.exit_code);
                        }
                        Ok(_) => task.stop_state = "unknown".into(),
                        Err(_) => task.stop_state = "failed".into(),
                    }
                } else if matches!(
                    task.execution_state.as_str(),
                    "starting" | "running" | "unknown"
                ) {
                    task.stop_state = "unknown".into();
                    task.execution_state = "unknown".into();
                } else {
                    task.stop_state = "confirmed".into();
                    task.execution_state = "not_started".into();
                }
                let rev = task.revision;
                self.update(task, rev).await?;
                continue;
            }
            if let Some(instance) = &body.instance {
                orc_execution::refresh_lease(instance)?;
                match backend.inspect(instance).await {
                    Ok(e) if e.state == RuntimeState::Exited => {
                        self.collect(&task, &body, instance).await?;
                        task.execution_state = "exited".into();
                        let result: Option<orc_execution::RunnerResult> = orc_execution::read_json(
                            &instance.directory.join("result.json"),
                            65536,
                        )
                        .ok();
                        task.exit_code =
                            result.as_ref().map(|r| r.exit_code).unwrap_or(e.exit_code);
                        task.stop_state = "confirmed".into();
                        if task.finish_reason.is_none() {
                            task.finish_reason =
                                Some(result.map(|r| r.reason).unwrap_or_else(|| {
                                    if e.exit_code == Some(0) {
                                        "exit_zero".into()
                                    } else {
                                        "exit_nonzero".into()
                                    }
                                }));
                        }
                        let rev = task.revision;
                        self.update(task, rev).await?;
                    }
                    Ok(e) if e.state == RuntimeState::Running => {}
                    _ => {
                        if task.execution_state != "unknown" {
                            task.execution_state = "unknown".into();
                            let rev = task.revision;
                            self.update(task, rev).await?;
                        }
                    }
                }
                continue;
            }
            // 已存在或状态未知的实例仍占用执行位置，防止恢复期间并行放行新任务。
            if active {
                continue;
            }
            if task.execution_state == "pending_approval" {
                let Some(id) = &body.approval_id else {
                    continue;
                };
                let approval = self
                    .store
                    .get_approval(id)
                    .await?
                    .ok_or("APPROVAL_MISSING")?;
                if approval.status == "rejected" || approval.expires_at <= now() {
                    task.execution_state = "not_started".into();
                    task.finish_reason = Some("approval_expired_or_rejected".into());
                    let rev = task.revision;
                    self.update(task, rev).await?;
                    continue;
                }
                if approval.status != "approved" {
                    continue;
                }
                task.execution_state = "accepted".into();
                let rev = task.revision;
                task = self.update(task, rev).await?;
            } else if task.execution_state != "accepted" {
                continue;
            }
            let gate = self.gate.lock().await;
            task = self
                .store
                .get_task(&task.task_id)
                .await?
                .ok_or("TASK_UNKNOWN")?;
            if task.stop_state != "none" {
                continue;
            }
            grant.authorize(
                &body.principal.id(),
                &body.request,
                Action::TaskSubmit,
                now(),
            )?;
            if grant.revision != body.grant_revision
                || grant.policy.revision() != body.policy_revision
            {
                task.execution_state = "not_started".into();
                task.finish_reason = Some("policy_changed".into());
                let rev = task.revision;
                self.update(task, rev).await?;
                continue;
            }
            task.execution_state = "starting".into();
            let rev = task.revision;
            task = self.update(task, rev).await?;
            drop(gate);
            // 准备可能慢且有外部副作用，不在此期间持有 gate；落盘 starting 后，崩溃只能恢复核实。
            let prepared = match backend.prepare(body.resolved.clone()).await {
                Ok(p) => p,
                Err(error) => {
                    task = self
                        .store
                        .get_task(&task.task_id)
                        .await?
                        .ok_or("TASK_UNKNOWN")?;
                    let root = body
                        .isolated
                        .as_ref()
                        .map(|c| c.state_dir.clone())
                        .unwrap_or_else(|| self.config.state_dir.join("tasks"));
                    let disk = orc_execution::read_json::<InstanceRef>(
                        &root.join(&task.task_id).join("runtime.json"),
                        orc_execution::MAX_SPEC,
                    )
                    .ok();
                    if let Some(instance) = disk {
                        if instance.task_id != task.task_id
                            || instance.spec_digest != body.resolved.digest
                            || instance.directory != root.join(&task.task_id)
                        {
                            return Err("RUNTIME_IDENTITY_CHANGED".into());
                        }
                        self.store
                            .put_record("runtime", &task.task_id, val(instance)?)
                            .await?;
                        task.execution_state = "unknown".into();
                        task.stop_state = "requested".into();
                    } else if matches!(error, orc_execution::BackendError::Unknown(_)) {
                        task.execution_state = "unknown".into();
                        task.stop_state = "unknown".into();
                    } else {
                        task.execution_state = "not_started".into();
                        task.stop_state = "confirmed".into();
                    }
                    task.finish_reason = Some("launch_failed".into());
                    let rev = task.revision;
                    self.update(task, rev).await?;
                    continue;
                }
            };
            body.instance = Some(prepared.instance.clone());
            self.store
                .put_record("runtime", &task.task_id, val(&prepared.instance)?)
                .await?;
            // prepare 期间允许撤销/取消推进；重新取锁并重读任务和 grant 后才能放行。
            let _gate = self.gate.lock().await;
            task = self
                .store
                .get_task(&task.task_id)
                .await?
                .ok_or("TASK_UNKNOWN")?;
            let grant = self.grant(&task.grant_id).await?;
            if task.stop_state != "none"
                || self.paused.load(std::sync::atomic::Ordering::SeqCst)
                || !self.watchdog_healthy()
                || (!self.connected.load(std::sync::atomic::Ordering::SeqCst)
                    && !self.config.continue_on_disconnect)
                || now() >= body.request.request_expires_at
                || orc_execution::unix_ms() >= body.resolved.spec.deadline_unix_ms
                || grant.revision != body.grant_revision
                || grant
                    .authorize(
                        &body.principal.id(),
                        &body.request,
                        Action::TaskSubmit,
                        now(),
                    )
                    .is_err()
            {
                task.stop_state = "requested".into();
                let rev = task.revision;
                self.update(task, rev).await?;
                active = true;
                continue;
            }
            // This lock serializes local revocation with the one-time launch gate.
            if let Some(id) = &body.approval_id {
                self.store
                    .consume_approval(
                        id,
                        &task.effective_digest,
                        grant.revision,
                        grant.policy.revision(),
                        &task.task_id,
                        now(),
                    )
                    .await?;
            }
            self.store
                .put_record(
                    "launch_attempt",
                    &task.task_id,
                    json!({"digest":task.effective_digest,"started_at":now()}),
                )
                .await?;
            // 审批消费与启动尝试都已持久化才发许可；此后失败仍可能已启动，只能停止/核实。
            let permit = LaunchPermit::after_durable_authorization(
                task.task_id.clone(),
                body.resolved.digest.clone(),
            );
            match backend.start(prepared, permit).await {
                Ok(instance) => {
                    orc_execution::refresh_lease(&instance)?;
                    body.instance = Some(instance);
                    task.execution_state = "running".into();
                }
                Err(_) => {
                    task.execution_state = "unknown".into();
                    task.stop_state = "requested".into();
                    task.finish_reason = Some("launch_failed".into());
                }
            }
            if let Some(instance) = &body.instance {
                self.store
                    .put_record("runtime", &task.task_id, val(instance)?)
                    .await?;
            }
            let rev = task.revision;
            self.update(task, rev).await?;
            active = true;
        }
        Ok(())
    }
    /// 收集隔离输出/产物后清理运行资源，以持久标记支持后续轮询补做未完成步骤。
    async fn collect(
        &self,
        task: &StoredTask,
        body: &TaskBody,
        instance: &InstanceRef,
    ) -> std::result::Result<(), AnyError> {
        let Some(config) = &body.isolated else {
            self.store
                .put_record(
                    "collection_complete",
                    &task.task_id,
                    json!({"host_output":true}),
                )
                .await?;
            return Ok(());
        };
        let backend = GvisorBackend::new(config.clone());
        match backend.collect_output(instance).await {
            Ok(_) => {}
            Err(error) => {
                self.store
                    .put_record(
                        "collection_error",
                        &task.task_id,
                        json!({"error":error.to_string()}),
                    )
                    .await?;
                return Ok(());
            }
        }
        let artifacts = match backend.collect_artifacts(instance).await {
            Ok(a) => a,
            Err(error) => {
                self.store
                    .put_record(
                        "collection_error",
                        &task.task_id,
                        json!({"error":error.to_string()}),
                    )
                    .await?;
                return Ok(());
            }
        };
        let _body_lock = self.body_lock.lock().await;
        let mut files = BTreeMap::new();
        let mut total = 0;
        for artifact in artifacts {
            let file = std::fs::File::open(&artifact.local_path)?;
            let mut bytes = Vec::new();
            file.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 != artifact.bytes
                || orc_execution::sha256(&bytes) != artifact.sha256
            {
                return Err("ARTIFACT_CHANGED".into());
            }
            let blob = self.objects.put_text(&bytes, 8 * 1024 * 1024)?;
            total += blob.size;
            files.insert(artifact.path, blob);
        }
        let workspace = body
            .request
            .context
            .workspace_id
            .clone()
            .ok_or("WORKSPACE_REQUIRED")?;
        let source = orc_workspace::DirectoryIdentity {
            device: 0,
            inode: 0,
        };
        let snapshot_id =
            orc_execution::sha256(&serde_json::to_vec(&(&workspace, &source, &files))?);
        let snapshot = Snapshot {
            snapshot_id,
            workspace_id: workspace,
            source,
            created_at: now(),
            files,
            exclusions: vec![],
            total_bytes: total,
        };
        snapshot.verify()?;
        self.store
            .put_record("task_artifacts", &task.task_id, val(snapshot)?)
            .await?;
        if let Err(error) = backend.cleanup(instance).await {
            self.store
                .put_record(
                    "cleanup_error",
                    &task.task_id,
                    json!({"error":error.to_string()}),
                )
                .await?;
        } else {
            self.store
                .put_record(
                    "collection_complete",
                    &task.task_id,
                    json!({"collected":true,"cleaned":true}),
                )
                .await?;
        }
        Ok(())
    }
    async fn cancel(
        &self,
        principal: &Principal,
        args: &Value,
    ) -> std::result::Result<Value, AnyError> {
        let _gate = self.gate.lock().await;
        let operation = SubmissionId(field(args, "operation_id")?.into());
        let digest = orc_protocol::canonical_digest(args)?;
        let task = self
            .owned_task(principal, field(args, "task_id")?, false)
            .await?;
        let key = format!("{}:{}", principal.id(), operation);
        if let Some(old) = self.store.get_record("cancel_operation", &key).await? {
            if old["digest"] != digest {
                return Err("SUBMISSION_CONFLICT".into());
            }
            return self.task_view(&task);
        }
        operation.validate_fresh(
            now(),
            args["request_expires_at"]
                .as_u64()
                .ok_or("request_expires_at required")?,
        )?;
        let task_id = task.task_id.clone();
        let result = self.request_stop(task, StopReason::Cancelled).await?;
        self.store
            .put_record(
                "cancel_operation",
                &key,
                json!({"digest":digest,"task_id":task_id}),
            )
            .await?;
        Ok(result)
    }
    async fn artifacts(
        &self,
        principal: &Principal,
        tool: &str,
        args: &Value,
    ) -> std::result::Result<Value, AnyError> {
        let task = self
            .owned_task(principal, field(args, "task_id")?, false)
            .await?;
        let grant = self.grant(&task.grant_id).await?;
        grant.check_access(
            &principal.id(),
            &DeviceId(self.device_id.clone()),
            Action::ArtifactRead,
            now(),
        )?;
        if now() >= task.created_at + 86400 {
            return Err("RESULT_EXPIRED".into());
        }
        let snapshot: Snapshot = serde_json::from_value(
            self.store
                .get_record("task_artifacts", &task.task_id)
                .await?
                .ok_or("ARTIFACTS_NOT_AVAILABLE")?,
        )?;
        if tool == "orc_artifacts_list" {
            return Ok(
                json!({"device_id":self.device_id,"task_id":task.task_id,"artifact_snapshot_id":snapshot.snapshot_id,"artifacts":snapshot.files.iter().map(|(path,b)|json!({"artifact_id":path,"bytes":b.size,"digest":b.digest})).collect::<Vec<_>>()}),
            );
        }
        let offset = args["offset"].as_u64().unwrap_or(0);
        let limit = args["limit"].as_u64().unwrap_or(65536);
        if limit > 65536 {
            return Err("READ_LIMIT_EXCEEDED".into());
        }
        let bytes = snapshot.read(
            field(args, "artifact_id")?,
            &self.objects,
            offset,
            limit as usize,
        )?;
        self.grant(&task.grant_id).await?.check_access(
            &principal.id(),
            &DeviceId(self.device_id.clone()),
            Action::ArtifactRead,
            now(),
        )?;
        Ok(
            json!({"device_id":self.device_id,"task_id":task.task_id,"offset":offset,"next_offset":offset+bytes.len() as u64,"bytes":bytes.len(),"text":String::from_utf8_lossy(&bytes),"untrusted":true}),
        )
    }
    async fn changes(
        &self,
        principal: &Principal,
        tool: &str,
        args: &Value,
    ) -> std::result::Result<Value, AnyError> {
        if tool == "orc_changes_get" {
            let stored = self
                .store
                .get_record("changes", field(args, "change_set_id")?)
                .await?
                .ok_or("CHANGES_UNKNOWN")?;
            if stored["principal_id"] != principal.id().0 {
                return Err("ACCESS_DENIED".into());
            }
            let grant = self.grant(field(&stored, "grant_id")?).await?;
            grant.check_access(
                &principal.id(),
                &DeviceId(self.device_id.clone()),
                Action::ChangesPropose,
                now(),
            )?;
            return Ok(stored);
        }
        let task = self
            .owned_task(principal, field(args, "task_id")?, false)
            .await?;
        let grant = self.grant(&task.grant_id).await?;
        grant.check_access(
            &principal.id(),
            &DeviceId(self.device_id.clone()),
            Action::ChangesPropose,
            now(),
        )?;
        if now() >= task.created_at.saturating_add(86400) {
            return Err("RESULT_EXPIRED".into());
        }
        if grant.environment != Environment::Isolated || task.execution_state != "exited" {
            return Err("CHANGES_REQUIRE_STOPPED_ISOLATED_TASK".into());
        }
        let operation = SubmissionId(field(args, "operation_id")?.into());
        let digest = orc_protocol::canonical_digest(args)?;
        let key = format!("{}:{}", principal.id(), operation);
        if let Some(old) = self.store.get_record("change_operation", &key).await? {
            if old["digest"] != digest {
                return Err("SUBMISSION_CONFLICT".into());
            }
            return self
                .store
                .get_record("changes", field(&old, "change_set_id")?)
                .await?
                .ok_or_else(|| "CHANGES_UNKNOWN".into());
        }
        let acceptance_deadline = args["request_expires_at"]
            .as_u64()
            .ok_or("request_expires_at required")?;
        operation.validate_fresh(now(), acceptance_deadline)?;
        let body: TaskBody = serde_json::from_value(task.payload)?;
        let baseline: Snapshot = serde_json::from_value(
            self.store
                .get_record(
                    "snapshot",
                    &body
                        .request
                        .context
                        .snapshot_id
                        .ok_or("SNAPSHOT_REQUIRED")?
                        .0,
                )
                .await?
                .ok_or("SNAPSHOT_UNKNOWN")?,
        )?;
        let artifact: Snapshot = serde_json::from_value(
            self.store
                .get_record("task_artifacts", &task.task_id)
                .await?
                .ok_or("ARTIFACTS_NOT_AVAILABLE")?,
        )?;
        let change =
            orc_workspace::ChangeSet::between(&baseline.workspace_id, &baseline, &artifact)?;
        let approval_id = format!("approval_{}", uuid::Uuid::now_v7());
        let effective = orc_protocol::canonical_digest(&(principal, &grant, &change))?;
        let record = json!({"change_set_id":change.change_set_id,"principal_id":principal.id(),"grant_id":grant.id,"approval_id":approval_id,"effective_digest":effective,"grant_revision":grant.revision,"policy_revision":grant.policy.revision(),"changes":change});
        self.store
            .put_record("changes", field(&record, "change_set_id")?, record.clone())
            .await?;
        self.store
            .create_approval(StoredApproval {
                approval_id,
                grant_id: grant.id.0,
                effective_digest: effective,
                grant_revision: grant.revision,
                policy_revision: grant.policy.revision(),
                expires_at: (now() + 300).min(grant.expires_at),
                status: "pending".into(),
                consumed_by: None,
            })
            .await?;
        self.store
            .put_record(
                "change_operation",
                &key,
                json!({"digest":digest,"change_set_id":record["change_set_id"]}),
            )
            .await?;
        Ok(record)
    }
    async fn revoke_principal(&self, id: &str) -> std::result::Result<(), AnyError> {
        let _gate = self.gate.lock().await;
        self.store
            .put_record("revoked_principal", id, json!({"principal_id":id}))
            .await?;
        for grant in self.store.list_grants().await? {
            if grant.principal_id == id {
                self.store.revoke_grant(&grant.grant_id, now()).await?;
            }
        }
        Ok(())
    }
    pub async fn connect(self: Arc<Self>) -> std::result::Result<(), AnyError> {
        let mut delay = 1;
        loop {
            let result = self.session().await;
            self.connected
                .store(false, std::sync::atomic::Ordering::SeqCst);
            if result.is_err() {
                tracing::warn!(event = "mcp_control_lost");
            }
            tokio::time::sleep(Duration::from_secs(delay)).await;
            delay = (delay * 2).min(30);
        }
    }
    /// 建立并固定对端身份，持久同步撤销后才标记 connected 并处理签名请求。
    async fn session(&self) -> std::result::Result<(), AnyError> {
        if self.trust_revoked.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("MCP_TRUST_REVOKED".into());
        }
        let tcp = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect(&self.config.mcp_address),
        )
        .await??;
        let tls = tokio::time::timeout(
            Duration::from_secs(10),
            tokio_rustls::TlsConnector::from(orc_transport::tls_client(&self.config.tls)?).connect(
                rustls::pki_types::ServerName::try_from(self.config.mcp_server_name.clone())?,
                tcp,
            ),
        )
        .await??;
        let cert = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .ok_or("MCP_CERTIFICATE_MISSING")?;
        if orc_transport::certificate_digest(cert.as_ref()) != self.config.mcp_certificate_digest {
            return Err("MCP_CERTIFICATE_MISMATCH".into());
        }
        let (mut ws, _) = tokio::time::timeout(
            Duration::from_secs(10),
            tokio_tungstenite::client_async_with_config(
                format!("wss://{}/endpoint/v1/connect", self.config.mcp_server_name),
                tls,
                Some(orc_transport::websocket_config()),
            ),
        )
        .await??;
        let hello = orc_transport::hello_frame(&self.identity)?;
        let nonce = match &hello {
            Frame::Hello { nonce, .. } => nonce.clone(),
            _ => return Err("INVALID_HELLO".into()),
        };
        orc_transport::send(&mut ws, &hello).await?;
        let sync = tokio::time::timeout(Duration::from_secs(10), orc_transport::receive(&mut ws))
            .await??;
        orc_transport::verify_sync(
            &sync,
            &self.config.mcp_id,
            &self.config.mcp_public_key,
            &nonce,
        )?;
        let (epoch, mut service_revision, revoked) = match &sync {
            Frame::Sync {
                epoch,
                service_revision,
                revoked_principals,
                ..
            } => (*epoch, *service_revision, revoked_principals.clone()),
            _ => return Err("SYNC_REQUIRED".into()),
        };
        // Ready 表示撤销已持久接收，所以必须在发 Ready 和开放请求处理之前完成。
        for principal in revoked {
            self.revoke_principal(&principal).await?;
        }
        orc_transport::send(&mut ws, &orc_transport::ready_frame(&self.identity, &sync)?).await?;
        self.connected
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let key = orc_transport::verifying_key(&self.config.mcp_public_key)?;
        let capabilities = orc_transport::capabilities();
        let mut last_seen = tokio::time::Instant::now();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut work = tokio::task::JoinSet::new();
        loop {
            // 优先检查信任/心跳，再接收控制帧；业务处理放入有界 JoinSet，
            // 避免单个工具调用占住读循环而阻塞撤销消息。
            tokio::select! { biased;
                _ = tick.tick() => {
                    if self.trust_revoked.load(std::sync::atomic::Ordering::SeqCst) {
                        return Err("MCP_TRUST_REVOKED".into())
                    }
                    if last_seen.elapsed() > Duration::from_secs(15) {
                        return Err("CONTROL_LOST".into())
                    }
                }
                frame = orc_transport::receive(&mut ws) => {
                    match frame? {
                        Frame::Ping { sequence } => {
                            last_seen = tokio::time::Instant::now();
                            orc_transport::send(&mut ws, &Frame::Pong { sequence }).await?;
                        }
                        Frame::Revoke { principal_id, revision } => {
                            if revision < service_revision {
                                return Err("SERVICE_REVISION_ROLLBACK".into())
                            }
                            // ACK 只确认持久撤销；停止核实由 supervise 独立推进。
                            self.revoke_principal(&principal_id).await?;
                            service_revision = revision;
                            orc_transport::send(
                                &mut ws,
                                &Frame::RevokeAck { principal_id, revision }
                            ).await?;
                        },
                        Frame::MaintenanceProbe { id } => {
                            let mut result = self.maintenance_status().await?;
                            result["unresolved_tasks"] = json!(
                                result["unresolved_tasks"].as_u64().unwrap_or(0) + work.len() as u64
                            );
                            orc_transport::send(
                                &mut ws,
                                &Frame::Response { id, result: Some(result), error: None }
                            ).await?;
                        }
                        Frame::Request { id, envelope } => {
                            envelope.verify(&key, &orc_protocol::EnvelopeContext {
                                mcp_id: &McpId(self.config.mcp_id.clone()),
                                device_id: &DeviceId(self.device_id.clone()),
                                connection_epoch: epoch,
                                service_policy_revision: service_revision,
                                capabilities: &capabilities,
                                now: now()
                            })?;
                            if work.len() >= 8 {
                                orc_transport::send(
                                    &mut ws,
                                    &Frame::Response {
                                        id, result: None, error: Some("DEVICE_BUSY".into())
                                    }
                                ).await?;
                                continue
                            }
                            let endpoint = self.clone();
                            work.spawn(async move {
                                let result = endpoint.invoke(
                                    envelope.payload.principal,
                                    &envelope.payload.operation,
                                    envelope.payload.request
                                ).await;
                                (id, result)
                            });
                        }
                        _ => return Err("INVALID_FRAME".into()),
                    }
                }
                completed = work.join_next(), if !work.is_empty() => {
                    if let Some(Ok((id, result))) = completed {
                        let frame = match result {
                            Ok(v) => Frame::Response { id, result: Some(v), error: None },
                            Err(e) => Frame::Response { id, result: None, error: Some(e.to_string()) }
                        };
                        orc_transport::send(&mut ws, &frame).await?;
                    }
                }
            }
        }
    }
    async fn maintenance_status(&self) -> std::result::Result<Value, AnyError> {
        let tasks = self.store.list_tasks(None).await?;
        let active = tasks
            .iter()
            .filter(|t| {
                matches!(
                    t.execution_state.as_str(),
                    "accepted" | "pending_approval" | "starting" | "running"
                )
            })
            .count();
        let unresolved = tasks
            .iter()
            .filter(|t| {
                t.execution_state == "unknown"
                    || matches!(t.stop_state.as_str(), "unknown" | "failed")
            })
            .count();
        Ok(
            json!({"maintenance":true,"active_tasks":active,"unresolved_tasks":unresolved,"state_schema":1}),
        )
    }
    async fn owner(&self, request: orc_admin::Request) -> std::result::Result<Value, AnyError> {
        let action = request.method.clone();
        let result = self.owner_inner(request).await;
        self.audit_operation(None, &action, &result).await;
        result
    }
    async fn audit_operation(
        &self,
        principal_id: Option<String>,
        action: &str,
        result: &std::result::Result<Value, AnyError>,
    ) {
        let action = match action {
            "orc_device_inspect"
            | "orc_policy_preview"
            | "orc_task_submit"
            | "orc_submission_get"
            | "orc_task_get"
            | "orc_task_list"
            | "orc_task_cancel"
            | "orc_task_output_read"
            | "orc_snapshot_list"
            | "orc_snapshot_read"
            | "orc_artifacts_list"
            | "orc_artifact_read"
            | "orc_changes_propose"
            | "orc_changes_get"
            | "status"
            | "grant.create"
            | "grant.list"
            | "grant.revoke"
            | "approval.show"
            | "approval.list"
            | "approval.approve"
            | "approval.reject"
            | "task.show"
            | "task.cancel"
            | "pause"
            | "resume"
            | "workspace.create"
            | "workspace.export"
            | "workspace.preview"
            | "workspace.approve"
            | "changes.show"
            | "changes.apply"
            | "data.cleanup"
            | "maintenance.prepare"
            | "maintenance.resume"
            | "uninstall.prepare"
            | "trust.revoke"
            | "trust.set" => action,
            _ => "unknown_operation",
        };
        // Never copy arguments, error messages, paths, output, or credentials.
        let task_id = result
            .as_ref()
            .ok()
            .and_then(|v| v["task_id"].as_str())
            .filter(|id| id.starts_with("task_") && id.len() <= 64)
            .map(str::to_owned);
        if self
            .store
            .audit(orc_store::AuditEvent {
                timestamp: now(),
                principal_id,
                device_id: Some(self.device_id.clone()),
                task_id,
                action: action.into(),
                outcome: if result.is_ok() {
                    "success"
                } else {
                    "rejected"
                }
                .into(),
            })
            .await
            .is_err()
        {
            tracing::warn!(event = "audit_unavailable");
        }
    }
    async fn prepare_maintenance(&self) -> std::result::Result<Value, AnyError> {
        let _gate = self.gate.lock().await;
        self.store
            .put_record("config", "maintenance", json!(true))
            .await?;
        self.maintenance
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut status = self.maintenance_status().await?;
        if status["active_tasks"] == 0 && status["unresolved_tasks"] == 0 {
            let backup = self.config.state_dir.join(format!(
                "maintenance-backup-{}.sqlite3",
                uuid::Uuid::now_v7()
            ));
            self.store.backup(&backup).await?;
            status["backup_path"] = val(backup)?;
        }
        Ok(status)
    }
    async fn owner_inner(
        &self,
        request: orc_admin::Request,
    ) -> std::result::Result<Value, AnyError> {
        match request.method.as_str() {
            "trust.revoke" => self.trust_revoke().await,
            "trust.set" => self.trust_set(request.params).await,
            "data.cleanup" => self.cleanup_expired().await,
            "maintenance.prepare" => self.prepare_maintenance().await,
            "uninstall.prepare" => {
                self.trust_revoke().await?;
                let mut status = self.prepare_maintenance().await?;
                status["revocation_applied"] = json!(true);
                Ok(status)
            }
            "maintenance.resume" => {
                let _gate = self.gate.lock().await;
                let status = self.maintenance_status().await?;
                if status["unresolved_tasks"] != 0 {
                    return Err("UNRESOLVED_TASKS".into());
                }
                self.store
                    .put_record("config", "maintenance", json!(false))
                    .await?;
                self.maintenance
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                Ok(json!({"maintenance":false}))
            }
            "status" => Ok(
                json!({"role":"endpoint","device_id":self.device_id,"public_key":self.identity.public_key()?,"mcp_id":self.config.mcp_id,"connected":self.connected.load(std::sync::atomic::Ordering::SeqCst),"paused":self.paused.load(std::sync::atomic::Ordering::SeqCst),"maintenance":self.maintenance.load(std::sync::atomic::Ordering::SeqCst),"trust_revoked":self.trust_revoked.load(std::sync::atomic::Ordering::SeqCst),"execution_uid":self.config.execution_uid}),
            ),
            "grant.create" => {
                let _gate = self.gate.lock().await;
                if self.trust_revoked.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err("MCP_TRUST_REVOKED".into());
                }
                let grant: Grant = serde_json::from_value(request.params)?;
                grant.validate()?;
                if grant.device_id.0 != self.device_id
                    || grant.execution_uid != self.config.execution_uid
                    || grant.issued_at > now()
                    || grant.expires_at <= now()
                {
                    return Err("INVALID_GRANT_CONTEXT".into());
                }
                if self.store.get_grant(&grant.id.0).await?.is_some() {
                    return Err("GRANT_EXISTS_CREATE_NEW_ID_FOR_CHANGED_AUTHORIZATION".into());
                }
                self.store
                    .put_grant(StoredGrant {
                        grant_id: grant.id.0.clone(),
                        principal_id: grant.principal_id.0.clone(),
                        device_id: grant.device_id.0.clone(),
                        revision: grant.revision,
                        expires_at: grant.expires_at,
                        status: "active".into(),
                        payload: val(&grant)?,
                    })
                    .await?;
                val(grant)
            }
            "grant.list" => val(self.store.list_grants().await?),
            "grant.revoke" => {
                let _gate = self.gate.lock().await;
                let tasks = self
                    .store
                    .revoke_grant(field(&request.params, "id")?, now())
                    .await?;
                Ok(
                    json!({"revoked":true,"stop_state":"requested","tasks":tasks.iter().map(|t|self.task_view(t)).collect::<std::result::Result<Vec<_>,_>>()?}),
                )
            }
            "approval.list" => val(self.store.list_approvals().await?),
            "approval.show" => {
                let id = field(&request.params, "id")?;
                let approval = self
                    .store
                    .get_approval(id)
                    .await?
                    .ok_or("APPROVAL_UNKNOWN")?;
                let tasks = self.store.list_tasks(None).await?;
                let task = tasks
                    .into_iter()
                    .find(|t| t.payload["approval_id"].as_str() == Some(id));
                let changes = self
                    .store
                    .list_records("changes")
                    .await?
                    .into_iter()
                    .find(|v| v["approval_id"].as_str() == Some(id));
                Ok(
                    json!({"approval":approval,"task":task,"changes":changes,"boundary":"approval fixes the entry bytes and explicit context; external dependencies and host side effects are not frozen"}),
                )
            }
            "approval.approve" | "approval.reject" => {
                let _gate = self.gate.lock().await;
                val(self
                    .store
                    .decide_approval(
                        field(&request.params, "id")?,
                        request.method == "approval.approve",
                        now(),
                    )
                    .await?)
            }
            "task.list" => {
                let mut views = vec![];
                for task in self.store.list_tasks(None).await? {
                    views.push(self.task_view(&task)?)
                }
                val(views)
            }
            "task.show" => self.task_view(
                &self
                    .store
                    .get_task(field(&request.params, "id")?)
                    .await?
                    .ok_or("TASK_UNKNOWN")?,
            ),
            "task.cancel" => {
                let _gate = self.gate.lock().await;
                let task = self
                    .store
                    .get_task(field(&request.params, "id")?)
                    .await?
                    .ok_or("TASK_UNKNOWN")?;
                self.request_stop(task, StopReason::Cancelled).await
            }
            "pause" => {
                let _gate = self.gate.lock().await;
                self.store
                    .put_record("config", "paused", json!(true))
                    .await?;
                self.paused.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(json!({"paused":true,"stop_state":"requested"}))
            }
            "resume" => {
                if self.trust_revoked.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err("MCP_TRUST_REVOKED".into());
                }
                let _gate = self.gate.lock().await;
                if self
                    .store
                    .list_tasks(None)
                    .await?
                    .iter()
                    .any(|t| matches!(t.stop_state.as_str(), "unknown" | "failed"))
                {
                    return Err("UNRESOLVED_STOP_EVIDENCE".into());
                }
                self.store
                    .put_record("config", "paused", json!(false))
                    .await?;
                self.paused
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                Ok(json!({"paused":false}))
            }
            "workspace.create" => {
                let root = field(&request.params, "path")?;
                let id = field(&request.params, "workspace_id")?;
                orc_workspace::ManagedWorkspace::create(root, id)?;
                self.store
                    .put_record("workspace", id, json!({"path":root,"managed":true}))
                    .await?;
                Ok(json!({"workspace_id":id,"path":root,"exclusive_contract":true}))
            }
            "workspace.approve" => {
                let _body_lock = self.body_lock.lock().await;
                let id = field(&request.params, "id")?;
                let snapshot: Snapshot = serde_json::from_value(
                    self.store
                        .get_record("snapshot_preview", id)
                        .await?
                        .ok_or("PREVIEW_UNKNOWN")?,
                )?;
                snapshot.verify()?;
                if snapshot.snapshot_id != id || now() >= snapshot.created_at.saturating_add(600) {
                    return Err("PREVIEW_EXPIRED".into());
                }
                // Approve the immutable preview, not a fresh read of a changing source.
                for object in snapshot.files.values() {
                    self.objects.read_all(object, 8 * 1024 * 1024)?;
                }
                self.store
                    .put_record("snapshot", id, val(&snapshot)?)
                    .await?;
                let mut response = val(&snapshot)?;
                response["approved"] = json!(true);
                response["expires_at"] = json!(snapshot.created_at.saturating_add(86400));
                Ok(response)
            }
            "workspace.preview" | "workspace.export" => {
                let preview = request.method == "workspace.preview";
                let _body_lock = self.body_lock.lock().await;
                let source = PathBuf::from(field(&request.params, "path")?);
                let id = field(&request.params, "workspace_id")?.to_string();
                let objects = self.objects.clone();
                let snapshot = tokio::task::spawn_blocking(move || {
                    if source.join(".orc-workspace.json").exists() {
                        let managed = orc_workspace::ManagedWorkspace::open(&source)?;
                        if managed.workspace_id() != id {
                            return Err(orc_workspace::WorkspaceError::IdentityChanged);
                        }
                        managed.export(&objects, &orc_workspace::Limits::default(), now())
                    } else {
                        Snapshot::export(
                            source,
                            &id,
                            &objects,
                            &orc_workspace::Limits::default(),
                            now(),
                        )
                    }
                })
                .await??;
                self.store
                    .put_record(
                        if preview {
                            "snapshot_preview"
                        } else {
                            "snapshot"
                        },
                        &snapshot.snapshot_id,
                        val(&snapshot)?,
                    )
                    .await?;
                let mut response = val(&snapshot)?;
                response["approved"] = json!(!preview);
                response["expires_at"] = json!(snapshot.created_at.saturating_add(86400));
                if preview {
                    response["approval_expires_at"] =
                        json!(snapshot.created_at.saturating_add(600));
                }
                Ok(response)
            }
            "changes.show" => self
                .store
                .get_record("changes", field(&request.params, "id")?)
                .await?
                .ok_or_else(|| "CHANGES_UNKNOWN".into()),
            "changes.apply" => self.apply_changes(field(&request.params, "id")?).await,
            _ => Err("UNKNOWN_ADMIN_METHOD".into()),
        }
    }
    /// 将本地审批映射为逐文件授权 guard，在阻塞文件操作期间保持授权锁存活。
    /// 回写可能部分完成；返回各文件结果，不能把整批再次提交当作故障恢复。
    async fn apply_changes(&self, id: &str) -> std::result::Result<Value, AnyError> {
        let record = self
            .store
            .get_record("changes", id)
            .await?
            .ok_or("CHANGES_UNKNOWN")?;
        if self.store.list_tasks(None).await?.iter().any(|t| {
            matches!(
                t.execution_state.as_str(),
                "starting" | "running" | "unknown"
            ) && t.stop_state != "confirmed"
        }) {
            return Err("WORKSPACE_NOT_EXCLUSIVE".into());
        }
        let changes: orc_workspace::ChangeSet = serde_json::from_value(record["changes"].clone())?;
        let workspace = self
            .store
            .get_record("workspace", &changes.workspace_id)
            .await?
            .ok_or("WORKSPACE_NOT_EXCLUSIVE")?;
        let root = PathBuf::from(field(&workspace, "path")?);
        let gate = self.gate.clone();
        let objects = self.objects.clone();
        let store = self.store.clone();
        let handle = tokio::runtime::Handle::current();
        let grant_id = field(&record, "grant_id")?.to_owned();
        let approval_id = field(&record, "approval_id")?.to_owned();
        let effective = field(&record, "effective_digest")?.to_owned();
        let grant_revision = record["grant_revision"].as_u64().ok_or("INVALID_RECORD")?;
        let policy_revision = record["policy_revision"].as_u64().ok_or("INVALID_RECORD")?;
        let operation = id.to_owned();
        let paused = self.paused.clone();
        let trust_revoked = self.trust_revoked.clone();
        let report = tokio::task::spawn_blocking(move || -> std::result::Result<_, AnyError> {
            let managed = orc_workspace::ManagedWorkspace::open(root)?;
            let result = managed.apply(&changes, &objects, &changes.change_set_id, |check| {
                handle.block_on(async {
                    let authorization = gate.clone().lock_owned().await;
                    if paused.load(std::sync::atomic::Ordering::SeqCst)
                        || trust_revoked.load(std::sync::atomic::Ordering::SeqCst)
                    {
                        return Err(orc_workspace::WorkspaceError::Revoked);
                    }
                    if store
                        .list_tasks(None)
                        .await
                        .map_err(|_| orc_workspace::WorkspaceError::NotExclusive)?
                        .iter()
                        .any(|t| {
                            matches!(
                                t.execution_state.as_str(),
                                "starting" | "running" | "unknown"
                            ) && t.stop_state != "confirmed"
                        })
                    {
                        return Err(orc_workspace::WorkspaceError::NotExclusive);
                    }
                    let grant = store
                        .get_grant(&grant_id)
                        .await
                        .map_err(|_| orc_workspace::WorkspaceError::Revoked)?
                        .ok_or(orc_workspace::WorkspaceError::Revoked)?;
                    if grant.status != "active"
                        || grant.revision != grant_revision
                        || grant.expires_at <= now()
                    {
                        return Err(orc_workspace::WorkspaceError::Revoked);
                    }
                    if matches!(check, orc_workspace::ApplyCheck::ConsumeApproval) {
                        store
                            .consume_change_approval(
                                &approval_id,
                                &effective,
                                grant_revision,
                                policy_revision,
                                &operation,
                                now(),
                            )
                            .await
                            .map_err(|_| orc_workspace::WorkspaceError::ApprovalInvalid)?;
                    }
                    // 把锁交给 ManagedWorkspace::apply 持有到实际文件修改结束；
                    // 若这里只返回 ()，检查通过到 rename/unlink 之间会留下撤销窗口。
                    Ok(authorization)
                })
            })?;
            Ok(result)
        })
        .await??;
        self.store
            .put_record("apply_result", id, val(&report)?)
            .await?;
        val(report)
    }
}
#[async_trait::async_trait]
impl orc_admin::Handler for Endpoint {
    async fn handle(&self, request: orc_admin::Request) -> orc_admin::Response {
        match self.owner(request).await {
            Ok(v) => orc_admin::Response::ok(v),
            Err(e) => orc_admin::Response::error(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests;

mod retention;
mod trust;

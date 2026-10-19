//! Rootless gVisor execution. All Docker control arguments originate in owner
//! configuration; task requests cannot change engine/runtime/image/mounts.
//! A matching M0 validation record is mandatory in addition to live probing.
use async_trait::async_trait;
use orc_execution::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageTool {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GvisorConfig {
    pub state_dir: PathBuf,
    pub socket: PathBuf,
    pub engine_data_root: PathBuf,
    pub runtime_name: String,
    pub runsc_path: PathBuf,
    pub runsc_sha256: String,
    pub image: String,
    pub image_digest: String,
    pub tools: BTreeMap<String, ImageTool>,
    pub scratch_root: PathBuf,
    pub scratch_mount_id: u64,
    pub approved_input: PathBuf,
    pub execution_uid: u32,
    pub container_uid: u32,
    pub container_gid: u32,
    pub validation_record: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationRecord {
    pub engine_version: String,
    pub kernel_release: String,
    pub runsc_sha256: String,
    pub image_digest: String,
    pub engine_data_root: PathBuf,
    pub scratch_mount_id: u64,
    pub checks: BTreeMap<String, bool>,
    pub checked_at_ms: u64,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CleanupStage {
    Stopped,
    ScratchRemoved,
    Complete,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupReceipt {
    version: u32,
    instance: InstanceRef,
    stage: CleanupStage,
    stop_confirmed_at_ms: u64,
    recorded_at_ms: u64,
}
fn read_cleanup_receipt(
    instance: &InstanceRef,
    name: &str,
) -> Result<Option<CleanupReceipt>, BackendError> {
    let path = instance.directory.join(name);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(BackendError::Invalid(
            "cleanup evidence is not a regular owner record".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::getuid() } {
            return Err(BackendError::Invalid(
                "cleanup evidence must be private to the execution owner".into(),
            ));
        }
    }
    let receipt: CleanupReceipt = read_json(&path, MAX_SPEC)?;
    let runtime: InstanceRef = read_json(&instance.directory.join("runtime.json"), MAX_SPEC)?;
    let base: InstanceRef = read_json(&instance.directory.join("instance.json"), MAX_SPEC)?;
    let same_intent = |record: &InstanceRef| {
        record.task_id == instance.task_id
            && record.backend == instance.backend
            && record.runtime_id == instance.runtime_id
            && record.boot_id == instance.boot_id
            && record.directory == instance.directory
            && record.spec_digest == instance.spec_digest
            && record.deadline_unix_ms == instance.deadline_unix_ms
    };
    if receipt.version != 1
        || receipt.instance != runtime
        || !same_intent(&runtime)
        || !same_intent(&base)
        || runtime.invocation_id.len() != 64
        || !runtime.invocation_id.bytes().all(|b| b.is_ascii_hexdigit())
        || (!instance.invocation_id.is_empty() && instance.invocation_id != runtime.invocation_id)
        || receipt.stop_confirmed_at_ms == 0
        || receipt.recorded_at_ms < receipt.stop_confirmed_at_ms
        || (name == "cleanup.json" && receipt.stage != CleanupStage::Complete)
    {
        return Err(BackendError::Invalid(
            "cleanup evidence is not bound to the original runtime and task".into(),
        ));
    }
    Ok(Some(receipt))
}
fn persist_cleanup_complete(mut receipt: CleanupReceipt) -> Result<(), BackendError> {
    receipt.stage = CleanupStage::Complete;
    receipt.recorded_at_ms = unix_ms().max(receipt.stop_confirmed_at_ms);
    let path = receipt.instance.directory.join("cleanup.json");
    match write_new_json(&path, &receipt) {
        Ok(()) => Ok(()),
        Err(BackendError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            read_cleanup_receipt(&receipt.instance, "cleanup.json")?
                .ok_or_else(|| BackendError::Unknown("cleanup evidence disappeared".into()))?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}
pub struct GvisorBackend {
    config: GvisorConfig,
}
const REQUIRED_CHECKS: &[&str] = &[
    "network_ipv4_ipv6_dns_host_metadata_blocked",
    "memory_cpu_cgroup_enforced",
    "guest_process_thread_limit_enforced",
    "runtime_tasks_limit_enforced",
    "scratch_capacity_enforced",
    "whole_sandbox_stop_confirmed",
    "stopped_artifacts_stable",
];
impl GvisorBackend {
    pub fn new(config: GvisorConfig) -> Self {
        Self { config }
    }
    fn validate_config(&self) -> Result<(), BackendError> {
        let c = &self.config;
        if !cfg!(target_os = "linux") {
            return Err(BackendError::Unavailable(
                "gVisor profile requires independently validated Linux rootless runtime".into(),
            ));
        }
        if c.execution_uid == 0
            || c.container_uid == 0
            || c.container_gid == 0
            || c.runtime_name != "runsc"
            || !c.image_digest.starts_with("sha256:")
            || c.image_digest.len() != 71
            || !c.image.ends_with(&format!("@{}", c.image_digest))
        {
            return Err(BackendError::Invalid(
                "non-root identity, fixed runsc runtime and digest-pinned image are required"
                    .into(),
            ));
        }
        for p in [
            &c.state_dir,
            &c.socket,
            &c.engine_data_root,
            &c.runsc_path,
            &c.scratch_root,
            &c.approved_input,
            &c.validation_record,
        ] {
            if !p.is_absolute() || p.to_string_lossy().contains([',', '\n', '\r']) {
                return Err(BackendError::Invalid(
                    "configured paths must be absolute and unambiguous".into(),
                ));
            }
        }
        if c.socket == Path::new("/var/run/docker.sock") {
            return Err(BackendError::Invalid(
                "system/default Docker socket is prohibited".into(),
            ));
        }
        #[cfg(unix)]
        {
            if unsafe { libc::getuid() } != c.execution_uid {
                return Err(BackendError::Invalid(
                    "service UID differs from execution UID".into(),
                ));
            }
        }
        Ok(())
    }
    async fn docker(&self, mut args: Vec<String>) -> Result<String, BackendError> {
        let mut all = vec![
            "--host".into(),
            format!("unix://{}", self.config.socket.display()),
        ];
        all.append(&mut args);
        control_command("docker", &all, 10).await
    }
    fn check_validation_record(&self) -> Result<ValidationRecord, BackendError> {
        let record: ValidationRecord = read_json(&self.config.validation_record, 64 * 1024)
            .map_err(|_| {
                BackendError::CapabilityMissing(
                    "matching M0 gVisor validation record is missing; run owner environment checks"
                        .into(),
                )
            })?;
        if record.runsc_sha256 != self.config.runsc_sha256
            || record.image_digest != self.config.image_digest
            || record.engine_data_root != self.config.engine_data_root
            || record.scratch_mount_id != self.config.scratch_mount_id
            || REQUIRED_CHECKS
                .iter()
                .any(|k| record.checks.get(*k) != Some(&true))
        {
            return Err(BackendError::CapabilityMissing("isolation validation evidence does not match this exact profile or mandatory checks".into()));
        }
        if fs::read_to_string("/proc/sys/kernel/osrelease")?.trim() != record.kernel_release {
            return Err(BackendError::CapabilityMissing(
                "kernel changed since isolation validation".into(),
            ));
        }
        Ok(record)
    }
    fn check_scratch(&self) -> Result<(), BackendError> {
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        let found = mountinfo.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields.first().and_then(|s| s.parse::<u64>().ok()) == Some(self.config.scratch_mount_id)
                && fields.get(4) == Some(&self.config.scratch_root.to_string_lossy().as_ref())
                && line
                    .split_once(" - ")
                    .is_some_and(|(_, r)| r.starts_with("tmpfs "))
        });
        if !found {
            return Err(BackendError::CapabilityMissing(
                "scratch is not the recorded dedicated tmpfs mount".into(),
            ));
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStrExt;
            let path = std::ffi::CString::new(self.config.scratch_root.as_os_str().as_bytes())
                .map_err(|_| BackendError::Invalid("invalid scratch path".into()))?;
            let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let stats = unsafe { stats.assume_init() };
            if stats.f_blocks.saturating_mul(stats.f_frsize) > 768 * 1024 * 1024 {
                return Err(BackendError::CapabilityMissing(
                    "scratch pool exceeds validated 768 MiB capacity".into(),
                ));
            }
        }
        Ok(())
    }
    /// Resolve against the owner-pinned image manifest, never the host PATH.
    pub fn resolve_spec(&self, mut spec: ExecutionSpec) -> Result<ResolvedSpec, BackendError> {
        self.validate_config()?;
        spec.validate(unix_ms())?;
        if spec.execution_uid != self.config.execution_uid
            || !(spec.cwd == Path::new("/work") || spec.cwd.starts_with("/work/"))
            || spec
                .cwd
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
        {
            return Err(BackendError::Invalid(
                "isolated task must use its fixed UID and /work context".into(),
            ));
        }
        let key = match &spec.command {
            ExecutionCommand::Argv { program, .. } => program,
            ExecutionCommand::Script { interpreter, .. } => interpreter,
        };
        let tool=self.config.tools.get(key).or_else(||self.config.tools.values().find(|tool|tool.path==Path::new(key))).ok_or_else(||BackendError::CapabilityMissing("program absent from fixed offline environment; owner must prepare a new environment".into()))?;
        if !tool.path.is_absolute() || tool.sha256.len() != 64 {
            return Err(BackendError::Invalid("invalid image tool manifest".into()));
        }
        match &mut spec.command {
            ExecutionCommand::Argv { program, .. } => {
                *program = tool.path.to_string_lossy().into_owned()
            }
            ExecutionCommand::Script {
                interpreter,
                source_path,
                ..
            } => {
                *interpreter = tool.path.to_string_lossy().into_owned();
                if source_path.is_some() {
                    return Err(BackendError::Invalid("isolated script file must first be frozen from its approved snapshot into inline source".into()));
                }
            }
        }
        let entry = EntryIdentity {
            path: tool.path.clone(),
            device: 0,
            inode: 0,
            bytes: 0,
            modified_ns: 0,
            sha256: tool.sha256.clone(),
        };
        let environment_digest = Some(self.config.image_digest.clone());
        let digest = sha256(&serde_json::to_vec(&(
            &spec,
            &entry,
            0u64,
            0u64,
            &environment_digest,
        ))?);
        Ok(ResolvedSpec {
            spec,
            entry,
            cwd_device: 0,
            cwd_inode: 0,
            environment_digest,
            digest,
        })
    }
    fn check_instance_metadata(&self, instance: &InstanceRef) -> Result<(), BackendError> {
        self.validate_config()?;
        if instance.backend != BackendKind::Gvisor
            || instance.directory != self.config.state_dir.join(&instance.task_id)
            || instance.runtime_id != container_name(&instance.task_id)
        {
            return Err(BackendError::Invalid("container ownership mismatch".into()));
        }
        let record: InstanceRef = read_json(&instance.directory.join("instance.json"), MAX_SPEC)?;
        if record.runtime_id != instance.runtime_id
            || record.spec_digest != instance.spec_digest
            || record.task_id != instance.task_id
            || record.backend != instance.backend
            || record.boot_id != instance.boot_id
            || record.directory != instance.directory
            || record.deadline_unix_ms != instance.deadline_unix_ms
        {
            return Err(BackendError::Invalid(
                "persisted container ownership mismatch".into(),
            ));
        }
        Ok(())
    }
    fn check_instance(&self, instance: &InstanceRef) -> Result<(), BackendError> {
        self.check_instance_metadata(instance)?;
        if fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() != instance.boot_id {
            return Err(BackendError::Unknown(
                "container belongs to earlier boot; explicit reconciliation required".into(),
            ));
        }
        Ok(())
    }
    async fn inspect_container(
        &self,
        instance: &InstanceRef,
    ) -> Result<serde_json::Value, BackendError> {
        let value: serde_json::Value = serde_json::from_str(
            &self
                .docker(vec![
                    "inspect".into(),
                    "--type=container".into(),
                    if instance.invocation_id.is_empty() {
                        instance.runtime_id.clone()
                    } else {
                        instance.invocation_id.clone()
                    },
                ])
                .await?,
        )?;
        let item = value
            .as_array()
            .and_then(|a| a.first())
            .ok_or_else(|| BackendError::Unknown("container identity unavailable".into()))?;
        if !instance.invocation_id.is_empty()
            && item["Id"].as_str() != Some(&instance.invocation_id)
        {
            return Err(BackendError::Unknown("container ID changed".into()));
        }
        if item["Config"]["Labels"]["org.openremoteconnector.spec"].as_str()
            != Some(&instance.spec_digest)
            || item["HostConfig"]["Runtime"].as_str() != Some("runsc")
        {
            return Err(BackendError::Unknown(
                "container runtime or ownership changed".into(),
            ));
        }
        let id = item["Id"]
            .as_str()
            .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| BackendError::Unknown("invalid immutable container identity".into()))?;
        if instance.invocation_id.is_empty() {
            let mut recorded: InstanceRef =
                read_json(&instance.directory.join("runtime.json"), MAX_SPEC)?;
            self.check_instance_metadata(&recorded)?;
            if !recorded.invocation_id.is_empty() && recorded.invocation_id != id {
                return Err(BackendError::Unknown(
                    "recorded container identity changed".into(),
                ));
            }
            if recorded.invocation_id.is_empty() {
                recorded.invocation_id = id.into();
                write_json_atomic(&instance.directory.join("runtime.json"), &recorded)?;
            }
        }
        Ok(item.clone())
    }
    pub async fn collect_output(
        &self,
        instance: &InstanceRef,
    ) -> Result<RunnerResult, BackendError> {
        self.check_instance_metadata(instance)?;
        if instance.directory.join("result.json").exists() {
            return read_json(&instance.directory.join("result.json"), MAX_SPEC);
        }
        self.check_instance(instance)?;
        let _control = InstanceControl::lock(instance)?;
        let item = self.inspect_container(instance).await?;
        if item["State"]["Running"].as_bool() != Some(false)
            || item["State"]["Pid"].as_i64() != Some(0)
        {
            return Err(BackendError::Unknown(
                "output has not been fixed by a stopped container".into(),
            ));
        }
        let frames = instance.directory.join("output.frames");
        let errors = instance.directory.join("output.errors");
        remove_collection_temporary(&frames)?;
        remove_collection_temporary(&errors)?;
        let (_, _, truncated) = self
            .capture(
                vec![
                    "logs".into(),
                    item["Id"].as_str().unwrap_or_default().into(),
                ],
                &frames,
                &errors,
                40 * 1024 * 1024,
                10,
            )
            .await?;
        if truncated {
            return Err(BackendError::Invalid(
                "output transport exceeded bounded frame budget".into(),
            ));
        }
        let resolved: ResolvedSpec = read_json(&instance.directory.join("spec.json"), MAX_SPEC)?;
        let (result, complete) = parse_output_frames(
            &frames,
            &instance.directory,
            resolved.spec.output_limit_bytes,
        )?;
        let observed = item["State"]["ExitCode"].as_i64().map(|n| n as i32);
        let expected = result
            .exit_code
            .unwrap_or(if result.reason == "deadline" {
                124
            } else {
                125
            })
            .clamp(0, 255);
        if complete && observed != Some(expected) {
            return Err(BackendError::Unknown(
                "runner result does not match container exit evidence".into(),
            ));
        }
        fs::remove_file(frames)?;
        fs::remove_file(errors)?;
        write_new_json(&instance.directory.join("result.json"), &result)?;
        Ok(result)
    }
    /// Stop evidence precedes a separate, read-only, fixed-image collector. The
    /// host validates every frame and writes bounded text objects, never a tar.
    pub async fn collect_artifacts(
        &self,
        instance: &InstanceRef,
    ) -> Result<Vec<CollectedArtifact>, BackendError> {
        self.check_instance_metadata(instance)?;
        let manifest = instance.directory.join("artifacts.json");
        if manifest.exists() {
            return read_json(&manifest, MAX_SPEC);
        }
        self.check_instance(instance)?;
        let _control = InstanceControl::lock(instance)?;
        let item = self.inspect_container(instance).await?;
        if item["State"]["Running"].as_bool() != Some(false)
            || item["State"]["Pid"].as_i64() != Some(0)
        {
            return Err(BackendError::Unknown(
                "sandbox has not stopped; artifacts are not fixed".into(),
            ));
        }
        let frames = instance.directory.join("collector.frames");
        let errors = instance.directory.join("collector.stderr");
        let scratch = self.config.scratch_root.join(&instance.task_id);
        let collector_name = format!("orc-collect-{}", sha256(instance.task_id.as_bytes()));
        match write_new_json(
            &instance.directory.join("collector-attempt.json"),
            &collector_name,
        ) {
            Ok(()) => {}
            Err(BackendError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let old: String =
                    read_json(&instance.directory.join("collector-attempt.json"), 1024)?;
                if old != collector_name {
                    return Err(BackendError::Invalid("collector identity changed".into()));
                }
            }
            Err(error) => return Err(error),
        }
        remove_collection_temporary(&frames)?;
        remove_collection_temporary(&errors)?;
        let args = vec![
            "run".into(),
            "--rm".into(),
            "--name".into(),
            collector_name.clone(),
            "--runtime=runsc".into(),
            "--network=none".into(),
            "--read-only".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges".into(),
            format!(
                "--user={}:{}",
                self.config.container_uid, self.config.container_gid
            ),
            "--memory=256m".into(),
            "--pids-limit=64".into(),
            "--log-driver=none".into(),
            "--mount".into(),
            format!("type=bind,src={},dst=/work,readonly", scratch.display()),
            "--entrypoint=/usr/local/bin/orc-runner".into(),
            self.config.image.clone(),
            "collect".into(),
            "--directory".into(),
            "/work".into(),
        ];
        let capture = self
            .capture(args, &frames, &errors, 320 * 1024 * 1024, 30)
            .await;
        if capture.is_err() {
            let _ = self
                .docker(vec!["stop".into(), "--time=3".into(), collector_name])
                .await;
        }
        let (_, _, truncated) = capture?;
        if truncated {
            return Err(BackendError::Invalid(
                "artifact transport exceeded budget".into(),
            ));
        }
        let artifacts = parse_artifact_frames(&frames, &instance.directory.join("artifacts"))?;
        write_new_json(&manifest, &artifacts)?;
        fs::remove_file(frames)?;
        fs::remove_file(errors)?;
        Ok(artifacts)
    }
    async fn capture(
        &self,
        mut args: Vec<String>,
        stdout: &Path,
        stderr: &Path,
        budget: u64,
        timeout_secs: u64,
    ) -> Result<(u64, u64, bool), BackendError> {
        use std::{
            process::Stdio,
            sync::{
                Arc,
                atomic::{AtomicBool, AtomicU64, Ordering},
            },
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut all = vec![
            "--host".into(),
            format!("unix://{}", self.config.socket.display()),
        ];
        all.append(&mut args);
        let mut child = tokio::process::Command::new("docker")
            .args(all)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let remaining = Arc::new(AtomicU64::new(budget));
        let truncated = Arc::new(AtomicBool::new(false));
        async fn drain<R: tokio::io::AsyncRead + Unpin>(
            mut input: R,
            output: PathBuf,
            remaining: Arc<AtomicU64>,
            truncated: Arc<AtomicBool>,
        ) -> Result<u64, BackendError> {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut output = tokio::fs::File::from_std(options.open(output)?);
            let mut count = 0;
            let mut buf = [0; 16 * 1024];
            loop {
                let n = input.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let available = remaining
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                        Some(v.saturating_sub(n as u64))
                    })
                    .unwrap_or(0);
                let retained = available.min(n as u64) as usize;
                if retained < n {
                    truncated.store(true, Ordering::Relaxed);
                }
                if retained > 0 {
                    output.write_all(&buf[..retained]).await?;
                    count += retained as u64;
                }
            }
            output.sync_all().await?;
            Ok(count)
        }
        let out = tokio::spawn(drain(
            child
                .stdout
                .take()
                .ok_or_else(|| BackendError::Unknown("missing Docker stdout".into()))?,
            stdout.to_owned(),
            remaining.clone(),
            truncated.clone(),
        ));
        let err = tokio::spawn(drain(
            child
                .stderr
                .take()
                .ok_or_else(|| BackendError::Unknown("missing Docker stderr".into()))?,
            stderr.to_owned(),
            remaining,
            truncated.clone(),
        ));
        let status =
            match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), child.wait())
                .await
            {
                Ok(s) => s?,
                Err(_) => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    out.abort();
                    err.abort();
                    return Err(BackendError::Unknown(
                        "collector timed out; retain instance for reconciliation".into(),
                    ));
                }
            };
        let out = out
            .await
            .map_err(|_| BackendError::Unknown("Docker output reader failed".into()))??;
        let err = err
            .await
            .map_err(|_| BackendError::Unknown("Docker error reader failed".into()))??;
        if !status.success() {
            return Err(BackendError::Unavailable(
                "Docker output/collector operation failed".into(),
            ));
        }
        Ok((out, err, truncated.load(Ordering::Relaxed)))
    }
}
fn container_name(task: &str) -> String {
    format!("orc-task-{}", sha256(task.as_bytes()))
}
fn remove_collection_temporary(path: &Path) -> Result<(), BackendError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)?
        }
        Ok(_) => return Err(BackendError::Invalid("unsafe collection temporary".into())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
fn parse_output_frames(
    frames: &Path,
    directory: &Path,
    budget: u64,
) -> Result<(RunnerResult, bool), BackendError> {
    use std::io::{BufRead, Read, Write};
    let mut input = std::io::BufReader::new(fs::File::open(frames)?);
    let mut out_options = fs::OpenOptions::new();
    out_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        out_options.mode(0o600);
    }
    let stdout_temp = directory.join("stdout.collecting");
    let stderr_temp = directory.join("stderr.collecting");
    remove_collection_temporary(&stdout_temp)?;
    remove_collection_temporary(&stderr_temp)?;
    let mut stdout = out_options.open(&stdout_temp)?;
    let mut stderr = out_options.open(&stderr_temp)?;
    let mut out_bytes = 0u64;
    let mut err_bytes = 0u64;
    let mut result = None;
    loop {
        let mut line = Vec::new();
        let n = (&mut input)
            .take(128 * 1024 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        if n > 128 * 1024 || result.is_some() {
            return Err(BackendError::Invalid(
                "invalid output frame ordering or budget".into(),
            ));
        }
        if line.last() != Some(&b'\n') {
            // A confirmed stopped runner may have been killed in the middle of
            // its last bounded frame. Preserve only complete preceding frames.
            break;
        }
        match serde_json::from_slice::<OutputFrame>(&line)? {
            OutputFrame::Chunk { stream, bytes } => {
                if bytes.len() > 16 * 1024 || out_bytes + err_bytes + bytes.len() as u64 > budget {
                    return Err(BackendError::Invalid(
                        "output retention budget exceeded".into(),
                    ));
                }
                match stream.as_str() {
                    "stdout" => {
                        stdout.write_all(&bytes)?;
                        out_bytes += bytes.len() as u64;
                    }
                    "stderr" => {
                        stderr.write_all(&bytes)?;
                        err_bytes += bytes.len() as u64;
                    }
                    _ => return Err(BackendError::Invalid("unknown output stream".into())),
                }
            }
            OutputFrame::Complete { result: complete } => {
                if complete.stdout_bytes != out_bytes || complete.stderr_bytes != err_bytes {
                    return Err(BackendError::Invalid(
                        "output byte counts do not match trusted framing".into(),
                    ));
                }
                result = Some(complete);
            }
        }
    }
    stdout.sync_all()?;
    stderr.sync_all()?;
    let complete = result.is_some();
    let result = result.unwrap_or_else(|| RunnerResult {
        exit_code: None,
        reason: "supervisor_lost".into(),
        stdout_bytes: out_bytes,
        stderr_bytes: err_bytes,
        output_truncated: true,
        finished_at_ms: unix_ms(),
    });
    fs::rename(stdout_temp, directory.join("stdout"))?;
    fs::rename(stderr_temp, directory.join("stderr"))?;
    fs::File::open(directory)?.sync_all()?;
    Ok((result, complete))
}

fn parse_artifact_frames(
    frames: &Path,
    output: &Path,
) -> Result<Vec<CollectedArtifact>, BackendError> {
    use std::io::{BufRead, Read, Write};
    private_dir(output)?;
    let mut input = std::io::BufReader::new(fs::File::open(frames)?);
    let mut artifacts = Vec::new();
    let mut active: Option<(String, u64, String, Vec<u8>)> = None;
    let mut total = 0u64;
    let mut seen = std::collections::BTreeSet::new();
    let mut done = false;
    loop {
        let mut line = Vec::new();
        let n = (&mut input)
            .take(128 * 1024 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        if n > 128 * 1024 || line.last() != Some(&b'\n') {
            return Err(BackendError::Invalid(
                "oversized or incomplete artifact frame".into(),
            ));
        }
        if done {
            return Err(BackendError::Invalid("data after artifact end".into()));
        }
        match serde_json::from_slice::<ArtifactFrame>(&line)? {
            ArtifactFrame::File {
                path,
                bytes,
                sha256: hash,
            } => {
                let relative = Path::new(&path);
                if active.is_some()
                    || bytes > 8 * 1024 * 1024
                    || artifacts.len() >= 1000
                    || total.saturating_add(bytes) > 64 * 1024 * 1024
                    || path.is_empty()
                    || path.chars().any(|c| c.is_control())
                    || path.contains('\\')
                    || relative
                        .components()
                        .any(|c| !matches!(c, std::path::Component::Normal(_)))
                    || !seen.insert(path.clone())
                {
                    return Err(BackendError::Invalid(
                        "invalid artifact name, order, or budget".into(),
                    ));
                }
                total += bytes;
                active = Some((path, bytes, hash, Vec::new()));
            }
            ArtifactFrame::Chunk { bytes } => {
                let (_, limit, _, data) = active
                    .as_mut()
                    .ok_or_else(|| BackendError::Invalid("chunk outside artifact".into()))?;
                if bytes.len() > 16 * 1024 || data.len() + bytes.len() > *limit as usize {
                    return Err(BackendError::Invalid(
                        "artifact byte budget exceeded".into(),
                    ));
                }
                data.extend_from_slice(&bytes);
            }
            ArtifactFrame::End => {
                let (path, length, hash, data) = active
                    .take()
                    .ok_or_else(|| BackendError::Invalid("artifact end without file".into()))?;
                if data.len() as u64 != length
                    || sha256(&data) != hash
                    || data.contains(&0)
                    || std::str::from_utf8(&data).is_err()
                {
                    return Err(BackendError::Invalid(
                        "invalid artifact text or digest".into(),
                    ));
                }
                // Store by digest under a private, flat object directory. Untrusted
                // paths remain manifest data and never become host paths.
                let local = output.join(&hash);
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                match options.open(&local) {
                    Ok(mut file) => {
                        file.write_all(&data)?;
                        file.sync_all()?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        if sha256(&fs::read(&local)?) != hash {
                            return Err(BackendError::Invalid("artifact object collision".into()));
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
                artifacts.push(CollectedArtifact {
                    path,
                    bytes: length,
                    sha256: hash,
                    local_path: local,
                });
            }
            ArtifactFrame::Done => {
                if active.is_some() {
                    return Err(BackendError::Invalid("unterminated artifact".into()));
                }
                done = true;
            }
        }
    }
    if !done {
        return Err(BackendError::Invalid(
            "artifact stream ended without completion".into(),
        ));
    }
    Ok(artifacts)
}

#[async_trait]
impl ExecutionBackend for GvisorBackend {
    async fn probe(&self) -> Result<Capabilities, BackendError> {
        self.validate_config()?;
        let validation = self.check_validation_record()?;
        self.check_scratch()?;
        let runtime = fs::read(&self.config.runsc_path)?;
        if sha256(&runtime) != self.config.runsc_sha256 {
            return Err(BackendError::CapabilityMissing(
                "runsc executable digest changed".into(),
            ));
        }
        let info: serde_json::Value = serde_json::from_str(
            &self
                .docker(vec!["info".into(), "--format".into(), "{{json .}}".into()])
                .await?,
        )?;
        if !info["SecurityOptions"].as_array().is_some_and(|a| {
            a.iter()
                .any(|v| v.as_str().is_some_and(|s| s.contains("rootless")))
        }) || info["CgroupVersion"].as_str() != Some("2")
            || info["CgroupDriver"].as_str() != Some("systemd")
            || info["DockerRootDir"].as_str() != self.config.engine_data_root.to_str()
        {
            return Err(BackendError::CapabilityMissing(
                "dedicated rootless cgroup-v2/systemd engine identity mismatch".into(),
            ));
        }
        if info["ServerVersion"].as_str() != Some(validation.engine_version.as_str()) {
            return Err(BackendError::CapabilityMissing(
                "Docker engine changed since isolation validation".into(),
            ));
        }
        let runsc = &info["Runtimes"]["runsc"];
        if runsc["path"].as_str().or_else(|| runsc["Path"].as_str())
            != self.config.runsc_path.to_str()
        {
            return Err(BackendError::CapabilityMissing(
                "engine runsc path differs from the verified executable".into(),
            ));
        }
        let args = runsc["runtimeArgs"]
            .as_array()
            .or_else(|| runsc["Args"].as_array());
        if !args.is_some_and(|a| {
            a.len() == 2
                && ["--platform=systrap", "--network=none"]
                    .iter()
                    .all(|x| a.iter().any(|v| v.as_str() == Some(x)))
        }) {
            return Err(BackendError::CapabilityMissing(
                "runsc must explicitly use systrap and network=none".into(),
            ));
        }
        let image: serde_json::Value = serde_json::from_str(
            &self
                .docker(vec![
                    "image".into(),
                    "inspect".into(),
                    self.config.image.clone(),
                ])
                .await?,
        )?;
        if !image
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v["RepoDigests"].as_array())
            .is_some_and(|a| {
                a.iter().any(|v| {
                    v.as_str()
                        .is_some_and(|s| s.ends_with(&format!("@{}", self.config.image_digest)))
                })
            })
        {
            return Err(BackendError::CapabilityMissing(
                "fixed offline image is not prepared".into(),
            ));
        }
        Ok(Capabilities{available:true,platform:"linux-rootless-gvisor".into(),checked_at_ms:unix_ms(),limits:BTreeMap::from([
            ("filesystem_isolation".into(),Enforcement::Enforced),("network_isolation".into(),Enforcement::Enforced),("cpu".into(),Enforcement::Enforced),("memory".into(),Enforcement::Enforced),("guest_processes".into(),Enforcement::Enforced),("scratch".into(),Enforcement::Enforced)]),evidence:vec!["exact local M0 validation record matched live engine/runtime/image/scratch identity".into(),"Docker CLI adapter; Ubuntu integration remains a release gate".into()]})
    }
    async fn prepare(&self, resolved: ResolvedSpec) -> Result<PreparedInstance, BackendError> {
        self.probe().await?;
        resolved.validate_digest()?;
        resolved.spec.validate(unix_ms())?;
        if resolved.environment_digest.as_deref() != Some(&self.config.image_digest) {
            return Err(BackendError::Invalid(
                "spec was not resolved against this isolated environment".into(),
            ));
        }
        private_dir(&self.config.state_dir)?;
        let directory = self.config.state_dir.join(&resolved.spec.task_id);
        fs::create_dir(&directory)?;
        private_dir(&directory)?;
        let mut instance = InstanceRef {
            task_id: resolved.spec.task_id.clone(),
            backend: BackendKind::Gvisor,
            runtime_id: container_name(&resolved.spec.task_id),
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .into(),
            invocation_id: String::new(),
            cgroup_path: String::new(),
            directory: directory.clone(),
            spec_digest: resolved.digest.clone(),
            deadline_unix_ms: resolved.spec.deadline_unix_ms,
        };
        write_new_json(&instance.directory.join("spec.json"), &resolved)?;
        write_new_json(&instance.directory.join("instance.json"), &instance)?;
        write_new_json(&instance.directory.join("runtime.json"), &instance)?;
        write_new_json(
            &instance.directory.join("prepare-attempt.json"),
            &instance.spec_digest,
        )?;
        refresh_lease(&instance)?;
        let control = InstanceControl::lock(&instance)?;
        control.ensure_launch_allowed()?;
        // A fixed trusted helper runs with the mapped workload UID to prepare
        // task copies in the installer-owned tmpfs pool. It cannot execute tasks.
        let helper_name = format!("orc-prepare-{}", sha256(resolved.spec.task_id.as_bytes()));
        write_new_json(&directory.join("helper-attempt.json"), &helper_name)?;
        let helper = self
            .docker(vec![
                "run".into(),
                "--rm".into(),
                "--name".into(),
                helper_name.clone(),
                "--runtime=runsc".into(),
                "--network=none".into(),
                "--read-only".into(),
                "--cap-drop=ALL".into(),
                "--security-opt=no-new-privileges".into(),
                format!(
                    "--user={}:{}",
                    self.config.container_uid, self.config.container_gid
                ),
                "--memory=256m".into(),
                "--pids-limit=64".into(),
                "--log-driver=none".into(),
                "--mount".into(),
                format!(
                    "type=bind,src={},dst=/pool",
                    self.config.scratch_root.display()
                ),
                "--mount".into(),
                format!(
                    "type=bind,src={},dst=/input,readonly",
                    self.config.approved_input.display()
                ),
                "--entrypoint=/usr/local/bin/orc-runner".into(),
                self.config.image.clone(),
                "prepare-scratch".into(),
                "--directory".into(),
                format!("/pool/{}", resolved.spec.task_id),
            ])
            .await;
        if helper.is_err() {
            let _ = self
                .docker(vec!["stop".into(), "--time=3".into(), helper_name])
                .await;
        }
        helper?;
        write_new_json(&directory.join("helper-complete.json"), &true)?;
        let request = SandboxRequest {
            spec: resolved.spec.clone(),
            expected_entry_sha256: resolved.entry.sha256.clone(),
            expected_entry_path: resolved.entry.path.clone(),
            image_digest: self.config.image_digest.clone(),
            guest_process_limit: 128,
        };
        write_new_json(&instance.directory.join("request.json"), &request)?;
        // Only this per-task file is mounted. Its private parent remains 0700 on
        // the host; read permission permits the mapped non-root container UID.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                instance.directory.join("request.json"),
                fs::Permissions::from_mode(0o444),
            )?;
        }
        // Rootless UID mappings must be established by environment preparation.
        // Never chmod the state directory broadly or import host credentials.
        let scratch = self.config.scratch_root.join(&instance.task_id);
        let args = vec![
            "create".into(),
            "--name".into(),
            instance.runtime_id.clone(),
            "--runtime=runsc".into(),
            "--network=none".into(),
            format!(
                "--user={}:{}",
                self.config.container_uid, self.config.container_gid
            ),
            "--read-only".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges".into(),
            "--pids-limit=512".into(),
            "--cpus=2".into(),
            "--memory=2g".into(),
            "--memory-swap=2g".into(),
            "--restart=no".into(),
            "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777".into(),
            "--shm-size=64m".into(),
            "--log-driver=local".into(),
            "--log-opt=max-size=40m".into(),
            "--log-opt=max-file=1".into(),
            "--mount".into(),
            format!(
                "type=bind,src={},dst=/orc/request.json,readonly",
                instance.directory.join("request.json").display()
            ),
            "--mount".into(),
            format!(
                "type=bind,src={},dst=/input,readonly",
                self.config.approved_input.display()
            ),
            "--mount".into(),
            format!("type=bind,src={},dst=/work", scratch.display()),
            "--label".into(),
            format!("org.openremoteconnector.spec={}", instance.spec_digest),
            "--entrypoint=/usr/local/bin/orc-runner".into(),
            self.config.image.clone(),
            "sandbox".into(),
            "--directory".into(),
            "/orc".into(),
        ];
        let id = self.docker(args).await.map_err(|_| {
            BackendError::Unknown(
                "container create outcome unknown; reconcile original name without repeating start"
                    .into(),
            )
        })?;
        if id.trim().len() != 64 || !id.trim().bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(BackendError::Unknown(
                "container create returned an invalid immutable identity".into(),
            ));
        }
        instance.invocation_id = id.trim().into();
        write_json_atomic(&instance.directory.join("runtime.json"), &instance)?;
        refresh_lease(&instance)?;
        Ok(PreparedInstance { resolved, instance })
    }
    async fn start(
        &self,
        prepared: PreparedInstance,
        permit: LaunchPermit,
    ) -> Result<InstanceRef, BackendError> {
        self.check_instance(&prepared.instance)?;
        let control = InstanceControl::lock(&prepared.instance)?;
        control.ensure_launch_allowed()?;
        prepared.resolved.spec.validate(unix_ms())?;
        permit.consume(&prepared)?;
        write_new_json(
            &prepared.instance.directory.join("launch-attempt.json"),
            &prepared.instance.spec_digest,
        )?;
        let instance = prepared.instance;
        refresh_lease(&instance)?;
        self.docker(vec!["start".into(), instance.invocation_id.clone()])
            .await
            .map_err(|_| {
                BackendError::Unknown("container start outcome unknown; inspect original ID".into())
            })?;
        Ok(instance)
    }
    async fn inspect(&self, instance: &InstanceRef) -> Result<RuntimeEvidence, BackendError> {
        self.check_instance_metadata(instance)?;
        if let Some(receipt) = read_cleanup_receipt(instance, "cleanup.json")? {
            let result =
                read_json::<RunnerResult>(&instance.directory.join("result.json"), MAX_SPEC).ok();
            return Ok(RuntimeEvidence {
                state: RuntimeState::Exited,
                exit_code: result.and_then(|r| r.exit_code),
                checked_at_ms: receipt.recorded_at_ms,
                detail: "original sandbox has a durable, identity-bound cleanup receipt".into(),
            });
        }
        self.check_instance(instance)?;
        let item = self.inspect_container(instance).await?;
        let state = match item["State"]["Status"].as_str() {
            Some("created") => RuntimeState::Waiting,
            Some("running" | "restarting" | "paused") => RuntimeState::Running,
            Some("exited" | "dead") => RuntimeState::Exited,
            _ => RuntimeState::Unknown,
        };
        let exit_code = if state == RuntimeState::Exited {
            item["State"]["ExitCode"].as_i64().map(|n| n as i32)
        } else {
            None
        };
        Ok(RuntimeEvidence {
            state,
            exit_code,
            checked_at_ms: unix_ms(),
            detail: "verified dedicated container identity; no automatic restart".into(),
        })
    }
    async fn stop(
        &self,
        instance: &InstanceRef,
        reason: StopReason,
    ) -> Result<StopEvidence, BackendError> {
        self.check_instance_metadata(instance)?;
        if let Some(receipt) = read_cleanup_receipt(instance, "cleanup.json")? {
            return Ok(StopEvidence{confirmed:true,checked_at_ms:receipt.stop_confirmed_at_ms,detail:"original sandbox was already stopped and removed; durable cleanup receipt verified".into()});
        }
        self.check_instance(instance)?;
        let control = InstanceControl::lock(instance)?;
        control.request_stop(reason)?;
        if !instance.directory.join("helper-complete.json").exists() {
            let expected = format!("orc-prepare-{}", sha256(instance.task_id.as_bytes()));
            let recorded: String =
                read_json(&instance.directory.join("helper-attempt.json"), 1024)?;
            if recorded != expected {
                return Err(BackendError::Invalid(
                    "preparation helper identity changed".into(),
                ));
            }
            // The prepare helper only copies approved input; it never executes
            // user commands. Still stop it when preparation was interrupted.
            let _ = self
                .docker(vec!["stop".into(), "--time=3".into(), expected])
                .await;
        }
        self.inspect_container(instance).await?;
        let _ = self
            .docker(vec![
                "stop".into(),
                "--time=3".into(),
                if instance.invocation_id.is_empty() {
                    instance.runtime_id.clone()
                } else {
                    instance.invocation_id.clone()
                },
            ])
            .await;
        let item = self.inspect_container(instance).await?;
        let confirmed = item["State"]["Running"].as_bool() == Some(false)
            && item["State"]["Pid"].as_i64() == Some(0);
        Ok(StopEvidence {
            confirmed,
            checked_at_ms: unix_ms(),
            detail: if confirmed {
                "engine confirms original sandbox stopped"
            } else {
                "sandbox termination remains unknown"
            }
            .into(),
        })
    }
    async fn cleanup(&self, instance: &InstanceRef) -> Result<(), BackendError> {
        self.check_instance_metadata(instance)?;
        if read_cleanup_receipt(instance, "cleanup.json")?.is_some() {
            return Ok(());
        }
        self.check_instance(instance)?;
        let previous = read_cleanup_receipt(instance, "cleanup-progress.json")?;
        let mut receipt = match previous {
            Some(receipt) => receipt,
            None => {
                let stopped = self.stop(instance, StopReason::EndpointPaused).await?;
                if !stopped.confirmed {
                    return Err(BackendError::Unknown(
                        "refusing cleanup before confirmed stop".into(),
                    ));
                }
                let runtime: InstanceRef =
                    read_json(&instance.directory.join("runtime.json"), MAX_SPEC)?;
                if runtime.invocation_id.len() != 64
                    || !runtime
                        .invocation_id
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(BackendError::Unknown(
                        "cleanup requires a recorded immutable container ID".into(),
                    ));
                }
                let receipt = CleanupReceipt {
                    version: 1,
                    instance: runtime,
                    stage: CleanupStage::Stopped,
                    stop_confirmed_at_ms: stopped.checked_at_ms,
                    recorded_at_ms: stopped.checked_at_ms,
                };
                write_new_json(&instance.directory.join("cleanup-progress.json"), &receipt)?;
                receipt
            }
        };
        if receipt.stage == CleanupStage::Stopped {
            self.check_scratch()?;
            // An absent task directory is a successful retry for the trusted
            // helper. A partial removal never triggers task execution.
            let helper_name = format!("orc-cleanup-{}", sha256(instance.task_id.as_bytes()));
            let cleanup = self
                .docker(vec![
                    "run".into(),
                    "--rm".into(),
                    "--name".into(),
                    helper_name.clone(),
                    "--runtime=runsc".into(),
                    "--network=none".into(),
                    "--read-only".into(),
                    "--cap-drop=ALL".into(),
                    "--security-opt=no-new-privileges".into(),
                    format!(
                        "--user={}:{}",
                        self.config.container_uid, self.config.container_gid
                    ),
                    "--memory=256m".into(),
                    "--cpus=2".into(),
                    "--pids-limit=64".into(),
                    "--log-driver=none".into(),
                    "--mount".into(),
                    format!(
                        "type=bind,src={},dst=/pool",
                        self.config.scratch_root.display()
                    ),
                    "--entrypoint=/usr/local/bin/orc-runner".into(),
                    self.config.image.clone(),
                    "cleanup-scratch".into(),
                    "--directory".into(),
                    format!("/pool/{}", instance.task_id),
                ])
                .await;
            if cleanup.is_err() {
                let _ = self
                    .docker(vec!["stop".into(), "--time=3".into(), helper_name])
                    .await;
            }
            cleanup?;
            receipt.stage = CleanupStage::ScratchRemoved;
            receipt.recorded_at_ms = unix_ms().max(receipt.stop_confirmed_at_ms);
            write_json_atomic(&instance.directory.join("cleanup-progress.json"), &receipt)?;
        }
        // Removal uses the recorded immutable ID, never a potentially reused
        // name. An ambiguous rm response is resolved with a successful bounded
        // engine listing; a failed inspection alone never proves absence.
        let _ = self
            .docker(vec!["rm".into(), receipt.instance.invocation_id.clone()])
            .await;
        let ids = self
            .docker(vec![
                "ps".into(),
                "--all".into(),
                "--no-trunc".into(),
                "--filter".into(),
                format!("id={}", receipt.instance.invocation_id),
                "--format".into(),
                "{{.ID}}".into(),
            ])
            .await?;
        if ids
            .lines()
            .any(|id| id.trim() == receipt.instance.invocation_id)
        {
            return Err(BackendError::Unknown(
                "original sandbox removal remains unconfirmed".into(),
            ));
        }
        persist_cleanup_complete(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_checks_required() {
        assert!(REQUIRED_CHECKS.contains(&"guest_process_thread_limit_enforced"));
        assert!(REQUIRED_CHECKS.contains(&"stopped_artifacts_stable"));
    }
    #[test]
    fn container_names_are_task_bound() {
        assert_ne!(container_name("a"), container_name("b"));
        assert!(!container_name("/bad;name").contains('/'));
    }
}

#[cfg(test)]
mod artifact_tests {
    use super::*;
    use std::io::Write;
    fn frames(items: Vec<ArtifactFrame>) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("frames");
        let mut f = fs::File::create(&path).unwrap();
        for item in items {
            serde_json::to_writer(&mut f, &item).unwrap();
            writeln!(f).unwrap();
        }
        (dir, path)
    }
    #[test]
    fn collects_verified_text_without_using_untrusted_paths() {
        let data = b"approved text";
        let (dir, path) = frames(vec![
            ArtifactFrame::File {
                path: "nested/report.txt".into(),
                bytes: data.len() as u64,
                sha256: sha256(data),
            },
            ArtifactFrame::Chunk {
                bytes: data.to_vec(),
            },
            ArtifactFrame::End,
            ArtifactFrame::Done,
        ]);
        let output = dir.path().join("objects");
        let artifacts = parse_artifact_frames(&path, &output).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(fs::read(&artifacts[0].local_path).unwrap(), data);
        assert!(!output.join("nested").exists());
    }
    #[test]
    fn rejects_path_traversal_and_missing_completion() {
        let (dir, path) = frames(vec![ArtifactFrame::File {
            path: "../secret".into(),
            bytes: 0,
            sha256: sha256(b""),
        }]);
        assert!(parse_artifact_frames(&path, &dir.path().join("objects")).is_err());
        let (dir, path) = frames(vec![]);
        assert!(parse_artifact_frames(&path, &dir.path().join("objects")).is_err());
    }
    #[test]
    fn rejects_tampered_digest() {
        let (dir, path) = frames(vec![
            ArtifactFrame::File {
                path: "a.txt".into(),
                bytes: 1,
                sha256: sha256(b"a"),
            },
            ArtifactFrame::Chunk {
                bytes: b"b".to_vec(),
            },
            ArtifactFrame::End,
            ArtifactFrame::Done,
        ]);
        assert!(parse_artifact_frames(&path, &dir.path().join("objects")).is_err());
    }
}

#[cfg(test)]
mod output_tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn output_framing_preserves_truncation_and_streams() {
        let dir = tempfile::tempdir().unwrap();
        let frames = dir.path().join("frames");
        let mut file = fs::File::create(&frames).unwrap();
        let result = RunnerResult {
            exit_code: Some(0),
            reason: "exit_zero".into(),
            stdout_bytes: 3,
            stderr_bytes: 2,
            output_truncated: true,
            finished_at_ms: 1,
        };
        for frame in [
            OutputFrame::Chunk {
                stream: "stdout".into(),
                bytes: b"out".to_vec(),
            },
            OutputFrame::Chunk {
                stream: "stderr".into(),
                bytes: b"er".to_vec(),
            },
            OutputFrame::Complete { result },
        ] {
            serde_json::to_writer(&mut file, &frame).unwrap();
            writeln!(file).unwrap();
        }
        let (result, complete) = parse_output_frames(&frames, dir.path(), 5).unwrap();
        assert!(complete);
        assert!(result.output_truncated);
        assert_eq!(fs::read(dir.path().join("stdout")).unwrap(), b"out");
        assert_eq!(fs::read(dir.path().join("stderr")).unwrap(), b"er");
    }
    #[test]
    fn incomplete_output_is_not_a_successful_result() {
        let dir = tempfile::tempdir().unwrap();
        let frames = dir.path().join("frames");
        fs::write(
            &frames,
            b"{\"type\":\"chunk\",\"stream\":\"stdout\",\"bytes\":[120]}\n",
        )
        .unwrap();
        let (result, complete) = parse_output_frames(&frames, dir.path(), 1).unwrap();
        assert!(!complete);
        assert_eq!(result.exit_code, None);
        assert_eq!(result.reason, "supervisor_lost");
        assert!(result.output_truncated);
        assert_eq!(fs::read(dir.path().join("stdout")).unwrap(), b"x");
        // Recovery can repeat parsing after a crash before result persistence.
        assert!(parse_output_frames(&frames, dir.path(), 1).is_ok());
    }
    #[test]
    fn killed_runner_retains_complete_frames_and_retry_does_not_duplicate_output() {
        let dir = tempfile::tempdir().unwrap();
        let frames = dir.path().join("frames");
        fs::write(&frames, b"{\"type\":\"chunk\",\"stream\":\"stdout\",\"bytes\":[120]}\n{\"type\":\"chunk\",\"bytes\":[121").unwrap();
        let (result, complete) = parse_output_frames(&frames, dir.path(), 2).unwrap();
        assert!(!complete);
        assert_eq!(result.stdout_bytes, 1);
        assert_eq!(result.exit_code, None);
        assert!(result.output_truncated);
        parse_output_frames(&frames, dir.path(), 2).unwrap();
        assert_eq!(fs::read(dir.path().join("stdout")).unwrap(), b"x");
    }
    #[test]
    fn corrupt_output_never_publishes_terminal_files_and_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let frames = dir.path().join("frames");
        fs::write(
            &frames,
            b"{\"type\":\"chunk\",\"stream\":\"unknown\",\"bytes\":[120]}\n",
        )
        .unwrap();
        assert!(parse_output_frames(&frames, dir.path(), 2).is_err());
        assert!(!dir.path().join("stdout").exists());
        fs::write(
            &frames,
            b"{\"type\":\"chunk\",\"stream\":\"stdout\",\"bytes\":[120]}\n",
        )
        .unwrap();
        assert!(parse_output_frames(&frames, dir.path(), 2).is_ok());
        assert_eq!(fs::read(dir.path().join("stdout")).unwrap(), b"x");
    }
}

#[cfg(test)]
mod cleanup_receipt_tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, InstanceRef, CleanupReceipt) {
        let dir = tempfile::tempdir().unwrap();
        let runtime = InstanceRef {
            task_id: "task-1".into(),
            backend: BackendKind::Gvisor,
            runtime_id: container_name("task-1"),
            boot_id: "original-boot".into(),
            invocation_id: "a".repeat(64),
            cgroup_path: String::new(),
            directory: dir.path().to_owned(),
            spec_digest: "b".repeat(64),
            deadline_unix_ms: 200,
        };
        let mut base = runtime.clone();
        base.invocation_id.clear();
        write_new_json(&dir.path().join("instance.json"), &base).unwrap();
        write_new_json(&dir.path().join("runtime.json"), &runtime).unwrap();
        let receipt = CleanupReceipt {
            version: 1,
            instance: runtime.clone(),
            stage: CleanupStage::Complete,
            stop_confirmed_at_ms: 100,
            recorded_at_ms: 110,
        };
        (dir, runtime, receipt)
    }
    #[test]
    fn complete_receipt_survives_retries_and_binds_authoritative_runtime() {
        let (_dir, instance, receipt) = fixture();
        persist_cleanup_complete(receipt.clone()).unwrap();
        persist_cleanup_complete(receipt).unwrap();
        let result = read_cleanup_receipt(&instance, "cleanup.json")
            .unwrap()
            .unwrap();
        assert!(result.stage == CleanupStage::Complete);
        assert_eq!(result.instance.invocation_id, instance.invocation_id);
        let mut provisional = instance.clone();
        provisional.invocation_id.clear();
        assert!(
            read_cleanup_receipt(&provisional, "cleanup.json")
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn boolean_or_unbound_marker_does_not_prove_cleanup() {
        let (dir, instance, _) = fixture();
        write_new_json(&dir.path().join("cleanup.json"), &true).unwrap();
        assert!(read_cleanup_receipt(&instance, "cleanup.json").is_err());
        fs::remove_file(dir.path().join("cleanup.json")).unwrap();
        let mut receipt = CleanupReceipt {
            version: 1,
            instance: instance.clone(),
            stage: CleanupStage::Complete,
            stop_confirmed_at_ms: 1,
            recorded_at_ms: 2,
        };
        receipt.instance.spec_digest = "other".into();
        write_new_json(&dir.path().join("cleanup.json"), &receipt).unwrap();
        assert!(read_cleanup_receipt(&instance, "cleanup.json").is_err());
    }
    #[test]
    fn different_container_or_boot_cannot_reuse_cleanup_receipt() {
        let (_dir, instance, receipt) = fixture();
        persist_cleanup_complete(receipt).unwrap();
        for changed in ["container", "boot", "task", "deadline"] {
            let mut requested = instance.clone();
            match changed {
                "container" => requested.invocation_id = "c".repeat(64),
                "boot" => requested.boot_id = "new-boot".into(),
                "task" => requested.task_id = "task-2".into(),
                _ => requested.deadline_unix_ms += 1,
            };
            assert!(read_cleanup_receipt(&requested, "cleanup.json").is_err());
        }
    }
    #[test]
    fn intermediate_progress_is_not_complete_stop_evidence() {
        let (dir, instance, mut receipt) = fixture();
        receipt.stage = CleanupStage::ScratchRemoved;
        write_new_json(&dir.path().join("cleanup-progress.json"), &receipt).unwrap();
        assert!(
            read_cleanup_receipt(&instance, "cleanup.json")
                .unwrap()
                .is_none()
        );
        assert!(
            read_cleanup_receipt(&instance, "cleanup-progress.json")
                .unwrap()
                .is_some()
        );
        write_new_json(&dir.path().join("cleanup.json"), &receipt).unwrap();
        assert!(read_cleanup_receipt(&instance, "cleanup.json").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn shared_or_symlinked_receipt_is_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (dir, instance, receipt) = fixture();
        persist_cleanup_complete(receipt).unwrap();
        let path = dir.path().join("cleanup.json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_cleanup_receipt(&instance, "cleanup.json").is_err());
        fs::rename(&path, dir.path().join("other")).unwrap();
        symlink(dir.path().join("other"), &path).unwrap();
        assert!(read_cleanup_receipt(&instance, "cleanup.json").is_err());
    }
}

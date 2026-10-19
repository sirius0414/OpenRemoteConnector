//! Linux host execution through systemd user units. The command-line adapter is
//! deliberately small and uses argv, never a shell. It is replaceable by zbus
//! without changing the endpoint/runner lifecycle contract.
use async_trait::async_trait;
use orc_execution::*;
use std::{collections::BTreeMap, fs, path::PathBuf};

#[derive(Clone)]
pub struct HostConfig {
    pub state_dir: PathBuf,
    pub runner_path: PathBuf,
    pub execution_uid: u32,
}
pub struct HostBackend {
    config: HostConfig,
}
impl HostBackend {
    pub fn new(config: HostConfig) -> Self {
        Self { config }
    }
    fn check_platform(&self) -> Result<(), BackendError> {
        if !cfg!(target_os = "linux") {
            return Err(BackendError::Unavailable(
                "host execution requires Linux/systemd; macOS execution is not implemented".into(),
            ));
        }
        #[cfg(unix)]
        {
            // SAFETY: getuid has no preconditions.
            let uid = unsafe { libc::getuid() };
            if uid == 0 || uid != self.config.execution_uid {
                return Err(BackendError::Invalid(
                    "configured execution UID does not match ordinary service UID".into(),
                ));
            }
        }
        if !self.config.runner_path.is_absolute() || !self.config.runner_path.is_file() {
            return Err(BackendError::Unavailable(
                "configured orc-runner executable is missing".into(),
            ));
        }
        Ok(())
    }
    fn validate_metadata(&self, instance: &InstanceRef) -> Result<(), BackendError> {
        self.check_platform()?;
        let expected = self.config.state_dir.join(&instance.task_id);
        if instance.backend != BackendKind::HostLinux
            || instance.directory != expected
            || instance.runtime_id != unit_name(&instance.task_id)
        {
            return Err(BackendError::Invalid("instance ownership mismatch".into()));
        }
        let recorded: InstanceRef = read_json(&expected.join("instance.json"), MAX_SPEC)?;
        if recorded.task_id != instance.task_id
            || recorded.spec_digest != instance.spec_digest
            || recorded.runtime_id != instance.runtime_id
            || recorded.backend != instance.backend
            || recorded.boot_id != instance.boot_id
            || recorded.directory != instance.directory
            || recorded.deadline_unix_ms != instance.deadline_unix_ms
        {
            return Err(BackendError::Invalid(
                "persisted instance ownership mismatch".into(),
            ));
        }
        Ok(())
    }
    fn current_boot(&self, instance: &InstanceRef) -> Result<bool, BackendError> {
        let current = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        if current.trim().is_empty() || instance.boot_id.is_empty() {
            return Err(BackendError::Unknown("boot identity unavailable".into()));
        }
        Ok(current.trim() == instance.boot_id)
    }
    fn validate_instance(&self, instance: &InstanceRef) -> Result<(), BackendError> {
        self.validate_metadata(instance)?;
        if !self.current_boot(instance)? {
            return Err(BackendError::Unknown(
                "instance belongs to an earlier boot; reconcile without restarting".into(),
            ));
        }
        Ok(())
    }
    async fn properties(&self, unit: &str) -> Result<BTreeMap<String, String>, BackendError> {
        let args=vec!["--user".into(),"show".into(),unit.into(),"--property=LoadState,ActiveState,SubState,InvocationID,ControlGroup,ExecMainCode,ExecMainStatus".into()];
        let output = match control_command("systemctl", &args, 5).await {
            Ok(output) => output,
            Err(_) => {
                // Successful transient services may already be unloaded. A
                // failed show is not proof of absence; require a successful
                // exact-name manager listing, then verify the recorded cgroup.
                let listed = control_command(
                    "systemctl",
                    &[
                        "--user".into(),
                        "list-units".into(),
                        "--all".into(),
                        "--plain".into(),
                        "--no-legend".into(),
                        "--no-pager".into(),
                        unit.into(),
                    ],
                    5,
                )
                .await?;
                if !listed.trim().is_empty() {
                    return Err(BackendError::Unknown(
                        "unit exists but its properties are unavailable".into(),
                    ));
                }
                return Ok(BTreeMap::from([
                    ("LoadState".into(), "not-found".into()),
                    ("ActiveState".into(), "inactive".into()),
                ]));
            }
        };
        Ok(output
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(k, v)| (k.into(), v.into()))
            .collect())
    }
    fn reconcile_identity(
        &self,
        instance: &InstanceRef,
        props: &BTreeMap<String, String>,
    ) -> Result<InstanceRef, BackendError> {
        let mut resolved = instance.clone();
        if resolved.invocation_id.is_empty()
            && let Some(id) = props.get("InvocationID").filter(|id| !id.is_empty())
            && let Some(group) = props.get("ControlGroup").filter(|group| !group.is_empty())
        {
            resolved.invocation_id = id.clone();
            resolved.cgroup_path = group.clone();
            let old: InstanceRef = read_json(&instance.directory.join("runtime.json"), MAX_SPEC)?;
            self.validate_metadata(&old)?;
            if !old.invocation_id.is_empty() && old.invocation_id != resolved.invocation_id {
                return Err(BackendError::Unknown(
                    "recorded systemd invocation changed".into(),
                ));
            }
            write_json_atomic(&instance.directory.join("runtime.json"), &resolved)?;
        }
        Ok(resolved)
    }
}
fn unit_name(task_id: &str) -> String {
    format!("orc-task-{}.service", sha256(task_id.as_bytes()))
}

#[async_trait]
impl ExecutionBackend for HostBackend {
    async fn probe(&self) -> Result<Capabilities, BackendError> {
        self.check_platform()?;
        control_command(
            "systemctl",
            &["--user".into(), "show-environment".into()],
            5,
        )
        .await?;
        Ok(Capabilities {
            available: true,
            platform: "linux-systemd-host".into(),
            checked_at_ms: unix_ms(),
            limits: BTreeMap::from([
                ("deadline".into(), Enforcement::Enforced),
                ("output".into(), Enforcement::Enforced),
                ("filesystem_isolation".into(), Enforcement::Unsupported),
                ("network_isolation".into(), Enforcement::Unsupported),
                ("whole_instance_stop".into(), Enforcement::BestEffort),
                ("cpu".into(), Enforcement::Unsupported),
                ("memory".into(), Enforcement::Unsupported),
                ("processes".into(), Enforcement::Unsupported),
                ("disk".into(), Enforcement::Unsupported),
            ]),
            evidence: vec![
                "systemd user manager reachable; UID fixed to service UID".into(),
                "same-UID code may escape the managed cgroup or alter control state".into(),
                "CLI adapter pending migration to zbus; Ubuntu validation required".into(),
            ],
        })
    }
    async fn prepare(&self, resolved: ResolvedSpec) -> Result<PreparedInstance, BackendError> {
        self.check_platform()?;
        resolved.validate_digest()?;
        resolved.spec.validate(unix_ms())?;
        if resolved.spec.execution_uid != self.config.execution_uid {
            return Err(BackendError::Invalid("wrong execution UID".into()));
        }
        private_dir(&self.config.state_dir)?;
        let directory = self.config.state_dir.join(&resolved.spec.task_id);
        fs::create_dir(&directory).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                BackendError::AlreadyAttempted
            } else {
                e.into()
            }
        })?;
        private_dir(&directory)?;
        let mut instance = InstanceRef {
            task_id: resolved.spec.task_id.clone(),
            backend: BackendKind::HostLinux,
            runtime_id: unit_name(&resolved.spec.task_id),
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .into(),
            invocation_id: String::new(),
            cgroup_path: String::new(),
            directory,
            spec_digest: resolved.digest.clone(),
            deadline_unix_ms: resolved.spec.deadline_unix_ms,
        };
        write_new_json(&instance.directory.join("spec.json"), &resolved)?;
        write_new_json(&instance.directory.join("instance.json"), &instance)?;
        write_new_json(
            &instance.directory.join("prepare-attempt.json"),
            &instance.spec_digest,
        )?;
        // Record the owned waiting unit before creating it. A crash never grants
        // the user entry; recovery may only reconcile/stop this same name.
        write_new_json(&instance.directory.join("runtime.json"), &instance)?;
        refresh_lease(&instance)?;
        let remaining = instance
            .deadline_unix_ms
            .saturating_sub(unix_ms())
            .div_ceil(1000)
            .max(1);
        let args = vec![
            "--user".into(),
            "--quiet".into(),
            "--unit".into(),
            instance.runtime_id.clone(),
            "--property=Type=exec".into(),
            "--property=KillMode=control-group".into(),
            "--property=TimeoutStopSec=3s".into(),
            "--property=SendSIGKILL=yes".into(),
            format!("--property=RuntimeMaxSec={}s", remaining + 5),
            "--property=Restart=no".into(),
            "--property=UMask=0077".into(),
            "--".into(),
            self.config.runner_path.to_string_lossy().into_owned(),
            "supervise".into(),
            "--directory".into(),
            instance.directory.to_string_lossy().into_owned(),
        ];
        if control_command("systemd-run", &args, 10).await.is_err() {
            return Err(BackendError::Unknown(
                "systemd launch outcome unknown; inspect original unit and never retry start"
                    .into(),
            ));
        }
        let props = self.properties(&instance.runtime_id).await.map_err(|_| {
            BackendError::Unknown("unit launched but identity could not be read".into())
        })?;
        instance.invocation_id = props
            .get("InvocationID")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| BackendError::Unknown("missing systemd invocation identity".into()))?
            .clone();
        instance.cgroup_path = props.get("ControlGroup").cloned().unwrap_or_default();
        if instance.cgroup_path.is_empty() {
            return Err(BackendError::Unknown(
                "missing systemd cgroup identity".into(),
            ));
        }
        write_json_atomic(&instance.directory.join("runtime.json"), &instance)?;
        refresh_lease(&instance)?;
        Ok(PreparedInstance { resolved, instance })
    }
    async fn start(
        &self,
        prepared: PreparedInstance,
        permit: LaunchPermit,
    ) -> Result<InstanceRef, BackendError> {
        self.validate_instance(&prepared.instance)?;
        let control = InstanceControl::lock(&prepared.instance)?;
        control.ensure_launch_allowed()?;
        prepared.resolved.spec.validate(unix_ms())?;
        permit.consume(&prepared)?;
        write_new_json(
            &prepared.instance.directory.join("launch-attempt.json"),
            &prepared.instance.spec_digest,
        )
        .map_err(|e| match e {
            BackendError::Io(ref io) if io.kind() == std::io::ErrorKind::AlreadyExists => {
                BackendError::AlreadyAttempted
            }
            other => other,
        })?;
        let instance = prepared.instance;
        refresh_lease(&instance)?;
        // Linearization point: one durable gate after the scheduler's final authorization.
        // The runner consumes it by creating a permanent started marker before exec.
        write_new_json(&instance.directory.join("gate.json"), &instance.spec_digest)?;
        Ok(instance)
    }
    async fn inspect(&self, instance: &InstanceRef) -> Result<RuntimeEvidence, BackendError> {
        self.validate_metadata(instance)?;
        if !self.current_boot(instance)? {
            return Ok(RuntimeEvidence {
                state: RuntimeState::Exited,
                exit_code: None,
                checked_at_ms: unix_ms(),
                detail:
                    "verified original host boot ended; no current unit was queried or signalled"
                        .into(),
            });
        }
        let props = self.properties(&instance.runtime_id).await?;
        let instance = self.reconcile_identity(instance, &props)?;
        if !instance.invocation_id.is_empty()
            && props
                .get("InvocationID")
                .is_some_and(|v| !v.is_empty() && v != &instance.invocation_id)
        {
            return Err(BackendError::Unknown("systemd invocation changed".into()));
        }
        let active = props
            .get("ActiveState")
            .map(String::as_str)
            .unwrap_or("unknown");
        let state = match active {
            "active" | "activating" => RuntimeState::Running,
            "inactive" | "failed" => {
                let group = props.get("ControlGroup").filter(|v| !v.is_empty()).or(
                    if instance.cgroup_path.is_empty() {
                        None
                    } else {
                        Some(&instance.cgroup_path)
                    },
                );
                let empty = group.is_some_and(|group| {
                    let path = PathBuf::from("/sys/fs/cgroup")
                        .join(group.trim_start_matches('/'))
                        .join("cgroup.events");
                    match fs::read_to_string(path) {
                        Ok(value) => value.lines().any(|line| line == "populated 0"),
                        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
                    }
                });
                if empty {
                    RuntimeState::Exited
                } else {
                    RuntimeState::Unknown
                }
            }
            _ => RuntimeState::Unknown,
        };
        let result =
            read_json::<RunnerResult>(&instance.directory.join("result.json"), MAX_SPEC).ok();
        Ok(RuntimeEvidence {
            state,
            exit_code: result.and_then(|r| r.exit_code),
            checked_at_ms: unix_ms(),
            detail: format!("systemd ActiveState={active}; managed unit only"),
        })
    }
    async fn stop(
        &self,
        instance: &InstanceRef,
        reason: StopReason,
    ) -> Result<StopEvidence, BackendError> {
        self.validate_metadata(instance)?;
        let control = InstanceControl::lock(instance)?;
        control.request_stop(reason)?;
        if !self.current_boot(instance)? {
            return Ok(StopEvidence {
                confirmed: true,
                checked_at_ms: unix_ms(),
                detail: "verified original host boot ended; no current unit was signalled".into(),
            });
        }
        let props = self.properties(&instance.runtime_id).await?;
        let instance = self.reconcile_identity(instance, &props)?;
        if !instance.invocation_id.is_empty()
            && props
                .get("InvocationID")
                .is_some_and(|v| !v.is_empty() && v != &instance.invocation_id)
        {
            return Err(BackendError::Unknown(
                "refusing to stop a different invocation".into(),
            ));
        }
        let args = vec!["--user".into(), "stop".into(), instance.runtime_id.clone()];
        let _ = control_command("systemctl", &args, 5).await;
        let props = self.properties(&instance.runtime_id).await?;
        let inactive = matches!(
            props.get("ActiveState").map(String::as_str),
            Some("inactive" | "failed")
        );
        let cgroup_empty = match props.get("ControlGroup").filter(|v| !v.is_empty()).or(
            if instance.cgroup_path.is_empty() {
                None
            } else {
                Some(&instance.cgroup_path)
            },
        ) {
            Some(group) => {
                let path = PathBuf::from("/sys/fs/cgroup")
                    .join(group.trim_start_matches('/'))
                    .join("cgroup.events");
                match fs::read_to_string(path) {
                    Ok(s) => s.lines().any(|l| l == "populated 0"),
                    Err(e) => e.kind() == std::io::ErrorKind::NotFound,
                }
            }
            None => false,
        };
        Ok(StopEvidence {
            confirmed: inactive && cgroup_empty,
            checked_at_ms: unix_ms(),
            detail: if inactive && cgroup_empty {
                "managed unit inactive and its cgroup empty; external host side effects are not rolled back".into()
            } else {
                "termination not confirmed; retain instance for reconciliation".into()
            },
        })
    }
    async fn cleanup(&self, instance: &InstanceRef) -> Result<(), BackendError> {
        if !self
            .stop(instance, StopReason::EndpointPaused)
            .await?
            .confirmed
        {
            return Err(BackendError::Unknown(
                "cannot clean up an unconfirmed instance".into(),
            ));
        }
        if !self.current_boot(instance)? {
            return Ok(());
        }
        // Keep task/spec/launch markers and output for retention and deduplication.
        let _ = control_command(
            "systemctl",
            &[
                "--user".into(),
                "reset-failed".into(),
                instance.runtime_id.clone(),
            ],
            5,
        )
        .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn old_boot_is_terminal_without_signalling_a_current_unit() {
        let root = tempfile::tempdir().unwrap();
        let task_dir = root.path().join("old-task");
        private_dir(&task_dir).unwrap();
        let instance = InstanceRef {
            task_id: "old-task".into(),
            backend: BackendKind::HostLinux,
            runtime_id: unit_name("old-task"),
            boot_id: "earlier-boot".into(),
            invocation_id: "original-invocation".into(),
            cgroup_path: "/missing-old-group".into(),
            directory: task_dir,
            spec_digest: "original-approved-spec".into(),
            deadline_unix_ms: 1,
        };
        write_new_json(&instance.directory.join("instance.json"), &instance).unwrap();
        let backend = HostBackend::new(HostConfig {
            state_dir: root.path().to_owned(),
            runner_path: std::env::current_exe().unwrap(),
            execution_uid: unsafe { libc::getuid() },
        });
        assert_eq!(
            backend.inspect(&instance).await.unwrap().state,
            RuntimeState::Exited
        );
        assert!(
            backend
                .stop(&instance, StopReason::SupervisorLost)
                .await
                .unwrap()
                .confirmed
        );
        let mut changed = instance;
        changed.boot_id = "unbound-boot".into();
        assert!(
            backend
                .stop(&changed, StopReason::SupervisorLost)
                .await
                .is_err()
        );
    }
    #[test]
    fn names_do_not_embed_untrusted_syntax() {
        assert_eq!(unit_name("../bad; $(id)").len(), 81);
        assert!(unit_name("../bad; $(id)").starts_with("orc-task-"));
    }
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn unsupported_platform_never_executes() {
        let b = HostBackend::new(HostConfig {
            state_dir: "/tmp/orc-test".into(),
            runner_path: "/bin/echo".into(),
            execution_uid: 1000,
        });
        assert!(matches!(b.probe().await, Err(BackendError::Unavailable(_))));
    }
}

//! Independent stop-only supervisor. Never launches or replays a task.
use orc_backend_gvisor::{GvisorBackend, GvisorConfig};
use orc_backend_host_linux::{HostBackend, HostConfig};
use orc_execution::*;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    state_dir: PathBuf,
    runner_path: PathBuf,
    execution_uid: u32,
    gvisor: Option<GvisorConfig>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchdogStopRecord {
    instance: InstanceRef,
    evidence: StopEvidence,
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), BackendError> {
    if !cfg!(target_os = "linux") {
        return Err(BackendError::Unavailable("watchdog requires Linux".into()));
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 || args[0] != "--config" {
        return Err(BackendError::Invalid(
            "usage: orc-watchdog --config <private configuration.json>".into(),
        ));
    }
    let config: Config = read_json(&PathBuf::from(&args[1]), MAX_SPEC)?;
    let host = HostBackend::new(HostConfig {
        state_dir: config.state_dir.clone(),
        runner_path: config.runner_path,
        execution_uid: config.execution_uid,
    });
    let gvisor = config.gvisor.map(GvisorBackend::new);
    private_dir(&config.state_dir)?;
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    loop {
        interval.tick().await;
        let now = unix_ms();
        let watchdog_state = config.state_dir.join("watchdog-heartbeat.json");
        let temp = config.state_dir.join("watchdog-heartbeat.tmp");
        if temp.exists() {
            fs::remove_file(&temp)?;
        }
        write_new_json(&temp, &now)?;
        fs::rename(temp, watchdog_state)?;
        // Retained terminal directories must not permanently hide newer tasks
        // behind a fixed read_dir prefix. Completed records are cheap to skip.
        for item in fs::read_dir(&config.state_dir)? {
            let entry = item?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let runtime = entry.path().join("runtime.json");
            let instance = match read_json::<InstanceRef>(&runtime, MAX_SPEC) {
                Ok(i) => i,
                Err(_) => continue,
            };
            if instance.directory != entry.path() {
                continue;
            }
            if read_json::<WatchdogStopRecord>(&entry.path().join("watchdog-stop.json"), MAX_SPEC)
                .is_ok_and(|record| record.instance == instance && record.evidence.confirmed)
            {
                continue;
            }
            let now = unix_ms();
            let lease =
                read_json::<SupervisorLease>(&entry.path().join("lease.json"), MAX_SPEC).ok();
            let expired = now >= instance.deadline_unix_ms;
            let lost = lease.as_ref().is_none_or(|l| {
                l.instance != instance
                    || l.updated_at_ms > now + 1000
                    || now.saturating_sub(l.updated_at_ms) >= 15_000
            });
            if !expired && !lost {
                continue;
            }
            let reason = if expired {
                StopReason::Deadline
            } else {
                StopReason::SupervisorLost
            };
            let backend: &dyn ExecutionBackend = match instance.backend {
                BackendKind::HostLinux => &host,
                BackendKind::Gvisor => match &gvisor {
                    Some(b) => b,
                    None => continue,
                },
            };
            // No task creation and no recovery of approvals exists in this binary.
            let evidence = backend
                .stop(&instance, reason)
                .await
                .unwrap_or_else(|_| StopEvidence {
                    confirmed: false,
                    checked_at_ms: unix_ms(),
                    detail: "watchdog could not verify termination; owner reconciliation required"
                        .into(),
                });
            if evidence.confirmed {
                write_json_atomic(
                    &entry.path().join("watchdog-stop.json"),
                    &WatchdogStopRecord { instance, evidence },
                )?;
            } else {
                let temp = entry.path().join("watchdog-unknown.tmp");
                if temp.exists() {
                    fs::remove_file(&temp)?;
                }
                write_new_json(&temp, &evidence)?;
                fs::rename(temp, entry.path().join("watchdog-unknown.json"))?;
            }
        }
    }
}

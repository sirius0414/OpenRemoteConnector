use super::*;
use orc_execution::{BackendError, Capabilities, PreparedInstance, RuntimeEvidence, StopEvidence};
use std::sync::atomic::{AtomicUsize, Ordering};

struct FakeBackend {
    root: PathBuf,
    starts: AtomicUsize,
    stops: AtomicUsize,
}
#[async_trait::async_trait]
impl ExecutionBackend for FakeBackend {
    async fn probe(&self) -> std::result::Result<Capabilities, BackendError> {
        Ok(Capabilities {
            available: true,
            platform: "test-only".into(),
            limits: BTreeMap::new(),
            checked_at_ms: 0,
            evidence: vec![],
        })
    }
    async fn prepare(
        &self,
        resolved: ResolvedSpec,
    ) -> std::result::Result<PreparedInstance, BackendError> {
        let directory = self.root.join(&resolved.spec.task_id);
        std::fs::create_dir_all(&directory)?;
        let instance = InstanceRef {
            task_id: resolved.spec.task_id.clone(),
            backend: orc_execution::BackendKind::HostLinux,
            runtime_id: resolved.spec.task_id.clone(),
            boot_id: "test".into(),
            invocation_id: "test".into(),
            cgroup_path: String::new(),
            directory,
            spec_digest: resolved.digest.clone(),
            deadline_unix_ms: resolved.spec.deadline_unix_ms,
        };
        Ok(PreparedInstance { resolved, instance })
    }
    async fn start(
        &self,
        p: PreparedInstance,
        permit: LaunchPermit,
    ) -> std::result::Result<InstanceRef, BackendError> {
        permit.consume(&p)?;
        self.starts.fetch_add(1, Ordering::SeqCst);
        Ok(p.instance)
    }
    async fn inspect(&self, _: &InstanceRef) -> std::result::Result<RuntimeEvidence, BackendError> {
        Ok(RuntimeEvidence {
            state: RuntimeState::Running,
            exit_code: None,
            checked_at_ms: orc_execution::unix_ms(),
            detail: "test".into(),
        })
    }
    async fn stop(
        &self,
        _: &InstanceRef,
        _: StopReason,
    ) -> std::result::Result<StopEvidence, BackendError> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        Ok(StopEvidence {
            confirmed: true,
            checked_at_ms: orc_execution::unix_ms(),
            detail: "fake evidence".into(),
        })
    }
    async fn cleanup(&self, _: &InstanceRef) -> std::result::Result<(), BackendError> {
        Ok(())
    }
}
async fn fixture(
    policy: Policy,
) -> (
    tempfile::TempDir,
    Endpoint,
    Principal,
    TaskRequest,
    Arc<FakeBackend>,
) {
    let dir = tempfile::tempdir().unwrap();
    let identity_path = dir.path().join("endpoint-identity.json");
    IdentityFile::create(&identity_path).unwrap();
    let server = IdentityFile::create(&dir.path().join("mcp-identity.json")).unwrap();
    let config = Config {
        state_dir: dir.path().join("state"),
        admin_socket: dir.path().join("admin.sock"),
        identity_file: identity_path,
        mcp_address: "127.0.0.1:1".into(),
        mcp_server_name: "localhost".into(),
        mcp_id: server.id("mcp").unwrap(),
        mcp_public_key: server.public_key().unwrap(),
        mcp_certificate_digest: "unused".into(),
        tls: TlsFiles {
            certificate: "unused".into(),
            key: "unused".into(),
            ca: "unused".into(),
        },
        execution_uid: orc_admin::current_uid(),
        runner_path: "unused".into(),
        host_context_id: "host".into(),
        host_profile_id: "linux-host-v1".into(),
        host_environment_digest: "host-test-v1".into(),
        environment: BTreeMap::new(),
        gvisor: None,
        continue_on_disconnect: false,
    };
    let principal = Principal {
        mcp_id: McpId(config.mcp_id.clone()),
        auth_domain_id: "auth".into(),
        owner_id: "owner".into(),
        client_registration_id: "client".into(),
    };
    let mut endpoint = Endpoint::open(config).await.unwrap();
    endpoint.connected.store(true, Ordering::SeqCst);
    let fake = Arc::new(FakeBackend {
        root: dir.path().join("tasks"),
        starts: AtomicUsize::new(0),
        stops: AtomicUsize::new(0),
    });
    endpoint.test_backend = Some(fake.clone());
    let grant = Grant {
        id: GrantId("grant-1".into()),
        principal_id: principal.id(),
        device_id: DeviceId(endpoint.device_id.clone()),
        execution_uid: orc_admin::current_uid(),
        actions: std::collections::BTreeSet::from([
            Action::DeviceDiscover,
            Action::TaskSubmit,
            Action::TaskInspect,
            Action::ResultRead,
        ]),
        environment: Environment::Host,
        environment_profile_id: "linux-host-v1".into(),
        environment_digest: "host-test-v1".into(),
        host_context_id: Some("host".into()),
        workspace_ids: Default::default(),
        allowed_env: Default::default(),
        policy,
        revision: 1,
        issued_at: now() - 1,
        expires_at: now() + 3600,
        status: GrantStatus::Active,
    };
    endpoint
        .owner(orc_admin::Request {
            method: "grant.create".into(),
            params: val(&grant).unwrap(),
        })
        .await
        .unwrap();
    let program = dir.path().join("test-elf");
    std::fs::write(&program, b"\x7fELFtest only, never executed").unwrap();
    let request = TaskRequest {
        submission_id: SubmissionId::generate(),
        device_id: grant.device_id,
        grant_id: grant.id,
        environment_profile_id: grant.environment_profile_id,
        context: ExecutionContext {
            host_context_id: Some("host".into()),
            snapshot_id: None,
            workspace_id: None,
            cwd: dir.path().to_str().unwrap().into(),
        },
        command: Command::Argv {
            program: program.to_str().unwrap().into(),
            args: vec!["literal | $HOME".into()],
        },
        stdin: Stdin::default(),
        env_overrides: Default::default(),
        limits: Limits::default(),
        request_expires_at: now() + 600,
    };
    (dir, endpoint, principal, request, fake)
}
#[tokio::test]
async fn retry_only_launches_once_and_cancel_waits_for_evidence() {
    let (_dir, ep, p, r, fake) = fixture(Policy::Automatic).await;
    let first = ep.submit(p.clone(), r.clone(), false).await.unwrap();
    let retry = ep.submit(p.clone(), r.clone(), false).await.unwrap();
    assert_eq!(first["task_id"], retry["task_id"]);
    ep.tick().await.unwrap();
    ep.tick().await.unwrap();
    assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
    let mut changed = r.clone();
    changed.command = Command::Argv {
        program: r.command.program().into(),
        args: vec!["changed".into()],
    };
    assert!(
        ep.submit(p.clone(), changed, false)
            .await
            .unwrap_err()
            .to_string()
            .contains("SUBMISSION_CONFLICT")
    );
    let args = json!({"device_id":ep.device_id,"task_id":first["task_id"],"operation_id":SubmissionId::generate(),"request_expires_at":now()+300});
    let cancelled = ep.cancel(&p, &args).await.unwrap();
    assert_eq!(cancelled["stop_state"], "requested");
    ep.tick().await.unwrap();
    let task = ep
        .store
        .get_task(first["task_id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(task.stop_state, "confirmed");
    assert_eq!(fake.stops.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn reviewed_task_consumes_exact_approval_once() {
    let (_dir, ep, p, r, fake) = fixture(Policy::Review).await;
    let first = ep.submit(p.clone(), r.clone(), false).await.unwrap();
    ep.tick().await.unwrap();
    assert_eq!(fake.starts.load(Ordering::SeqCst), 0);
    let approval = first["approval_id"].as_str().unwrap();
    ep.owner(orc_admin::Request {
        method: "approval.approve".into(),
        params: json!({"id":approval}),
    })
    .await
    .unwrap();
    ep.tick().await.unwrap();
    assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
    assert_eq!(
        ep.store
            .get_approval(approval)
            .await
            .unwrap()
            .unwrap()
            .status,
        "consumed"
    );
    ep.submit(p, r, false).await.unwrap();
    ep.tick().await.unwrap();
    assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn revoked_or_cross_device_authority_never_starts() {
    let (_dir, ep, p, mut r, fake) = fixture(Policy::Automatic).await;
    r.device_id = DeviceId("other-device".into());
    assert!(ep.submit(p.clone(), r.clone(), false).await.is_err());
    r.device_id = DeviceId(ep.device_id.clone());
    let first = ep.submit(p.clone(), r, false).await.unwrap();
    ep.owner(orc_admin::Request {
        method: "grant.revoke".into(),
        params: json!({"id":"grant-1"}),
    })
    .await
    .unwrap();
    ep.tick().await.unwrap();
    assert_eq!(fake.starts.load(Ordering::SeqCst), 0);
    let task = ep
        .store
        .get_task(first["task_id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(task.stop_state, "confirmed");
}
#[tokio::test]
async fn disconnect_policy_stops_active_tasks_but_request_return_does_not() {
    let (_dir, ep, p, r, fake) = fixture(Policy::Automatic).await;
    ep.submit(p, r, false).await.unwrap();
    ep.tick().await.unwrap();
    assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
    ep.connected.store(false, Ordering::SeqCst);
    ep.tick().await.unwrap();
    assert_eq!(fake.stops.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn restart_never_replays_accepted_work() {
    let (_dir, ep, p, r, fake) = fixture(Policy::Automatic).await;
    let first = ep.submit(p, r, false).await.unwrap();
    let config = ep.config.clone();
    drop(ep);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let restarted = loop {
        match Endpoint::open(config.clone()).await {
            Ok(endpoint) => break endpoint,
            Err(e)
                if e.to_string().contains("state directory is already in use")
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await
            }
            Err(e) => panic!("restart failed: {e}"),
        }
    };
    let task = restarted
        .store
        .get_task(first["task_id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(task.execution_state, "not_started");
    assert_eq!(fake.starts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn maintenance_rejects_new_work_preserves_retry_and_requires_drain() {
    let (_dir, ep, p, request, fake) = fixture(Policy::Automatic).await;
    let first = ep.submit(p.clone(), request.clone(), false).await.unwrap();
    ep.tick().await.unwrap();
    let status = ep
        .owner(orc_admin::Request {
            method: "maintenance.prepare".into(),
            params: json!({}),
        })
        .await
        .unwrap();
    assert_eq!(status["active_tasks"], 1);
    assert!(status.get("backup_path").is_none());
    assert_eq!(fake.stops.load(Ordering::SeqCst), 0);
    assert_eq!(
        ep.submit(p.clone(), request.clone(), false).await.unwrap()["task_id"],
        first["task_id"]
    );
    let mut other = request;
    other.submission_id = SubmissionId::generate();
    assert_eq!(
        ep.submit(p.clone(), other, false)
            .await
            .unwrap_err()
            .to_string(),
        "MAINTENANCE"
    );
    ep.cancel(&p, &json!({"device_id":ep.device_id,"task_id":first["task_id"],"operation_id":SubmissionId::generate(),"request_expires_at":now()+60})).await.unwrap();
    ep.tick().await.unwrap();
    let status = ep
        .owner(orc_admin::Request {
            method: "maintenance.prepare".into(),
            params: json!({}),
        })
        .await
        .unwrap();
    assert_eq!(status["active_tasks"], 0);
    assert_eq!(status["unresolved_tasks"], 0);
    assert!(Path::new(status["backup_path"].as_str().unwrap()).is_file());
    assert!(
        ep.store
            .get_record("collection_complete", first["task_id"].as_str().unwrap())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn recovery_links_prepared_instance_before_database_reference_was_saved() {
    let (_dir, ep, p, request, fake) = fixture(Policy::Automatic).await;
    let first = ep.submit(p, request, false).await.unwrap();
    let mut task = ep
        .store
        .get_task(first["task_id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    let body: TaskBody = serde_json::from_value(task.payload.clone()).unwrap();
    task.execution_state = "starting".into();
    let revision = task.revision;
    let task = ep.update(task, revision).await.unwrap();
    let mut prepared = fake.prepare(body.resolved).await.unwrap();
    prepared.instance.directory = ep.config.state_dir.join("tasks").join(&task.task_id);
    std::fs::create_dir_all(&prepared.instance.directory).unwrap();
    orc_execution::write_new_json(
        &prepared.instance.directory.join("runtime.json"),
        &prepared.instance,
    )
    .unwrap();
    let recovered = ep.load_body(&task).await.unwrap().instance.unwrap();
    assert_eq!(recovered.task_id, task.task_id);
    assert!(
        ep.store
            .get_record("runtime", &task.task_id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(fake.starts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn retention_removes_expired_bodies_and_unreferenced_objects_but_keeps_tombstones() {
    let (dir, ep, p, _request, _fake) = fixture(Policy::Automatic).await;
    let created = now() - 86410;
    let key = SubmissionKey {
        principal_id: p.id().0,
        device_id: ep.device_id.clone(),
        submission_id: SubmissionId::generate().0,
    };
    let task = StoredTask {
        task_id: "old-task".into(),
        principal_id: key.principal_id.clone(),
        device_id: key.device_id.clone(),
        grant_id: "grant-1".into(),
        effective_digest: "old-digest".into(),
        execution_state: "accepted".into(),
        stop_state: "none".into(),
        finish_reason: None,
        exit_code: None,
        revision: 0,
        created_at: created,
        updated_at: created,
        payload: json!({"sensitive":"old body"}),
    };
    ep.store
        .accept_submission(
            SubmissionRecord {
                key: key.clone(),
                request_digest: "old-request".into(),
                task_id: task.task_id.clone(),
                grant_id: task.grant_id.clone(),
                created_at: created,
            },
            task.clone(),
        )
        .await
        .unwrap();
    let mut finished = task;
    finished.execution_state = "not_started".into();
    finished.stop_state = "confirmed".into();
    ep.update(finished, 0).await.unwrap();
    let workspace = dir.path().join("snapshot-source");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::write(workspace.join("keep.txt"), b"approved input").unwrap();
    let snapshot = Snapshot::export(
        &workspace,
        "workspace",
        &ep.objects,
        &orc_workspace::Limits::default(),
        now(),
    )
    .unwrap();
    ep.store
        .put_record("snapshot", &snapshot.snapshot_id, val(&snapshot).unwrap())
        .await
        .unwrap();
    let orphan = ep.objects.put_text(b"expired artifact", 100).unwrap();
    let fresh = ep
        .objects
        .put_text(b"concurrent new artifact", 100)
        .unwrap();
    let old_time = std::time::SystemTime::now() - Duration::from_secs(86410);
    for digest in snapshot
        .files
        .values()
        .map(|b| &b.digest)
        .chain(std::iter::once(&orphan.digest))
    {
        std::fs::File::open(ep.config.state_dir.join("objects").join(digest))
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old_time))
            .unwrap();
    }
    let result = ep.cleanup_expired().await.unwrap();
    assert_eq!(result["expired_tasks"], 1);
    assert!(
        ep.store
            .get_task("old-task")
            .await
            .unwrap()
            .unwrap()
            .payload
            .is_null()
    );
    assert!(ep.store.get_submission(key).await.unwrap().is_some());
    assert!(ep.objects.read_all(&orphan, 100).is_err());
    assert!(ep.objects.read_all(&fresh, 100).is_ok());
    assert!(
        ep.objects
            .read_all(snapshot.files.get("keep.txt").unwrap(), 100)
            .is_ok()
    );
    let mut expired = snapshot;
    expired.created_at = created;
    ep.store
        .put_record("snapshot", &expired.snapshot_id, val(&expired).unwrap())
        .await
        .unwrap();
    ep.cleanup_expired().await.unwrap();
    assert!(
        ep.objects
            .read_all(expired.files.get("keep.txt").unwrap(), 100)
            .is_err()
    );
    assert_eq!(
        ep.snapshot_access(&p, &expired)
            .await
            .unwrap_err()
            .to_string(),
        "SNAPSHOT_EXPIRED"
    );
}

#[tokio::test]
async fn snapshot_approval_publishes_exact_preview_even_if_source_changes() {
    let (dir, ep, _p, _request, _fake) = fixture(Policy::Automatic).await;
    let source = dir.path().join("preview-source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("report.txt"), b"reviewed version").unwrap();
    std::fs::write(source.join(".env"), b"SECRET_MARKER=hidden").unwrap();
    let preview = ep
        .owner(orc_admin::Request {
            method: "workspace.preview".into(),
            params: json!({"path":source,"workspace_id":"preview-workspace"}),
        })
        .await
        .unwrap();
    let id = preview["snapshot_id"].as_str().unwrap();
    assert_eq!(preview["approved"], false);
    assert!(ep.store.get_record("snapshot", id).await.unwrap().is_none());
    assert!(preview["files"].get(".env").is_none());
    std::fs::write(source.join("report.txt"), b"unreviewed later version").unwrap();
    ep.owner(orc_admin::Request {
        method: "workspace.approve".into(),
        params: json!({"id":id}),
    })
    .await
    .unwrap();
    let snapshot: Snapshot =
        serde_json::from_value(ep.store.get_record("snapshot", id).await.unwrap().unwrap())
            .unwrap();
    assert_eq!(
        snapshot.read("report.txt", &ep.objects, 0, 64).unwrap(),
        b"reviewed version"
    );
}

#[tokio::test]
async fn uninstall_revokes_before_backup_and_waits_for_stop_confirmation() {
    let (_dir, ep, p, request, fake) = fixture(Policy::Automatic).await;
    ep.submit(p.clone(), request, false).await.unwrap();
    ep.tick().await.unwrap();
    let status = ep
        .owner(orc_admin::Request {
            method: "uninstall.prepare".into(),
            params: json!({}),
        })
        .await
        .unwrap();
    assert_eq!(status["revocation_applied"], true);
    assert_eq!(status["active_tasks"], 1);
    assert!(status.get("backup_path").is_none());
    assert_eq!(
        ep.store.get_grant("grant-1").await.unwrap().unwrap().status,
        "revoked"
    );
    assert!(ep.trust_revoked.load(Ordering::SeqCst));
    ep.tick().await.unwrap();
    assert_eq!(fake.stops.load(Ordering::SeqCst), 1);
    let status = ep
        .owner(orc_admin::Request {
            method: "uninstall.prepare".into(),
            params: json!({}),
        })
        .await
        .unwrap();
    assert_eq!(status["active_tasks"], 0);
    assert_eq!(status["unresolved_tasks"], 0);
    assert!(Path::new(status["backup_path"].as_str().unwrap()).is_file());
    assert!(
        ep.invoke(p, "orc_device_inspect", json!({"device_id":ep.device_id}))
            .await
            .is_err()
    );
}

//! Owner-only trust replacement. Revoking identity and stopping its work are
//! separate facts; replacement never makes old grants valid again.
use super::*;
use std::sync::atomic::Ordering;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustParams {
    invitation: orc_transport::Invitation,
    expected_mcp_id: String,
    expected_mcp_public_key: String,
    mcp_certificate_digest: String,
}

impl Endpoint {
    pub(crate) async fn trust_revoke(&self) -> std::result::Result<Value, AnyError> {
        let _gate = self.gate.lock().await;
        // Fail closed in this process even if persistence subsequently fails.
        self.trust_revoked.store(true, Ordering::SeqCst);
        self.paused.store(true, Ordering::SeqCst);
        self.store
            .put_record("config", "trust_revoked", json!(true))
            .await?;
        self.store
            .put_record("config", "paused", json!(true))
            .await?;
        let mut revoked_grants = 0_u64;
        for grant in self.store.list_grants().await? {
            if grant.status != "revoked" {
                self.store.revoke_grant(&grant.grant_id, now()).await?;
                revoked_grants += 1;
            }
        }
        let mut stop_requests = 0_u64;
        for task in self.store.list_tasks(None).await? {
            if matches!(
                task.execution_state.as_str(),
                "accepted" | "pending_approval" | "starting" | "running" | "unknown"
            ) || matches!(task.stop_state.as_str(), "failed" | "unknown")
            {
                self.request_stop(task, StopReason::GrantRevoked).await?;
                stop_requests += 1;
            }
        }
        Ok(
            json!({"trust_revoked":true,"paused":true,"mcp_id":self.config.mcp_id,"grants_revoked":revoked_grants,"stop_requests":stop_requests,"stop_state":"requested","next_action":"inspect_tasks_until_stop_confirmed"}),
        )
    }

    pub(crate) async fn trust_set(&self, params: Value) -> std::result::Result<Value, AnyError> {
        let params: TrustParams = serde_json::from_value(params)?;
        let _gate = self.gate.lock().await;
        if !self.trust_revoked.load(Ordering::SeqCst)
            || self.store.get_record("config", "trust_revoked").await? != Some(json!(true))
        {
            return Err("TRUST_CHANGE_REQUIRES_REVOKE_AND_REENROLL".into());
        }
        let status = self.maintenance_status().await?;
        if status["active_tasks"] != 0 || status["unresolved_tasks"] != 0 {
            return Err("TRUST_CHANGE_REQUIRES_CONFIRMED_STOP".into());
        }
        // A partially completed revoke must be retried before trust replacement.
        if self
            .store
            .list_grants()
            .await?
            .iter()
            .any(|g| g.status != "revoked")
        {
            return Err("TRUST_CHANGE_REQUIRES_ALL_GRANTS_REVOKED".into());
        }
        params.invitation.verify(
            &params.expected_mcp_id,
            &params.expected_mcp_public_key,
            &self.identity.id("dev")?,
            now(),
        )?;
        if params.invitation.request.certificate_digest
            != orc_transport::certificate_file_digest(&self.config.tls.certificate)?
        {
            return Err("INVITATION_CERTIFICATE_MISMATCH".into());
        }
        if !params
            .mcp_certificate_digest
            .strip_prefix("sha256:")
            .is_some_and(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
        {
            return Err("INVALID_MCP_CERTIFICATE_DIGEST".into());
        }
        let trust = json!({
            "mcp_id": params.expected_mcp_id,
            "execution_uid": self.config.execution_uid,
            "mcp_public_key": params.expected_mcp_public_key,
            "mcp_certificate_digest": params.mcp_certificate_digest,
        });
        self.paused.store(true, Ordering::SeqCst);
        self.store
            .put_record("config", "paused", json!(true))
            .await?;
        self.store
            .put_record("trust", "current", trust.clone())
            .await?;
        self.store
            .put_record("config", "trust_revoked", json!(false))
            .await?;
        // The immutable config and the live connection still describe the old
        // peer. Only restart with the owner's updated config may activate trust.
        Ok(
            json!({"trust":trust,"needs_restart":true,"paused":true,"trust_revoked_in_current_process":true,"execution_grant_created":false}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fixture() -> (tempfile::TempDir, Endpoint, IdentityFile) {
        let dir = tempfile::tempdir().unwrap();
        let identity_file = dir.path().join("identity.json");
        IdentityFile::create(&identity_file).unwrap();
        let old = IdentityFile::create(&dir.path().join("old-mcp.json")).unwrap();
        let new = IdentityFile::create(&dir.path().join("new-mcp.json")).unwrap();
        let certificate = dir.path().join("device.pem");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(&certificate, cert.cert.pem()).unwrap();
        let config = Config {
            state_dir: dir.path().join("state"),
            admin_socket: dir.path().join("admin.sock"),
            identity_file,
            mcp_address: "127.0.0.1:1".into(),
            mcp_server_name: "localhost".into(),
            mcp_id: old.id("mcp").unwrap(),
            mcp_public_key: old.public_key().unwrap(),
            mcp_certificate_digest: format!("sha256:{}", "a".repeat(64)),
            tls: TlsFiles {
                certificate,
                key: dir.path().join("unused.key"),
                ca: dir.path().join("unused-ca.pem"),
            },
            execution_uid: orc_admin::current_uid(),
            runner_path: dir.path().join("unused-runner"),
            host_context_id: "host".into(),
            host_profile_id: "host-v1".into(),
            host_environment_digest: "host-v1".into(),
            environment: BTreeMap::new(),
            gvisor: None,
            continue_on_disconnect: false,
        };
        (dir, Endpoint::open(config).await.unwrap(), new)
    }
    fn params(ep: &Endpoint, new: &IdentityFile, digest: Option<String>) -> Value {
        let request = orc_transport::EnrollmentRequest::create(
            &ep.identity,
            digest.unwrap_or_else(|| {
                orc_transport::certificate_file_digest(&ep.config.tls.certificate).unwrap()
            }),
            now(),
        )
        .unwrap();
        let invitation = orc_transport::Invitation::issue(new, request, now()).unwrap();
        json!({"invitation":invitation,"expected_mcp_id":new.id("mcp").unwrap(),"expected_mcp_public_key":new.public_key().unwrap(),"mcp_certificate_digest":format!("sha256:{}", "b".repeat(64))})
    }
    async fn grant(ep: &Endpoint) {
        ep.store
            .put_grant(StoredGrant {
                grant_id: "old-grant".into(),
                principal_id: "old-principal".into(),
                device_id: ep.device_id.clone(),
                revision: 1,
                expires_at: now() + 3600,
                status: "active".into(),
                payload: json!({}),
            })
            .await
            .unwrap();
    }
    async fn running_task(ep: &Endpoint) -> StoredTask {
        let task = StoredTask {
            task_id: "old-task".into(),
            principal_id: "old-principal".into(),
            device_id: ep.device_id.clone(),
            grant_id: "old-grant".into(),
            effective_digest: "digest".into(),
            execution_state: "accepted".into(),
            stop_state: "none".into(),
            finish_reason: None,
            exit_code: None,
            revision: 0,
            created_at: now(),
            updated_at: now(),
            payload: json!({}),
        };
        ep.store
            .accept_submission(
                SubmissionRecord {
                    key: SubmissionKey {
                        principal_id: task.principal_id.clone(),
                        device_id: ep.device_id.clone(),
                        submission_id: SubmissionId::generate().0,
                    },
                    request_digest: "digest".into(),
                    task_id: task.task_id.clone(),
                    grant_id: task.grant_id.clone(),
                    created_at: now(),
                },
                task.clone(),
            )
            .await
            .unwrap();
        let mut task = task;
        for state in ["starting", "running"] {
            task.execution_state = state.into();
            let revision = task.revision;
            task = ep.store.update_task(task, revision).await.unwrap();
        }
        task
    }
    #[tokio::test]
    async fn revoke_is_durable_revokes_grants_and_does_not_claim_stopped() {
        let (_dir, ep, new) = fixture().await;
        grant(&ep).await;
        running_task(&ep).await;
        let result = ep.trust_revoke().await.unwrap();
        assert_eq!(result["stop_state"], "requested");
        assert!(ep.trust_revoked.load(Ordering::SeqCst));
        assert!(ep.paused.load(Ordering::SeqCst));
        assert_eq!(
            ep.store
                .get_record("config", "trust_revoked")
                .await
                .unwrap(),
            Some(json!(true))
        );
        assert_eq!(
            ep.store
                .get_grant("old-grant")
                .await
                .unwrap()
                .unwrap()
                .status,
            "revoked"
        );
        let task = ep.store.get_task("old-task").await.unwrap().unwrap();
        assert_eq!(task.execution_state, "running");
        assert_eq!(task.stop_state, "requested");
        assert_eq!(
            ep.trust_set(params(&ep, &new, None))
                .await
                .unwrap_err()
                .to_string(),
            "TRUST_CHANGE_REQUIRES_CONFIRMED_STOP"
        );
        ep.trust_revoke().await.unwrap();
    }
    #[tokio::test]
    async fn replacement_requires_revocation_exact_peer_and_local_certificate() {
        let (_dir, ep, new) = fixture().await;
        assert!(ep.trust_set(params(&ep, &new, None)).await.is_err());
        ep.trust_revoke().await.unwrap();
        assert_eq!(
            ep.trust_set(params(
                &ep,
                &new,
                Some(format!("sha256:{}", "c".repeat(64)))
            ))
            .await
            .unwrap_err()
            .to_string(),
            "INVITATION_CERTIFICATE_MISMATCH"
        );
        let mut wrong = params(&ep, &new, None);
        wrong["expected_mcp_id"] = json!("mcp-other");
        assert!(ep.trust_set(wrong).await.is_err());
        let mut wrong = params(&ep, &new, None);
        wrong["mcp_certificate_digest"] = json!("unverified");
        assert_eq!(
            ep.trust_set(wrong).await.unwrap_err().to_string(),
            "INVALID_MCP_CERTIFICATE_DIGEST"
        );
        assert_eq!(
            ep.store
                .get_record("config", "trust_revoked")
                .await
                .unwrap(),
            Some(json!(true))
        );
    }
    #[tokio::test]
    async fn new_trust_needs_restart_and_never_restores_old_grants() {
        let (_dir, ep, new) = fixture().await;
        grant(&ep).await;
        ep.trust_revoke().await.unwrap();
        let requested = params(&ep, &new, None);
        let result = ep.trust_set(requested.clone()).await.unwrap();
        assert_eq!(result["needs_restart"], true);
        assert_eq!(result["execution_grant_created"], false);
        assert!(ep.trust_revoked.load(Ordering::SeqCst));
        assert!(ep.paused.load(Ordering::SeqCst));
        assert_eq!(
            ep.store
                .get_record("config", "trust_revoked")
                .await
                .unwrap(),
            Some(json!(false))
        );
        assert_eq!(
            ep.store
                .get_grant("old-grant")
                .await
                .unwrap()
                .unwrap()
                .status,
            "revoked"
        );
        assert!(ep.trust_set(requested.clone()).await.is_err());
        let mut config = ep.config.clone();
        config.mcp_id = new.id("mcp").unwrap();
        config.mcp_public_key = new.public_key().unwrap();
        config.mcp_certificate_digest =
            requested["mcp_certificate_digest"].as_str().unwrap().into();
        drop(ep);
        // Store's worker releases its exclusive directory lock asynchronously
        // after the last sender is dropped, as a process exit would do at once.
        let restarted = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match Endpoint::open(config.clone()).await {
                    Ok(endpoint) => break endpoint,
                    Err(error) if matches!(error.downcast_ref::<orc_store::StoreError>(), Some(orc_store::StoreError::SecurityState(message)) if message == "state directory is already in use") => tokio::time::sleep(Duration::from_millis(10)).await,
                    Err(error) => panic!("unexpected restart failure: {error}"),
                }
            }
        }).await.unwrap();
        assert!(!restarted.trust_revoked.load(Ordering::SeqCst));
        assert!(restarted.paused.load(Ordering::SeqCst));
        assert_eq!(
            restarted
                .store
                .get_grant("old-grant")
                .await
                .unwrap()
                .unwrap()
                .status,
            "revoked"
        );
    }
}

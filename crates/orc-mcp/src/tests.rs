use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use orc_domain::{Command, ExecutionContext, Limits, Stdin, TaskRequest};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

fn config(dir: &std::path::Path) -> Config {
    let identity_file = dir.join("identity.json");
    IdentityFile::create(&identity_file).unwrap();
    let absent = dir.join("not-configured.pem");
    Config {
        state_dir: dir.join("mcp-state"),
        admin_socket: dir.join("mcp.sock"),
        identity_file,
        http_bind: "127.0.0.1:7790".parse().unwrap(),
        public_url: "http://127.0.0.1:7790/mcp".into(),
        device_bind: "127.0.0.1:0".parse().unwrap(),
        device_tls: TlsFiles {
            certificate: absent.clone(),
            key: absent.clone(),
            ca: absent,
        },
        owner_id: "owner-a".into(),
        auth_domain_id: "auth-a".into(),
    }
}
async fn authenticated(mcp: &Mcp, name: &str) -> (orc_auth::Tokens, Principal) {
    let client = mcp
        .auth
        .register(
            name.into(),
            vec!["http://127.0.0.1:4200/callback".into()],
            now(),
        )
        .await
        .unwrap();
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let (pending, nonce) = mcp
        .auth
        .begin(
            Authorization {
                client_id: client.client_id.clone(),
                redirect_uri: client.redirect_uris[0].clone(),
                response_type: "code".into(),
                scope: "orc".into(),
                resource: mcp.config.public_url.clone(),
                state: "state".into(),
                code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
                code_challenge_method: "S256".into(),
            },
            now(),
        )
        .await
        .unwrap();
    mcp.auth.approve(&pending.id, now()).await.unwrap();
    let redirect = mcp.auth.complete(&pending.id, &nonce, now()).await.unwrap();
    let code = url::Url::parse(&redirect)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .to_string();
    let tokens = mcp
        .auth
        .exchange(
            &client.client_id,
            &code,
            &client.redirect_uris[0],
            verifier,
            &mcp.config.public_url,
            now(),
        )
        .await
        .unwrap();
    let principal = mcp
        .auth
        .authenticate(&tokens.access_token, now())
        .await
        .unwrap();
    (tokens, principal)
}
fn rpc_request(token: Option<&str>, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "127.0.0.1:7790")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-11-25");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}
async fn response_value(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}
fn task(device: &str) -> TaskRequest {
    TaskRequest {
        submission_id: SubmissionId::generate(),
        device_id: device.into(),
        grant_id: "grant-a".into(),
        environment_profile_id: "host-v1".into(),
        context: ExecutionContext {
            host_context_id: Some("host-a".into()),
            snapshot_id: None,
            workspace_id: None,
            cwd: "/tmp".into(),
        },
        command: Command::Argv {
            program: "/usr/bin/true".into(),
            args: vec![],
        },
        stdin: Stdin::default(),
        env_overrides: Default::default(),
        limits: Limits::default(),
        request_expires_at: now() + 60,
    }
}

#[tokio::test]
async fn mcp_alone_has_no_execution_and_offline_submission_is_not_queued() {
    use orc_admin::Handler;
    let dir = tempfile::tempdir().unwrap();
    let mcp = Mcp::open(config(dir.path())).await.unwrap();
    let (_, principal) = authenticated(&mcp, "owner-client").await;
    let status = mcp
        .handle(orc_admin::Request {
            method: "status".into(),
            params: json!({}),
        })
        .await
        .result
        .unwrap();
    assert_eq!(status["execution_capability"], false);
    assert_eq!(
        mcp.invoke(principal.clone(), "orc_devices_list", json!({}))
            .await
            .unwrap()["devices"],
        json!([])
    );
    let key = IdentityFile::create(&dir.path().join("device.json")).unwrap();
    let id = key.id("dev").unwrap();
    mcp.store.put_record("device",&id,json!({"device_id":id,"name":"offline","public_key":key.public_key().unwrap(),"certificate_digest":"sha256:offline","revoked":false})).await.unwrap();
    mcp.store
        .put_record("service_allow", &principal.id().0, json!([id]))
        .await
        .unwrap();
    let request = task(&id);
    assert_eq!(
        mcp.invoke(
            principal,
            "orc_task_submit",
            serde_json::to_value(request).unwrap()
        )
        .await
        .unwrap_err()
        .to_string(),
        "DEVICE_OFFLINE"
    );
    assert!(
        mcp.store
            .list_records("forwarding")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(mcp.store.list_tasks(None).await.unwrap().is_empty());
}

#[tokio::test]
async fn http_authentication_is_per_request_and_revocation_is_immediate() {
    let dir = tempfile::tempdir().unwrap();
    let mcp = Arc::new(Mcp::open(config(dir.path())).await.unwrap());
    let (a, principal_a) = authenticated(&mcp, "client-a").await;
    let (b, principal_b) = authenticated(&mcp, "client-b").await;
    let app = router(mcp.clone());
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"orc_connection_status","arguments":{}}}"#;
    let response = app.clone().oneshot(rpc_request(None, body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key("www-authenticate"));
    let response = app
        .clone()
        .oneshot(rpc_request(Some(&a.access_token), body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let a_body = response_value(response).await;
    assert_eq!(
        a_body["result"]["structuredContent"]["principal_id"],
        json!(principal_a.id())
    );
    let response = app
        .clone()
        .oneshot(rpc_request(Some(&b.access_token), body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let b_body = response_value(response).await;
    assert_eq!(
        b_body["result"]["structuredContent"]["principal_id"],
        json!(principal_b.id())
    );
    mcp.auth
        .revoke_token(&a.access_token, &principal_a.client_registration_id)
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(rpc_request(Some(&a.access_token), body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        app.oneshot(rpc_request(Some(&b.access_token), body))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn http_rejects_duplicate_json_host_origin_and_identity_override() {
    let dir = tempfile::tempdir().unwrap();
    let mcp = Arc::new(Mcp::open(config(dir.path())).await.unwrap());
    let (token, _) = authenticated(&mcp, "client-a").await;
    let app = router(mcp);
    let duplicate = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"orc_connection_status","arguments":{"x":1,"x":2}}}"#;
    assert_eq!(
        app.clone()
            .oneshot(rpc_request(Some(&token.access_token), duplicate))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let normal = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
    let mut wrong_host = rpc_request(Some(&token.access_token), normal);
    wrong_host
        .headers_mut()
        .insert("host", "attacker.example".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(wrong_host).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut origin = rpc_request(Some(&token.access_token), normal);
    origin
        .headers_mut()
        .insert("origin", "https://attacker.example".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(origin).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let override_identity = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"orc_connection_status","arguments":{"principal_id":"another-client"}}}"#;
    let response = app
        .oneshot(rpc_request(Some(&token.access_token), override_identity))
        .await
        .unwrap();
    let body = response_value(response).await;
    assert_eq!(body["result"]["isError"], true);
}

#[tokio::test]
async fn metadata_and_schemas_describe_only_registered_operations() {
    let dir = tempfile::tempdir().unwrap();
    let mcp = Arc::new(Mcp::open(config(dir.path())).await.unwrap());
    let (token, _) = authenticated(&mcp, "client-a").await;
    let app = router(mcp);
    let metadata = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-authorization-server")
                .header("host", "127.0.0.1:7790")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metadata.headers()["cache-control"], "no-store");
    let value = response_value(metadata).await;
    assert_eq!(value["code_challenge_methods_supported"], json!(["S256"]));
    assert!(value.get("client_id_metadata_document_supported").is_none());
    let response = app
        .oneshot(rpc_request(
            Some(&token.access_token),
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
        ))
        .await
        .unwrap();
    let value = response_value(response).await;
    let tools = value["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 16);
    assert!(
        tools
            .iter()
            .all(|t| !t["name"].as_str().unwrap().contains("approve"))
    );
    let task = tools
        .iter()
        .find(|t| t["name"] == "orc_task_submit")
        .unwrap();
    assert_eq!(task["annotations"]["readOnlyHint"], false);
    assert!(task["inputSchema"]["$defs"]["Command"]["oneOf"].is_array());
    assert!(
        tool_schema::validate_arguments("orc_task_cancel", &json!({"device_id":"d","task_id":"t"}))
            .is_err()
    );
    assert!(
        tool_schema::validate_arguments(
            "orc_task_output_read",
            &json!({"device_id":"d","task_id":"t","stream":"stdout","limit":65537})
        )
        .is_err()
    );
}

#[tokio::test]
async fn oauth_http_does_not_collapse_duplicate_parameters() {
    let dir = tempfile::tempdir().unwrap();
    let mcp = Arc::new(Mcp::open(config(dir.path())).await.unwrap());
    let app = router(mcp);
    let request=Request::builder().method("POST").uri("/register").header("host","127.0.0.1:7790").header("content-type","application/json").body(Body::from(r#"{"client_name":"a","client_name":"b","redirect_uris":["https://example.com/callback"]}"#)).unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let request = Request::builder()
        .method("POST")
        .uri("/token")
        .header("host", "127.0.0.1:7790")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=authorization_code&client_id=a&client_id=b",
        ))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_value(response).await["error"], "invalid_request");
}

struct CertificateAuthority {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    pem: String,
}
impl CertificateAuthority {
    fn new() -> Self {
        let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        Self {
            issuer: rcgen::Issuer::new(p, key),
            pem: cert.pem(),
        }
    }
    fn leaf(&self, dir: &std::path::Path, name: &str, server: bool) -> TlsFiles {
        let mut p = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        p.extended_key_usages = vec![if server {
            rcgen::ExtendedKeyUsagePurpose::ServerAuth
        } else {
            rcgen::ExtendedKeyUsagePurpose::ClientAuth
        }];
        p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = p.signed_by(&key, &self.issuer).unwrap();
        let files = TlsFiles {
            certificate: dir.join(format!("{name}.pem")),
            key: dir.join(format!("{name}.key")),
            ca: dir.join(format!("{name}-ca.pem")),
        };
        std::fs::write(&files.certificate, cert.pem()).unwrap();
        std::fs::write(&files.key, key.serialize_pem()).unwrap();
        std::fs::write(&files.ca, &self.pem).unwrap();
        files
    }
}
async fn fake_device(
    mcp: &Arc<Mcp>,
    address: std::net::SocketAddr,
    identity: IdentityFile,
    tls: TlsFiles,
    principal: Principal,
    marker: u32,
) -> tokio::task::JoinHandle<()> {
    let id = identity.id("dev").unwrap();
    let registration = DeviceRegistration {
        device_id: id.clone(),
        name: "same visible name".into(),
        public_key: identity.public_key().unwrap(),
        certificate_digest: orc_transport::certificate_file_digest(&tls.certificate).unwrap(),
        revoked: false,
    };
    mcp.store
        .put_record("device", &id, json!(registration))
        .await
        .unwrap();
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(orc_transport::tls_client(&tls).unwrap())
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            stream,
        )
        .await
        .unwrap();
    let (mut ws, _) = tokio_tungstenite::client_async_with_config(
        "wss://localhost/endpoint/v1/connect",
        tls,
        Some(orc_transport::websocket_config()),
    )
    .await
    .unwrap();
    let hello = orc_transport::hello_frame(&identity).unwrap();
    let nonce = match &hello {
        Frame::Hello { nonce, .. } => nonce.clone(),
        _ => unreachable!(),
    };
    orc_transport::send(&mut ws, &hello).await.unwrap();
    let sync = orc_transport::receive(&mut ws).await.unwrap();
    orc_transport::verify_sync(
        &sync,
        &mcp.identity.id("mcp").unwrap(),
        &mcp.identity.public_key().unwrap(),
        &nonce,
    )
    .unwrap();
    orc_transport::send(
        &mut ws,
        &orc_transport::ready_frame(&identity, &sync).unwrap(),
    )
    .await
    .unwrap();
    let (epoch, mut revision) = match &sync {
        Frame::Sync {
            epoch,
            service_revision,
            ..
        } => (*epoch, *service_revision),
        _ => unreachable!(),
    };
    let server_key = mcp.identity.signing_key().unwrap().verifying_key();
    let mcp_id = McpId(mcp.identity.id("mcp").unwrap());
    let device_id = DeviceId(id);
    let capabilities = orc_transport::capabilities();
    tokio::spawn(async move {
        loop {
            match orc_transport::receive(&mut ws).await {
                Ok(Frame::Ping { sequence }) => {
                    if orc_transport::send(&mut ws, &Frame::Pong { sequence })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Frame::Request { id, envelope }) => {
                    envelope
                        .verify(
                            &server_key,
                            &orc_protocol::EnvelopeContext {
                                mcp_id: &mcp_id,
                                device_id: &device_id,
                                connection_epoch: epoch,
                                service_policy_revision: revision,
                                capabilities: &capabilities,
                                now: now(),
                            },
                        )
                        .unwrap();
                    let response = if envelope.payload.principal == principal {
                        Frame::Response {
                            id,
                            result: Some(json!({"device_id":device_id,"marker":marker})),
                            error: None,
                        }
                    } else {
                        Frame::Response {
                            id,
                            result: None,
                            error: Some("ACCESS_DENIED".into()),
                        }
                    };
                    if orc_transport::send(&mut ws, &response).await.is_err() {
                        break;
                    }
                }
                Ok(Frame::MaintenanceProbe { id }) => {
                    if orc_transport::send(
                        &mut ws,
                        &Frame::Response {
                            id,
                            result: Some(json!({"active_tasks":0,"unresolved_tasks":0})),
                            error: None,
                        },
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                Ok(Frame::Revoke {
                    principal_id,
                    revision: update,
                }) => {
                    revision = update;
                    if orc_transport::send(
                        &mut ws,
                        &Frame::RevokeAck {
                            principal_id,
                            revision,
                        },
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                _ => break,
            }
        }
    })
}

#[tokio::test]
async fn two_mutual_tls_devices_keep_targets_permissions_and_disconnects_separate() {
    let dir = tempfile::tempdir().unwrap();
    let ca = CertificateAuthority::new();
    let mut config = config(dir.path());
    config.device_tls = ca.leaf(dir.path(), "server", true);
    let mcp = Arc::new(Mcp::open(config).await.unwrap());
    let (_, principal) = authenticated(&mcp, "client-a").await;
    let (_, outsider) = authenticated(&mcp, "client-b").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(mcp.clone().serve_devices_on(listener));
    let first_identity = IdentityFile::create(&dir.path().join("first.json")).unwrap();
    let first_id = first_identity.id("dev").unwrap();
    let second_identity = IdentityFile::create(&dir.path().join("second.json")).unwrap();
    let second_id = second_identity.id("dev").unwrap();
    let first = fake_device(
        &mcp,
        address,
        first_identity,
        ca.leaf(dir.path(), "first", false),
        principal.clone(),
        1,
    )
    .await;
    let second = fake_device(
        &mcp,
        address,
        second_identity,
        ca.leaf(dir.path(), "second", false),
        principal.clone(),
        2,
    )
    .await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while mcp.connections.lock().await.len() != 2 {
            tokio::task::yield_now().await
        }
    })
    .await
    .unwrap();
    mcp.store
        .put_record(
            "service_allow",
            &principal.id().0,
            json!([first_id, second_id]),
        )
        .await
        .unwrap();
    mcp.store
        .put_record("service_allow", &outsider.id().0, json!([first_id]))
        .await
        .unwrap();
    let listed = mcp
        .invoke(principal.clone(), "orc_devices_list", json!({}))
        .await
        .unwrap();
    assert_eq!(listed["devices"].as_array().unwrap().len(), 2);
    assert!(
        mcp.invoke(outsider.clone(), "orc_devices_list", json!({}))
            .await
            .unwrap()["devices"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        mcp.invoke(
            outsider,
            "orc_device_inspect",
            json!({"device_id":second_id})
        )
        .await
        .is_err()
    );
    assert_eq!(
        mcp.invoke(
            principal.clone(),
            "orc_device_inspect",
            json!({"device_id":second_id})
        )
        .await
        .unwrap()["marker"],
        2
    );
    let prepared = mcp.maintenance_prepare().await.unwrap();
    assert_eq!(prepared["state_schema"], 1);
    assert_eq!(prepared["active_tasks"], 0);
    assert_eq!(
        mcp.invoke(principal.clone(), "orc_task_submit", json!(task(&first_id)))
            .await
            .unwrap_err()
            .to_string(),
        "MAINTENANCE"
    );
    mcp.maintenance_resume().await.unwrap();
    first.abort();
    let _ = first.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while mcp.connections.lock().await.contains_key(&first_id) {
            tokio::task::yield_now().await
        }
    })
    .await
    .unwrap();
    assert_eq!(
        mcp.invoke(
            principal.clone(),
            "orc_device_inspect",
            json!({"device_id":first_id})
        )
        .await
        .unwrap_err()
        .to_string(),
        "DEVICE_OFFLINE"
    );
    assert_eq!(
        mcp.invoke(
            principal,
            "orc_device_inspect",
            json!({"device_id":second_id})
        )
        .await
        .unwrap()["marker"],
        2
    );
    second.abort();
    let _ = second.await;
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn revocation_queue_saturation_forces_resync_without_claiming_a_confirmed_stop() {
    let dir = tempfile::tempdir().unwrap();
    let mcp = Mcp::open(config(dir.path())).await.unwrap();
    let (token, principal) = authenticated(&mcp, "client-a").await;
    let (sender, _data) = mpsc::channel(1);
    let (control, mut controls) = mpsc::channel(1);
    let (maintenance, _probes) = mpsc::channel(1);
    control.send(Frame::Ping { sequence: 1 }).await.unwrap();
    let closed = tokio_util::sync::CancellationToken::new();
    mcp.connections.lock().await.insert(
        "device-a".into(),
        Connection {
            epoch: 1,
            service_revision: 1,
            capabilities: orc_transport::capabilities(),
            sender,
            control,
            closed: closed.clone(),
            maintenance,
        },
    );
    mcp.store
        .put_record("service_allow", &principal.id().0, json!(["device-a"]))
        .await
        .unwrap();
    let outcome = mcp
        .revoke_access(&principal.client_registration_id)
        .await
        .unwrap();
    assert_eq!(outcome["stop_state"], "requested");
    assert_eq!(outcome["service_revision"], 2);
    assert_eq!(outcome["channels_requiring_resync"], 1);
    assert!(closed.is_cancelled());
    assert!(
        mcp.auth
            .authenticate(&token.access_token, now())
            .await
            .is_err()
    );
    assert!(mcp.service_allowed(&principal, "device-a").await.is_err());
    assert_eq!(
        mcp.store
            .get_record("service_revoked", &principal.id().0)
            .await
            .unwrap()
            .unwrap()["revision"],
        2
    );
    let _ = controls.recv().await;
    let second = mcp
        .revoke_access(&principal.client_registration_id)
        .await
        .unwrap();
    assert_eq!(second["service_revision"], 3);
    assert!(matches!(
        controls.recv().await.unwrap(),
        Frame::Revoke { revision: 3, .. }
    ));
}

#[test]
fn tool_errors_preserve_recovery_codes_without_exposing_internal_details() {
    let error: AnyError = "DEVICE_OFFLINE".into();
    let result = tool_failure(&error, &json!({"device_id":"dev-a"}));
    assert_eq!(result["code"], "DEVICE_OFFLINE");
    assert_eq!(result["device_id"], "dev-a");
    assert_eq!(result["retry_mode"], "same_submission");
    let error: AnyError = std::io::Error::other("private secret path and command body").into();
    let result = tool_failure(&error, &json!({}));
    assert_eq!(result["code"], "INTERNAL");
    assert!(!result.to_string().contains("private secret"));
}

#[tokio::test]
async fn maintenance_is_durable_and_refuses_unverified_remote_tasks() {
    let dir = tempfile::tempdir().unwrap();
    let mcp = Mcp::open(config(dir.path())).await.unwrap();
    let (_, principal) = authenticated(&mcp, "client-a").await;
    let prepared = mcp.maintenance_prepare().await.unwrap();
    assert_eq!(prepared["active_tasks"], 0);
    assert_eq!(prepared["unresolved_tasks"], 0);
    assert_eq!(prepared["state_schema"], 1);
    let again = mcp.maintenance_prepare().await.unwrap();
    assert_ne!(prepared["backup_path"], again["backup_path"]);
    assert!(std::path::Path::new(prepared["backup_path"].as_str().unwrap()).exists());
    mcp.store
        .put_record("service_allow", &principal.id().0, json!(["offline"]))
        .await
        .unwrap();
    mcp.store.put_record("device","offline",json!({"device_id":"offline","name":"offline","public_key":"unused","certificate_digest":"unused","revoked":false})).await.unwrap();
    let request = serde_json::to_value(task("offline")).unwrap();
    assert_eq!(
        mcp.invoke(principal.clone(), "orc_task_submit", request.clone())
            .await
            .unwrap_err()
            .to_string(),
        "MAINTENANCE"
    );
    mcp.maintenance_resume().await.unwrap();
    assert_eq!(
        mcp.invoke(principal, "orc_task_submit", request)
            .await
            .unwrap_err()
            .to_string(),
        "DEVICE_OFFLINE"
    );
    assert_eq!(
        mcp.maintenance_prepare().await.unwrap_err().to_string(),
        "MAINTENANCE_DEVICE_OFFLINE"
    );
    assert_eq!(
        mcp.store
            .get_record("maintenance", "state")
            .await
            .unwrap()
            .unwrap()["active"],
        true
    );
}

#[tokio::test]
async fn device_invitation_is_bound_single_use_and_creates_no_grants() {
    let dir = tempfile::tempdir().unwrap();
    let mcp = Mcp::open(config(dir.path())).await.unwrap();
    let device = IdentityFile::create(&dir.path().join("device.json")).unwrap();
    let request = orc_transport::EnrollmentRequest::create(
        &device,
        format!("sha256:{}", "a".repeat(64)),
        now(),
    )
    .unwrap();
    let invitation: orc_transport::Invitation = serde_json::from_value(
        mcp.invite_device(json!({"name":"worker","request":request}))
            .await
            .unwrap(),
    )
    .unwrap();
    let proof = orc_transport::EnrollmentProof::create(&device, &invitation, now()).unwrap();
    let params = json!({"invitation":invitation,"proof":proof});
    let (first, second) = tokio::join!(
        mcp.redeem_device(params.clone()),
        mcp.redeem_device(params.clone())
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let success = first.or(second).unwrap();
    assert_eq!(success["state"], "trusted_ungranted");
    assert_eq!(success["execution_grant_created"], false);
    assert!(mcp.store.list_grants().await.unwrap().is_empty());
    assert!(
        mcp.store
            .list_records("service_allow")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(mcp.redeem_device(params).await.is_err());
    assert_eq!(mcp.store.list_records("device").await.unwrap().len(), 1);
    assert_eq!(
        mcp.store
            .get_record("enrollment_invitation", &invitation.nonce)
            .await
            .unwrap()
            .unwrap()["consumed"],
        true
    );
}

#[tokio::test]
async fn invitation_redemption_rejects_wrong_key_and_expiry_without_consuming() {
    let dir = tempfile::tempdir().unwrap();
    let mcp = Mcp::open(config(dir.path())).await.unwrap();
    let device = IdentityFile::create(&dir.path().join("device.json")).unwrap();
    let other = IdentityFile::create(&dir.path().join("other.json")).unwrap();
    let request = orc_transport::EnrollmentRequest::create(
        &device,
        format!("sha256:{}", "a".repeat(64)),
        now(),
    )
    .unwrap();
    let invitation: orc_transport::Invitation = serde_json::from_value(
        mcp.invite_device(json!({"name":"worker","request":request}))
            .await
            .unwrap(),
    )
    .unwrap();
    let mut proof = orc_transport::EnrollmentProof::create(&device, &invitation, now()).unwrap();
    proof.device_id = other.id("dev").unwrap();
    assert!(
        mcp.redeem_device(json!({"invitation":invitation,"proof":proof}))
            .await
            .is_err()
    );
    assert_eq!(
        mcp.store
            .get_record("enrollment_invitation", &invitation.nonce)
            .await
            .unwrap()
            .unwrap()["consumed"],
        false
    );
    let mut expired = invitation.clone();
    expired.expires_at = now() - 1;
    assert!(
        mcp.redeem_device(json!({"invitation":expired,"proof":proof}))
            .await
            .is_err()
    );
    assert!(mcp.store.list_records("device").await.unwrap().is_empty());
}

#[tokio::test]
async fn service_policy_only_expands_and_revoked_identity_cannot_be_reenabled() {
    let dir = tempfile::tempdir().unwrap();
    let mcp = Mcp::open(config(dir.path())).await.unwrap();
    let (_, principal) = authenticated(&mcp, "client-a").await;
    for id in ["dev-a", "dev-b"] {
        mcp.store
            .put_record("device", id, json!({"device_id":id,"revoked":false}))
            .await
            .unwrap();
    }
    mcp.allow_service(json!({"principal_id":principal.id(),"device_ids":["dev-a"]}))
        .await
        .unwrap();
    mcp.allow_service(json!({"principal_id":principal.id(),"device_ids":["dev-a","dev-b"]}))
        .await
        .unwrap();
    assert_eq!(
        mcp.allow_service(json!({"principal_id":principal.id(),"device_ids":["dev-a"]}))
            .await
            .unwrap_err()
            .to_string(),
        "SERVICE_PERMISSION_NARROWING_REQUIRES_AUTH_REVOKE"
    );
    assert_eq!(
        mcp.store
            .get_record("service_allow", &principal.id().0)
            .await
            .unwrap()
            .unwrap(),
        json!(["dev-a", "dev-b"])
    );
    mcp.revoke_access(&principal.client_registration_id)
        .await
        .unwrap();
    assert_eq!(
        mcp.allow_service(json!({"principal_id":principal.id(),"device_ids":["dev-a","dev-b"]}))
            .await
            .unwrap_err()
            .to_string(),
        "PRINCIPAL_REVOKED_REAUTHORIZE_NEW_CLIENT"
    );
}

#[tokio::test]
async fn offline_revocation_is_confirmed_by_signed_reconnect_and_online_ack() {
    let dir = tempfile::tempdir().unwrap();
    let ca = CertificateAuthority::new();
    let mut config = config(dir.path());
    config.device_tls = ca.leaf(dir.path(), "server-revoke", true);
    let mcp = Arc::new(Mcp::open(config).await.unwrap());
    let (_, principal) = authenticated(&mcp, "client-revoke").await;
    let identity = IdentityFile::create(&dir.path().join("device-revoke.json")).unwrap();
    let id = identity.id("dev").unwrap();
    let tls = ca.leaf(dir.path(), "device-revoke", false);
    mcp.register_device(json!(DeviceRegistration {
        device_id: id.clone(),
        name: "offline".into(),
        public_key: identity.public_key().unwrap(),
        certificate_digest: orc_transport::certificate_file_digest(&tls.certificate).unwrap(),
        revoked: false
    }))
    .await
    .unwrap();
    let revoked = mcp
        .revoke_access(&principal.client_registration_id)
        .await
        .unwrap();
    assert_eq!(revoked["delivery"]["requested"], 1);
    assert_eq!(revoked["delivery"]["delivered"], 0);
    assert_eq!(
        mcp.auth_show(&principal.client_registration_id)
            .await
            .unwrap()["delivery"]["devices"][0]["state"],
        "requested"
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(mcp.clone().serve_devices_on(listener));
    let device = fake_device(&mcp, address, identity, tls, principal.clone(), 1).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if mcp
                .revocation_deliveries(Some(&principal.id().0))
                .await
                .unwrap()["delivered"]
                == 1
            {
                break;
            }
            tokio::task::yield_now().await
        }
    })
    .await
    .unwrap();
    let old_revision = revoked["service_revision"].as_u64().unwrap();
    let again = mcp
        .revoke_access(&principal.client_registration_id)
        .await
        .unwrap();
    let new_revision = again["service_revision"].as_u64().unwrap();
    assert!(new_revision > old_revision);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let delivery = mcp
                .revocation_deliveries(Some(&principal.id().0))
                .await
                .unwrap();
            if delivery["delivered"] == 1 && delivery["devices"][0]["revision"] == new_revision {
                break;
            }
            tokio::task::yield_now().await
        }
    })
    .await
    .unwrap();
    let status = mcp
        .auth_show(&principal.client_registration_id)
        .await
        .unwrap();
    assert_eq!(status["access_revoked"], true);
    assert_eq!(status["delivery"]["stop_state"], "not_implied_by_delivery");
    assert!(status["delivery"]["devices"][0]["delivered_at"].is_u64());
    device.abort();
    let _ = device.await;
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn revocation_delivery_repairs_partial_records_and_rejects_wrong_channel_ack() {
    let dir = tempfile::tempdir().unwrap();
    let mcp = Mcp::open(config(dir.path())).await.unwrap();
    for id in ["dev-a", "dev-b"] {
        mcp.store
            .put_record("device", id, json!({"device_id":id,"revoked":false}))
            .await
            .unwrap();
    }
    // Model interruption after the authoritative revocation write and before
    // the derived per-device records and the revision metadata were written.
    mcp.store
        .put_record(
            "service_revoked",
            "principal-a",
            json!({"principal_id":"principal-a","revision":5,"requested_at":now()}),
        )
        .await
        .unwrap();
    assert_eq!(mcp.service_revision().await.unwrap(), 5);
    assert_eq!(
        mcp.revocation_deliveries(None).await.unwrap()["requested"],
        2
    );
    mcp.repair_delivery_records().await.unwrap();
    assert_eq!(
        mcp.revocation_deliveries(None).await.unwrap()["requested"],
        2
    );
    let (sender, _data) = mpsc::channel(1);
    let (control, _controls) = mpsc::channel(1);
    let (maintenance, _probes) = mpsc::channel(1);
    mcp.connections.lock().await.insert(
        "dev-a".into(),
        Connection {
            epoch: 8,
            service_revision: 5,
            capabilities: orc_transport::capabilities(),
            sender,
            control,
            closed: Default::default(),
            maintenance,
        },
    );
    assert!(
        mcp.acknowledge_revocation("dev-a", 7, "principal-a", 5)
            .await
            .is_err()
    );
    assert!(
        mcp.acknowledge_revocation("dev-a", 8, "principal-a", 6)
            .await
            .is_err()
    );
    assert!(
        mcp.acknowledge_revocation("dev-b", 8, "principal-a", 5)
            .await
            .is_err()
    );
    assert_eq!(
        mcp.revocation_deliveries(None).await.unwrap()["requested"],
        2
    );
    mcp.acknowledge_revocation("dev-a", 8, "principal-a", 5)
        .await
        .unwrap();
    assert_eq!(
        mcp.revocation_deliveries(None).await.unwrap()["delivered"],
        1
    );
    mcp.repair_delivery_records().await.unwrap();
    assert_eq!(
        mcp.revocation_deliveries(None).await.unwrap()["delivered"],
        1
    );
}

#[test]
fn owner_audit_only_contains_bounded_operation_metadata() {
    let event = revocation::owner_audit("auth.revoke", true).unwrap();
    let serialized = serde_json::to_value(event).unwrap();
    assert_eq!(serialized["action"], "owner.auth.revoke");
    assert_eq!(serialized["outcome"], "succeeded");
    assert!(serialized["principal_id"].is_null());
    assert!(serialized.get("params").is_none());
    assert!(serialized.get("error").is_none());
    assert!(revocation::owner_audit("auth.pending", true).is_none());
    assert!(revocation::owner_audit("arbitrary request body", false).is_none());
}

#[tokio::test]
async fn uninstall_revokes_once_and_requires_known_stop_and_delivery_before_backup() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let mcp = Arc::new(Mcp::open(config(dir.path())).await.unwrap());
    let (token, principal) = authenticated(&mcp, "uninstall-client").await;
    mcp.store.put_record("device","dev-uninstall",json!({"device_id":"dev-uninstall","name":"test","public_key":"unused","certificate_digest":"unused","revoked":false})).await.unwrap();
    mcp.store
        .put_record("service_allow", &principal.id().0, json!(["dev-uninstall"]))
        .await
        .unwrap();
    let (sender, _data) = mpsc::channel(1);
    let (control, mut controls) = mpsc::channel(4);
    let (maintenance, mut probes) = mpsc::channel::<MaintenanceProbe>(4);
    mcp.connections.lock().await.insert(
        "dev-uninstall".into(),
        Connection {
            epoch: 9,
            service_revision: 1,
            capabilities: orc_transport::capabilities(),
            sender,
            control,
            closed: Default::default(),
            maintenance,
        },
    );
    let unknown = Arc::new(AtomicBool::new(true));
    let revocations = Arc::new(AtomicUsize::new(0));
    let worker_unknown = unknown.clone();
    let worker_revocations = revocations.clone();
    let worker = tokio::spawn(async move {
        loop {
            tokio::select! {biased;
                control=controls.recv()=>{if matches!(control,Some(Frame::Revoke{..})){worker_revocations.fetch_add(1,Ordering::SeqCst);}else{break}},
                probe=probes.recv()=>{let Some(probe)=probe else{break};let _=probe.reply.send(Ok(json!({"active_tasks":0,"unresolved_tasks":u64::from(worker_unknown.load(Ordering::SeqCst))})));}
            }
        }
    });
    assert_eq!(
        mcp.uninstall_prepare().await.unwrap_err().to_string(),
        "MAINTENANCE_TASKS_NOT_TERMINAL"
    );
    assert!(
        mcp.auth
            .authenticate(&token.access_token, now())
            .await
            .is_err()
    );
    assert!(
        mcp.service_allowed(&principal, "dev-uninstall")
            .await
            .is_err()
    );
    assert_eq!(
        mcp.store
            .get_record("maintenance", "state")
            .await
            .unwrap()
            .unwrap()["active"],
        true
    );
    let revision = mcp.service_revision().await.unwrap();
    unknown.store(false, Ordering::SeqCst);
    assert_eq!(
        mcp.uninstall_prepare().await.unwrap_err().to_string(),
        "UNINSTALL_REVOCATION_NOT_DELIVERED"
    );
    assert_eq!(mcp.service_revision().await.unwrap(), revision);
    assert_eq!(revocations.load(Ordering::SeqCst), 1);
    mcp.acknowledge_revocation("dev-uninstall", 9, &principal.id().0, revision)
        .await
        .unwrap();
    let prepared = mcp.uninstall_prepare().await.unwrap();
    assert_eq!(prepared["revocation_applied"], true);
    assert_eq!(prepared["pending_revocation_deliveries"], 0);
    assert_eq!(prepared["active_tasks"], 0);
    assert_eq!(prepared["unresolved_tasks"], 0);
    assert!(std::path::Path::new(prepared["backup_path"].as_str().unwrap()).exists());
    assert_eq!(mcp.service_revision().await.unwrap(), revision);
    assert_eq!(revocations.load(Ordering::SeqCst), 1);
    worker.abort();
    let _ = worker.await;
}

use super::*;

const NOW: u64 = 1_900_000_000;
const RESOURCE: &str = "http://127.0.0.1:7790/mcp";
const REDIRECT: &str = "http://127.0.0.1:4200/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

async fn setup() -> (tempfile::TempDir, Store, Auth, Client) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let auth = Auth::open(
        store.clone(),
        RESOURCE.into(),
        "mcp-a".into(),
        "owner-a".into(),
        "auth-a".into(),
    )
    .await
    .unwrap();
    let client = auth
        .register("test client".into(), vec![REDIRECT.into()], NOW)
        .await
        .unwrap();
    (dir, store, auth, client)
}

fn authorization(client: &Client) -> Authorization {
    Authorization {
        client_id: client.client_id.clone(),
        redirect_uri: REDIRECT.into(),
        response_type: "code".into(),
        scope: "orc".into(),
        resource: RESOURCE.into(),
        state: "client-csrf-state".into(),
        code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes())),
        code_challenge_method: "S256".into(),
    }
}

async fn code(auth: &Auth, client: &Client) -> String {
    let (login, nonce) = auth.begin(authorization(client), NOW).await.unwrap();
    assert!(matches!(
        auth.complete(&login.id, &nonce, NOW).await,
        Err(AuthError::Pending)
    ));
    auth.approve(&login.id, NOW).await.unwrap();
    let redirect = auth.complete(&login.id, &nonce, NOW).await.unwrap();
    let url = Url::parse(&redirect).unwrap();
    assert_eq!(
        url.query_pairs().find(|(key, _)| key == "state").unwrap().1,
        "client-csrf-state"
    );
    url.query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .to_string()
}

async fn tokens(auth: &Auth, client: &Client) -> Tokens {
    let code = code(auth, client).await;
    auth.exchange(&client.client_id, &code, REDIRECT, VERIFIER, RESOURCE, NOW)
        .await
        .unwrap()
}

#[tokio::test]
async fn native_flow_is_persistent_single_use_and_registration_scoped() {
    let (_dir, store, auth, client) = setup().await;
    let code = code(&auth, &client).await;
    let result = auth
        .exchange(&client.client_id, &code, REDIRECT, VERIFIER, RESOURCE, NOW)
        .await
        .unwrap();
    let principal = auth
        .authenticate(&result.access_token, NOW + 1)
        .await
        .unwrap();
    assert_eq!(principal.client_registration_id, client.client_id);
    assert!(
        auth.exchange(&client.client_id, &code, REDIRECT, VERIFIER, RESOURCE, NOW)
            .await
            .is_err()
    );
    assert!(auth.authenticate(&result.refresh_token, NOW).await.is_err());
    let reopened = Auth::open(
        store.clone(),
        RESOURCE.into(),
        "mcp-a".into(),
        "owner-a".into(),
        "auth-a".into(),
    )
    .await
    .unwrap();
    assert_eq!(
        reopened
            .authenticate(&result.access_token, NOW + 1)
            .await
            .unwrap(),
        principal
    );
    assert!(
        reopened
            .exchange(&client.client_id, &code, REDIRECT, VERIFIER, RESOURCE, NOW)
            .await
            .is_err()
    );
    let raw =
        serde_json::to_string(&store.get_record("oauth", "state").await.unwrap().unwrap()).unwrap();
    for secret in [&result.access_token, &result.refresh_token, &code] {
        assert!(!raw.contains(secret));
    }
}

#[tokio::test]
async fn pkce_and_resource_binding_cannot_be_downgraded() {
    let (_dir, _, auth, client) = setup().await;
    for mutation in 0..5 {
        let mut request = authorization(&client);
        match mutation {
            0 => request.code_challenge_method = "plain".into(),
            1 => request.code_challenge.clear(),
            2 => request.resource = "https://other.example/mcp".into(),
            3 => request.redirect_uri = "https://attacker.example/callback".into(),
            4 => request.scope = "orc admin".into(),
            _ => unreachable!(),
        }
        assert!(auth.begin(request, NOW).await.is_err());
    }
    let code = code(&auth, &client).await;
    assert!(
        auth.exchange(
            &client.client_id,
            &code,
            REDIRECT,
            &"a".repeat(43),
            RESOURCE,
            NOW
        )
        .await
        .is_err()
    );
    assert!(
        auth.exchange(
            &client.client_id,
            &code,
            REDIRECT,
            VERIFIER,
            "https://other.example/mcp",
            NOW
        )
        .await
        .is_err()
    );
    assert!(
        auth.exchange(
            &client.client_id,
            &code,
            "https://attacker.example",
            VERIFIER,
            RESOURCE,
            NOW
        )
        .await
        .is_err()
    );
    assert!(
        auth.exchange("different-client", &code, REDIRECT, VERIFIER, RESOURCE, NOW)
            .await
            .is_err()
    );
    auth.exchange(&client.client_id, &code, REDIRECT, VERIFIER, RESOURCE, NOW)
        .await
        .unwrap();
}

#[tokio::test]
async fn consent_is_browser_nonce_bound_and_expires() {
    let (_dir, _, auth, client) = setup().await;
    let (pending, nonce) = auth.begin(authorization(&client), NOW).await.unwrap();
    auth.approve(&pending.id, NOW).await.unwrap();
    assert!(
        auth.complete(&pending.id, "wrong-browser", NOW)
            .await
            .is_err()
    );
    assert!(auth.complete(&pending.id, &nonce, NOW + 300).await.is_err());
    assert!(auth.approve(&pending.id, NOW + 300).await.is_err());
}

#[tokio::test]
async fn refresh_rotation_detects_reuse_and_revokes_the_entire_family() {
    let (_dir, store, auth, client) = setup().await;
    let original = tokens(&auth, &client).await;
    let rotated = auth
        .refresh(
            &client.client_id,
            &original.refresh_token,
            RESOURCE,
            NOW + 1,
        )
        .await
        .unwrap();
    assert_eq!(
        auth.authenticate(&original.access_token, NOW + 1)
            .await
            .unwrap()
            .id(),
        auth.authenticate(&rotated.access_token, NOW + 1)
            .await
            .unwrap()
            .id()
    );
    assert!(
        auth.refresh(
            &client.client_id,
            &original.refresh_token,
            RESOURCE,
            NOW + 2
        )
        .await
        .is_err()
    );
    assert!(
        auth.authenticate(&original.access_token, NOW + 2)
            .await
            .is_err()
    );
    assert!(
        auth.authenticate(&rotated.access_token, NOW + 2)
            .await
            .is_err()
    );
    assert!(
        auth.refresh(&client.client_id, &rotated.refresh_token, RESOURCE, NOW + 2)
            .await
            .is_err()
    );
    let reopened = Auth::open(
        store,
        RESOURCE.into(),
        "mcp-a".into(),
        "owner-a".into(),
        "auth-a".into(),
    )
    .await
    .unwrap();
    assert!(
        reopened
            .authenticate(&rotated.access_token, NOW + 2)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn concurrent_code_exchange_has_one_success() {
    let (_dir, _, auth, client) = setup().await;
    let code = code(&auth, &client).await;
    let (first, second) = tokio::join!(
        auth.exchange(&client.client_id, &code, REDIRECT, VERIFIER, RESOURCE, NOW),
        auth.exchange(&client.client_id, &code, REDIRECT, VERIFIER, RESOURCE, NOW)
    );
    assert_ne!(first.is_ok(), second.is_ok());
}

#[tokio::test]
async fn concurrent_refresh_reuse_revokes_successful_sibling() {
    let (_dir, _, auth, client) = setup().await;
    let original = tokens(&auth, &client).await;
    let (first, second) = tokio::join!(
        auth.refresh(
            &client.client_id,
            &original.refresh_token,
            RESOURCE,
            NOW + 1
        ),
        auth.refresh(
            &client.client_id,
            &original.refresh_token,
            RESOURCE,
            NOW + 1
        )
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let successful = first.or(second).unwrap();
    assert!(
        auth.authenticate(&successful.access_token, NOW + 2)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn expiry_and_revocation_deny_bearer_reads() {
    let (_dir, _, auth, client) = setup().await;
    let first = tokens(&auth, &client).await;
    assert!(
        auth.authenticate(&first.access_token, NOW + 600)
            .await
            .is_err()
    );
    assert!(
        auth.refresh(
            &client.client_id,
            &first.refresh_token,
            RESOURCE,
            NOW + 30 * 86400
        )
        .await
        .is_err()
    );
    auth.revoke_token(&first.refresh_token, &client.client_id)
        .await
        .unwrap();
    assert!(
        auth.authenticate(&first.access_token, NOW + 1)
            .await
            .is_err()
    );
    let second = tokens(&auth, &client).await;
    auth.revoke_client(&client.client_id).await.unwrap();
    assert!(
        auth.authenticate(&second.access_token, NOW + 1)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn registrations_do_not_inherit_identity_by_name_and_reject_unsafe_redirects() {
    let (_dir, _, auth, client) = setup().await;
    let second = auth
        .register(
            client.client_name.clone(),
            client.redirect_uris.clone(),
            NOW,
        )
        .await
        .unwrap();
    assert_ne!(client.client_id, second.client_id);
    for bad in [
        "http://example.com/callback",
        "http://localhost/callback",
        "https://example.com/callback#fragment",
        "https://name:secret@example.com/callback",
        "javascript:alert(1)",
    ] {
        assert!(
            auth.register("test".into(), vec![bad.into()], NOW)
                .await
                .is_err()
        );
    }
    auth.register(
        "IPv6".into(),
        vec!["http://[::1]:1234/callback".into()],
        NOW,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn dropped_response_does_not_discard_authorization_mutation() {
    let (_dir, store, auth, client) = setup().await;
    let (pending, _nonce) = auth.begin(authorization(&client), NOW).await.unwrap();
    let pending_id = pending.id.clone();
    let (reply, response) = oneshot::channel();
    auth.actor
        .sender
        .send(Job {
            write: true,
            mutation: Box::new(move |state| {
                state.pending.get_mut(&pending_id).unwrap().approved = true;
                encode(())
            }),
            reply,
        })
        .await
        .unwrap();
    drop(response);
    // The next actor read is ordered after the durable mutation.
    assert!(
        auth.pending(NOW)
            .await
            .iter()
            .find(|p| p.id == pending.id)
            .unwrap()
            .approved
    );
    let reopened = Auth::open(
        store,
        RESOURCE.into(),
        "mcp-a".into(),
        "owner-a".into(),
        "auth-a".into(),
    )
    .await
    .unwrap();
    assert!(
        reopened
            .pending(NOW)
            .await
            .iter()
            .find(|p| p.id == pending.id)
            .unwrap()
            .approved
    );
}

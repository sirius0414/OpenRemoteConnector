use super::*;
use orc_domain::{Action, Command, ExecutionContext, Limits, Stdin, TaskRequest};
use serde_json::json;

#[test]
fn recursively_rejects_duplicate_keys_and_noninteger_numbers() {
    for input in [
        r#"{"a":1,"a":2}"#,
        r#"{"nested":[{"a":1,"a":1}]}"#,
        r#"{"a":1.0}"#,
        r#"{"a":1e0}"#,
        r#"{"a":9007199254740992}"#,
        r#"{} {}"#,
    ] {
        assert!(
            strict_decode::<Value>(input.as_bytes()).is_err(),
            "accepted {input}"
        );
    }
    assert!(strict_decode::<Value>(&vec![b' '; MAX_MESSAGE_BYTES + 1]).is_err());
    assert_eq!(
        strict_decode::<Value>(br#"{"a":1,"nested":[true,null,"safe"]}"#).unwrap()["a"],
        1
    );
}

#[test]
fn canonical_digest_ignores_object_order_but_preserves_array_order() {
    let a: Value = strict_decode(br#"{"b":2,"a":[1,2]}"#).unwrap();
    let b: Value = strict_decode(br#"{"a":[1,2],"b":2}"#).unwrap();
    let c: Value = strict_decode(br#"{"a":[2,1],"b":2}"#).unwrap();
    assert_eq!(canonical_bytes(&a).unwrap(), br#"{"a":[1,2],"b":2}"#);
    assert_eq!(canonical_digest(&a).unwrap(), canonical_digest(&b).unwrap());
    assert_ne!(canonical_digest(&a).unwrap(), canonical_digest(&c).unwrap());
    assert!(canonical_bytes(&json!(1.0)).is_err());
}

#[test]
fn canonical_order_uses_utf16_including_astral_keys() {
    let data = json!({"\u{e000}": 1, "\u{1f600}": 2, "\n": "\"\\"});
    assert_eq!(
        String::from_utf8(canonical_bytes(&data).unwrap()).unwrap(),
        "{\"\\n\":\"\\\"\\\\\",\"😀\":2,\"\u{e000}\":1}"
    );
}

fn task() -> TaskRequest {
    TaskRequest {
        submission_id: SubmissionId::generate(),
        device_id: "dev-a".into(),
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
        request_expires_at: 200,
    }
}

#[test]
fn task_schema_rejects_identity_override_and_ambiguous_commands() {
    let mut data = serde_json::to_value(task()).unwrap();
    data["principal_id"] = json!("other-user");
    assert!(strict_decode::<TaskRequest>(&serde_json::to_vec(&data).unwrap()).is_err());
    let mut data = serde_json::to_value(task()).unwrap();
    data["command"]["script"] = json!("malicious");
    assert!(strict_decode::<TaskRequest>(&serde_json::to_vec(&data).unwrap()).is_err());
}

fn envelope() -> Envelope {
    let task = task();
    let request = serde_json::to_value(&task).unwrap();
    Envelope {
        protocol_major: 1,
        mcp_id: "mcp-a".into(),
        device_id: "dev-a".into(),
        principal: Principal {
            mcp_id: "mcp-a".into(),
            auth_domain_id: "auth-a".into(),
            owner_id: "owner-a".into(),
            client_registration_id: "client-a".into(),
        },
        connection_epoch: 7,
        operation: "orc_task_submit".into(),
        submission_id: Some(task.submission_id),
        request_digest: canonical_digest(&request).unwrap(),
        request,
        service_policy_revision: 3,
        required_capabilities: BTreeSet::new(),
        sent_at: 100,
        delivery_expires_at: 130,
    }
}

#[test]
fn signature_binds_principal_target_request_and_channel_epoch() {
    let key = SigningKey::from_bytes(&[17; 32]);
    let signed = SignedEnvelope::sign(envelope(), &key).unwrap();
    let capabilities = operation_capabilities("orc_task_submit").unwrap();
    let mcp = "mcp-a".into();
    let device = "dev-a".into();
    let context = EnvelopeContext {
        mcp_id: &mcp,
        device_id: &device,
        connection_epoch: 7,
        service_policy_revision: 3,
        capabilities: &capabilities,
        now: 101,
    };
    signed.verify(&key.verifying_key(), &context).unwrap();
    let mut changed = signed.clone();
    changed.payload.principal.owner_id = "attacker".into();
    assert!(changed.verify(&key.verifying_key(), &context).is_err());
    let mut changed = signed.clone();
    changed.payload.request["command"]["args"] = json!(["other"]);
    assert!(changed.verify(&key.verifying_key(), &context).is_err());
    let wrong_epoch = EnvelopeContext {
        connection_epoch: 8,
        ..context
    };
    assert!(signed.verify(&key.verifying_key(), &wrong_epoch).is_err());
    assert!(
        signed
            .verify(&SigningKey::from_bytes(&[18; 32]).verifying_key(), &context)
            .is_err()
    );
}

#[test]
fn signed_but_wrong_target_expiry_or_schema_is_rejected() {
    let key = SigningKey::from_bytes(&[17; 32]);
    let capabilities = operation_capabilities("orc_task_submit").unwrap();
    let mcp = "mcp-a".into();
    let device = "dev-a".into();
    let context = EnvelopeContext {
        mcp_id: &mcp,
        device_id: &device,
        connection_epoch: 7,
        service_policy_revision: 3,
        capabilities: &capabilities,
        now: 101,
    };
    for mutation in 0..5 {
        let mut payload = envelope();
        match mutation {
            0 => payload.device_id = "dev-b".into(),
            1 => payload.principal.mcp_id = "mcp-b".into(),
            2 => payload.delivery_expires_at = 100,
            3 => payload.delivery_expires_at = 200,
            4 => payload.operation = "grant.create".into(),
            _ => unreachable!(),
        }
        let signed = SignedEnvelope::sign(payload, &key).unwrap();
        assert!(signed.verify(&key.verifying_key(), &context).is_err());
    }
}

#[test]
fn omitted_capabilities_do_not_downgrade_trusted_schema() {
    let key = SigningKey::from_bytes(&[17; 32]);
    let signed = SignedEnvelope::sign(envelope(), &key).unwrap();
    let capabilities = BTreeSet::new();
    let mcp = "mcp-a".into();
    let device = "dev-a".into();
    let context = EnvelopeContext {
        mcp_id: &mcp,
        device_id: &device,
        connection_epoch: 7,
        service_policy_revision: 3,
        capabilities: &capabilities,
        now: 101,
    };
    assert_eq!(
        signed
            .verify(&key.verifying_key(), &context)
            .unwrap_err()
            .code,
        ErrorCode::CapabilityUnavailable
    );
    assert!(operation_capabilities("approval.approve").is_err());
}

#[test]
fn chunk_order_length_hash_and_budget_are_checked() {
    let bytes = b"safe content".to_vec();
    let mut chunk = Chunk {
        transfer_id: "transfer-a".into(),
        sequence: 2,
        length: bytes.len(),
        digest: format!("sha256:{:x}", Sha256::digest(&bytes)),
        bytes,
    };
    chunk.validate(2).unwrap();
    assert!(chunk.validate(1).is_err());
    chunk.bytes[0] = b'X';
    assert!(chunk.validate(2).is_err());
}

#[test]
fn action_wire_names_are_stable() {
    assert_eq!(
        serde_json::to_string(&Action::TaskSubmit).unwrap(),
        "\"task.submit\""
    );
    assert_eq!(
        serde_json::to_string(&ErrorCode::AccessDenied).unwrap(),
        "\"ACCESS_DENIED\""
    );
}

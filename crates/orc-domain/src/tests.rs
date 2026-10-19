use super::*;

fn request(environment: Environment) -> TaskRequest {
    TaskRequest {
        submission_id: SubmissionId::generate(),
        device_id: "device-a".into(),
        grant_id: "grant-a".into(),
        environment_profile_id: "profile-a".into(),
        context: match environment {
            Environment::Host => ExecutionContext {
                host_context_id: Some("host-a".into()),
                snapshot_id: None,
                workspace_id: None,
                cwd: "/srv/project".into(),
            },
            Environment::Isolated => ExecutionContext {
                host_context_id: None,
                snapshot_id: Some("snapshot-a".into()),
                workspace_id: Some("workspace-a".into()),
                cwd: "/work/project".into(),
            },
        },
        command: Command::Argv {
            program: "python3".into(),
            args: vec!["literal | $HOME > file".into()],
        },
        stdin: Stdin::default(),
        env_overrides: BTreeMap::new(),
        limits: Limits::default(),
        request_expires_at: 200,
    }
}

fn grant(environment: Environment, policy: Policy) -> Grant {
    Grant {
        id: "grant-a".into(),
        principal_id: "principal-a".into(),
        device_id: "device-a".into(),
        execution_uid: 1000,
        actions: [
            Action::DeviceDiscover,
            Action::TaskSubmit,
            Action::TaskInspect,
            Action::ResultRead,
        ]
        .into_iter()
        .collect(),
        environment,
        environment_profile_id: "profile-a".into(),
        environment_digest: "sha256:profile".into(),
        host_context_id: (environment == Environment::Host).then(|| "host-a".into()),
        workspace_ids: if environment == Environment::Isolated {
            ["workspace-a".into()].into_iter().collect()
        } else {
            BTreeSet::new()
        },
        allowed_env: ["LANG".into()].into_iter().collect(),
        policy,
        revision: 1,
        issued_at: 1,
        expires_at: 500,
        status: GrantStatus::Active,
    }
}

fn matches_all() -> RuleMatch {
    RuleMatch {
        principal: FieldMatch::Any(true),
        device: FieldMatch::Any(true),
        account: FieldMatch::Any(true),
        environment: FieldMatch::Any(true),
        action: FieldMatch::Any(true),
        cwd: FieldMatch::Any(true),
        command_kind: FieldMatch::Any(true),
        program: FieldMatch::Any(true),
        args: ArgsMatch::Any(true),
    }
}

fn rules(effects: &[RuleEffect]) -> RuleSet {
    RuleSet {
        revision: 1,
        unmatched: UnmatchedEffect::Deny,
        rules: effects
            .iter()
            .enumerate()
            .map(|(i, effect)| Rule {
                id: format!("rule-{i}"),
                effect: *effect,
                matches: matches_all(),
            })
            .collect(),
    }
}

#[test]
fn six_policy_environment_combinations_preserve_authorization() {
    let principal = PrincipalId::from("principal-a");
    for environment in [Environment::Host, Environment::Isolated] {
        for policy in [
            Policy::Automatic,
            Policy::Review,
            Policy::Rules {
                policy: rules(&[RuleEffect::Allow]),
            },
        ] {
            let g = grant(environment, policy);
            let req = request(environment);
            g.authorize(&principal, &req, Action::TaskSubmit, 100)
                .unwrap();
            let mut wrong = req.clone();
            wrong.device_id = "device-b".into();
            assert_eq!(
                g.authorize(&principal, &wrong, Action::TaskSubmit, 100)
                    .unwrap_err()
                    .code,
                ErrorCode::AccessDenied
            );
            assert!(
                g.authorize(&"principal-b".into(), &req, Action::TaskSubmit, 100)
                    .is_err()
            );
            let mut wrong = req.clone();
            wrong.environment_profile_id = "other-environment".into();
            assert!(
                g.authorize(&principal, &wrong, Action::TaskSubmit, 100)
                    .is_err()
            );
            assert_eq!(
                g.authorize(&principal, &req, Action::TaskSubmit, 500)
                    .unwrap_err()
                    .code,
                ErrorCode::GrantExpired
            );
            let mut revoked = g.clone();
            revoked.status = GrantStatus::Revoked;
            assert_eq!(
                revoked
                    .authorize(&principal, &req, Action::TaskSubmit, 100)
                    .unwrap_err()
                    .code,
                ErrorCode::GrantRevoked
            );
        }
    }
}

#[test]
fn grant_does_not_inherit_context_or_environment_overrides() {
    let g = grant(Environment::Host, Policy::Automatic);
    let mut req = request(Environment::Host);
    req.env_overrides
        .insert("LD_PRELOAD".into(), "secret.so".into());
    assert_eq!(
        g.authorize(&"principal-a".into(), &req, Action::TaskSubmit, 100)
            .unwrap_err()
            .code,
        ErrorCode::AccessDenied
    );
    req.env_overrides.clear();
    req.context.host_context_id = Some("ungranted".into());
    assert_eq!(
        g.authorize(&"principal-a".into(), &req, Action::TaskSubmit, 100)
            .unwrap_err()
            .code,
        ErrorCode::AccessDenied
    );
    let req = request(Environment::Isolated);
    assert!(
        g.authorize(&"principal-a".into(), &req, Action::TaskSubmit, 100)
            .is_err()
    );
}

#[test]
fn rule_precedence_is_independent_of_rule_order() {
    let principal = "principal-a".into();
    let device = "device-a".into();
    let c = RuleContext {
        principal: &principal,
        device: &device,
        account: 1000,
        environment: "profile-a",
        action: Action::TaskSubmit,
        cwd: "/work",
        command_kind: CommandKind::Argv,
        program: "sha256:resolved-entry",
        args: &[],
    };
    for effects in [
        vec![RuleEffect::Allow, RuleEffect::Review, RuleEffect::Deny],
        vec![RuleEffect::Deny, RuleEffect::Review, RuleEffect::Allow],
        vec![RuleEffect::Review, RuleEffect::Allow, RuleEffect::Deny],
    ] {
        let d = rules(&effects).evaluate(&c);
        assert_eq!(d.effect, RuleEffect::Deny);
        assert_eq!(d.matched_rules.len(), 3);
        assert!(d.unrestricted_fields.contains(&"program".into()));
    }
    assert_eq!(
        rules(&[RuleEffect::Allow, RuleEffect::Review])
            .evaluate(&c)
            .effect,
        RuleEffect::Review
    );
    assert_eq!(
        rules(&[RuleEffect::Allow]).evaluate(&c).effect,
        RuleEffect::Allow
    );
    assert_eq!(rules(&[]).evaluate(&c).effect, RuleEffect::Deny);
}

#[test]
fn exact_directory_is_not_a_prefix_and_entry_identity_is_required() {
    let principal = "principal-a".into();
    let device = "device-a".into();
    let mut c = RuleContext {
        principal: &principal,
        device: &device,
        account: 1000,
        environment: "profile-a",
        action: Action::TaskSubmit,
        cwd: "/work/project-other",
        command_kind: CommandKind::Argv,
        program: "sha256:python",
        args: &[],
    };
    let mut r = rules(&[RuleEffect::Allow]);
    r.rules[0].matches.cwd = FieldMatch::Exact("/work/project".into());
    assert_eq!(r.evaluate(&c).effect, RuleEffect::Deny);
    c.cwd = "/work/project";
    assert_eq!(r.evaluate(&c).effect, RuleEffect::Allow);
    c.program = "";
    assert_eq!(r.evaluate(&c).effect, RuleEffect::Deny);
}

#[test]
fn positional_rules_cannot_implicitly_allow_extra_arguments() {
    let fixed = ArgsMatch::Positions(PositionMatch {
        values: [(0, "-m".into()), (1, "unittest".into())]
            .into_iter()
            .collect(),
        allow_extra: false,
    });
    assert!(fixed.matches(&["-m".into(), "unittest".into()]));
    assert!(!fixed.matches(&["-m".into(), "unittest".into(), "extra".into()]));
    let invalid = ArgsMatch::Positions(PositionMatch {
        values: [(1, "test".into())].into_iter().collect(),
        allow_extra: false,
    });
    assert!(invalid.validate().is_err());
    assert!(ArgsMatch::Any(false).validate().is_err());
}

#[test]
fn unknown_or_missing_rule_fields_fail_to_decode() {
    let mut value = serde_json::to_value(matches_all()).unwrap();
    value.as_object_mut().unwrap().remove("program");
    assert!(serde_json::from_value::<RuleMatch>(value).is_err());
    let mut value = serde_json::to_value(matches_all()).unwrap();
    value["shell"] = serde_json::json!({"any":true});
    assert!(serde_json::from_value::<RuleMatch>(value).is_err());
    let mut r = rules(&[RuleEffect::Allow]);
    r.rules[0].matches.program = FieldMatch::Any(false);
    assert!(r.validate().is_err());
}

#[test]
fn uuid_window_cannot_be_extended_with_an_external_timestamp() {
    let now = 2_000_000_u64;
    let create_id = |seconds: u64| {
        let mut bytes = [0_u8; 16];
        bytes[..6].copy_from_slice(&(seconds * 1000).to_be_bytes()[2..]);
        bytes[6] = 0x70;
        bytes[8] = 0x80;
        SubmissionId(uuid::Uuid::from_bytes(bytes).to_string())
    };
    create_id(now).validate_fresh(now, now + 60).unwrap();
    assert_eq!(
        create_id(now - 86_400)
            .validate_fresh(now, now + 60)
            .unwrap_err()
            .code,
        ErrorCode::SubmissionExpired
    );
    assert_eq!(
        create_id(now + 61)
            .validate_fresh(now, now + 120)
            .unwrap_err()
            .code,
        ErrorCode::ClockSkew
    );
    assert!(create_id(now).validate_fresh(now, now + 86_401).is_err());
    assert!(
        SubmissionId("00000000-0000-4000-8000-000000000000".into())
            .validate_fresh(now, now + 10)
            .is_err()
    );
}

#[test]
fn state_machine_never_restarts_unknown_or_terminal_tasks() {
    assert!(!ExecutionState::Unknown.can_transition_to(ExecutionState::Accepted));
    assert!(!ExecutionState::Exited.can_transition_to(ExecutionState::Running));
    assert!(ExecutionState::Unknown.can_transition_to(ExecutionState::Exited));
    let mut status = TaskStatus::new(ExecutionState::Running, 100);
    status.stop_state = StopState::Requested;
    status.validate().unwrap();
    status.stop_state = StopState::Confirmed;
    assert!(status.validate().is_err());
    status.transition(ExecutionState::Exited, 101).unwrap();
    status.exit_code = Some(0);
    status.validate().unwrap();
}

#[test]
fn source_and_arguments_are_bounded_without_shell_interpretation() {
    let req = request(Environment::Host);
    req.validate().unwrap();
    assert_eq!(req.command.args(), &["literal | $HOME > file"]);
    let cmd = Command::Argv {
        program: "python3".into(),
        args: vec!["bad\0arg".into()],
    };
    assert!(cmd.validate().is_err());
    let cmd = Command::Script {
        interpreter: "python3".into(),
        interpreter_args: vec![],
        args: vec![],
        entry: ScriptEntry::Inline {
            value: "x".repeat(MAX_SCRIPT_BYTES + 1),
        },
    };
    assert!(cmd.validate().is_err());
    assert!(!format!("{req:?}").contains("$HOME"));
}

#[test]
fn principal_identity_is_stable_and_registration_specific() {
    let p = Principal {
        mcp_id: "mcp-a".into(),
        auth_domain_id: "domain-a".into(),
        owner_id: "owner-a".into(),
        client_registration_id: "client-a".into(),
    };
    assert_eq!(p.id(), p.clone().id());
    let mut other = p.clone();
    other.client_registration_id = "client-b".into();
    assert_ne!(p.id(), other.id());
    other = p.clone();
    other.owner_id = "replacement-owner".into();
    assert_ne!(p.id(), other.id());
}

#[test]
fn task_deadline_is_capped_by_grant_and_not_token_or_delivery_expiry() {
    let g = grant(Environment::Host, Policy::Automatic);
    let req = request(Environment::Host);
    assert_eq!(g.deadline(&req, 100), 220);
    assert_eq!(g.deadline(&req, 450), 500);
}

#[test]
fn terminal_escape_sequences_are_inert() {
    assert_eq!(
        sanitize_terminal("ok\u{1b}[31m\r\u{9b}\n"),
        "ok\\u{1b}[31m\\r\\u{9b}\n"
    );
}

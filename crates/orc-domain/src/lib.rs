//! Platform independent authorization and task contracts.
//! Names and client supplied labels never establish an identity.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

macro_rules! string_id {
    ($($name:ident),+ $(,)?) => {$ (
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(pub String);
        impl $name {
            pub fn new(value: impl Into<String>) -> Self { Self(value.into()) }
            pub fn as_str(&self) -> &str { &self.0 }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
        }
        impl From<String> for $name { fn from(s: String) -> Self { Self(s) } }
        impl From<&str> for $name { fn from(s: &str) -> Self { Self(s.to_owned()) } }
    )+};
}

string_id!(
    McpId,
    PrincipalId,
    DeviceId,
    GrantId,
    TaskId,
    SubmissionId,
    ApprovalId,
    SnapshotId
);

impl SubmissionId {
    pub fn generate() -> Self {
        Self(uuid::Uuid::now_v7().to_string())
    }

    /// This check is only for a previously unseen submission. Existing records
    /// must be looked up first and compared by digest, including after expiry.
    pub fn validate_fresh(&self, now: u64, request_expires_at: u64) -> Result<()> {
        let id = uuid::Uuid::parse_str(&self.0)
            .map_err(|_| Error::new(ErrorCode::InvalidRequest, "submission_id must be UUIDv7"))?;
        if id.get_version_num() != 7 || id.get_variant() != uuid::Variant::RFC4122 {
            return Err(Error::new(
                ErrorCode::InvalidRequest,
                "submission_id must be UUIDv7",
            ));
        }
        let bytes = id.as_bytes();
        let mut timestamp = [0_u8; 8];
        timestamp[2..].copy_from_slice(&bytes[..6]);
        let created_at = u64::from_be_bytes(timestamp) / 1000;
        if created_at > now.saturating_add(60) {
            return Err(Error::new(
                ErrorCode::ClockSkew,
                "submission clock is ahead; synchronize clocks",
            ));
        }
        if now >= created_at.saturating_add(86_400)
            || request_expires_at <= now
            || request_expires_at > created_at.saturating_add(86_400)
        {
            return Err(Error::new(
                ErrorCode::SubmissionExpired,
                "submission acceptance window has expired",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub mcp_id: McpId,
    pub auth_domain_id: String,
    pub owner_id: String,
    pub client_registration_id: String,
}

impl Principal {
    pub fn id(&self) -> PrincipalId {
        // Length framing is unambiguous even when identifiers contain separators.
        let mut hash = Sha256::new();
        hash.update(b"orc-principal-v1\0");
        for field in [
            &self.mcp_id.0,
            &self.auth_domain_id,
            &self.owner_id,
            &self.client_registration_id,
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        PrincipalId(format!("principal_{:x}", hash.finalize()))
    }

    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.mcp_id.0,
            &self.auth_domain_id,
            &self.owner_id,
            &self.client_registration_id,
        ] {
            validate_id(value)?;
        }
        Ok(())
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum Action {
    #[serde(rename = "device.discover")]
    DeviceDiscover,
    #[serde(rename = "snapshot.read")]
    SnapshotRead,
    #[serde(rename = "task.submit")]
    TaskSubmit,
    #[serde(rename = "task.inspect")]
    TaskInspect,
    #[serde(rename = "result.read")]
    ResultRead,
    #[serde(rename = "artifact.read")]
    ArtifactRead,
    #[serde(rename = "changes.propose")]
    ChangesPropose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    Host,
    Isolated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    Active,
    Revoked,
    Suspended,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: GrantId,
    pub principal_id: PrincipalId,
    pub device_id: DeviceId,
    pub execution_uid: u32,
    pub actions: BTreeSet<Action>,
    pub environment: Environment,
    pub environment_profile_id: String,
    pub environment_digest: String,
    pub host_context_id: Option<String>,
    pub workspace_ids: BTreeSet<String>,
    pub allowed_env: BTreeSet<String>,
    pub policy: Policy,
    pub revision: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub status: GrantStatus,
}

impl Grant {
    pub fn validate(&self) -> Result<()> {
        for id in [
            &self.id.0,
            &self.principal_id.0,
            &self.device_id.0,
            &self.environment_profile_id,
            &self.environment_digest,
        ] {
            validate_id(id)?;
        }
        if self.execution_uid == 0 || self.revision == 0 || self.expires_at <= self.issued_at {
            return Err(Error::new(
                ErrorCode::InvalidRequest,
                "grant requires an ordinary UID, revision and finite validity",
            ));
        }
        match self.environment {
            Environment::Host
                if self.host_context_id.as_ref().is_none_or(|s| s.is_empty())
                    || !self.workspace_ids.is_empty() =>
            {
                return Err(Error::new(
                    ErrorCode::InvalidRequest,
                    "host grant requires one host context and no workspace",
                ));
            }
            Environment::Isolated
                if self.host_context_id.is_some() || self.workspace_ids.is_empty() =>
            {
                return Err(Error::new(
                    ErrorCode::InvalidRequest,
                    "isolated grant requires workspace scope and no host context",
                ));
            }
            _ => {}
        }
        self.policy.validate()
    }

    pub fn check_access(
        &self,
        principal: &PrincipalId,
        device: &DeviceId,
        action: Action,
        now: u64,
    ) -> Result<()> {
        if &self.principal_id != principal
            || &self.device_id != device
            || !self.actions.contains(&action)
        {
            return Err(Error::new(
                ErrorCode::AccessDenied,
                "operation is outside the local grant",
            ));
        }
        if self.status != GrantStatus::Active {
            return Err(Error::new(
                ErrorCode::GrantRevoked,
                "grant is revoked or suspended",
            ));
        }
        if now < self.issued_at || now >= self.expires_at {
            return Err(Error::new(
                ErrorCode::GrantExpired,
                "grant is not currently valid",
            ));
        }
        Ok(())
    }

    pub fn authorize(
        &self,
        principal: &PrincipalId,
        request: &TaskRequest,
        action: Action,
        now: u64,
    ) -> Result<()> {
        self.validate()?;
        request.validate()?;
        self.check_access(principal, &request.device_id, action, now)?;
        if request.grant_id != self.id
            || request.environment_profile_id != self.environment_profile_id
        {
            return Err(Error::new(
                ErrorCode::AccessDenied,
                "grant or execution profile does not match",
            ));
        }
        match self.environment {
            Environment::Host
                if request.context.host_context_id != self.host_context_id
                    || request.context.snapshot_id.is_some()
                    || request.context.workspace_id.is_some() =>
            {
                return Err(Error::new(
                    ErrorCode::AccessDenied,
                    "host context does not match grant",
                ));
            }
            Environment::Isolated
                if request.context.host_context_id.is_some()
                    || request.context.snapshot_id.is_none()
                    || request
                        .context
                        .workspace_id
                        .as_ref()
                        .is_none_or(|id| !self.workspace_ids.contains(id)) =>
            {
                return Err(Error::new(
                    ErrorCode::AccessDenied,
                    "snapshot workspace is outside grant",
                ));
            }
            _ => {}
        }
        if request
            .env_overrides
            .keys()
            .any(|key| !self.allowed_env.contains(key))
        {
            return Err(Error::new(
                ErrorCode::AccessDenied,
                "environment override is not authorized",
            ));
        }
        if request.request_expires_at <= now {
            return Err(Error::new(
                ErrorCode::SubmissionExpired,
                "request has expired",
            ));
        }
        Ok(())
    }

    pub fn deadline(&self, request: &TaskRequest, now: u64) -> u64 {
        self.expires_at
            .min(now.saturating_add(request.limits.wall_time_ms.div_ceil(1000)))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskRequest {
    pub submission_id: SubmissionId,
    pub device_id: DeviceId,
    pub grant_id: GrantId,
    pub environment_profile_id: String,
    pub context: ExecutionContext,
    pub command: Command,
    #[serde(default)]
    pub stdin: Stdin,
    #[serde(default)]
    pub env_overrides: BTreeMap<String, String>,
    #[serde(default)]
    pub limits: Limits,
    pub request_expires_at: u64,
}

impl fmt::Debug for TaskRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskRequest")
            .field("submission_id", &self.submission_id)
            .field("device_id", &self.device_id)
            .field("grant_id", &self.grant_id)
            .field("environment_profile_id", &self.environment_profile_id)
            .finish_non_exhaustive()
    }
}

impl TaskRequest {
    pub fn validate(&self) -> Result<()> {
        for id in [
            &self.device_id.0,
            &self.grant_id.0,
            &self.environment_profile_id,
        ] {
            validate_id(id)?;
        }
        self.context.validate()?;
        self.command.validate()?;
        self.limits.validate()?;
        if self.stdin.bytes().len() > MAX_STDIN_BYTES {
            return Err(Error::new(ErrorCode::QuotaExceeded, "stdin exceeds 64 KiB"));
        }
        let mut env_bytes = 0_usize;
        for (key, value) in &self.env_overrides {
            if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
                return Err(Error::new(
                    ErrorCode::InvalidRequest,
                    "invalid environment variable",
                ));
            }
            env_bytes = env_bytes
                .saturating_add(key.len())
                .saturating_add(value.len());
        }
        if env_bytes > MAX_ARGS_BYTES {
            return Err(Error::new(
                ErrorCode::QuotaExceeded,
                "environment exceeds 32 KiB",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionContext {
    #[serde(default)]
    pub host_context_id: Option<String>,
    #[serde(default)]
    pub snapshot_id: Option<SnapshotId>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    pub cwd: String,
}

impl ExecutionContext {
    pub fn validate(&self) -> Result<()> {
        if !self.cwd.starts_with('/') || self.cwd.contains('\0') || self.cwd.len() > 4096 {
            return Err(Error::new(
                ErrorCode::InvalidRequest,
                "cwd must be an absolute bounded path",
            ));
        }
        if self.cwd.split('/').any(|part| part == "." || part == "..") {
            return Err(Error::new(
                ErrorCode::InvalidRequest,
                "cwd must not contain dot path components",
            ));
        }
        if self.host_context_id.is_some() == self.snapshot_id.is_some() {
            return Err(Error::new(
                ErrorCode::InvalidRequest,
                "exactly one host or snapshot context is required",
            ));
        }
        for id in [
            self.host_context_id.as_deref(),
            self.snapshot_id.as_ref().map(|id| id.as_str()),
            self.workspace_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_id(id)?;
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Argv {
        program: String,
        args: Vec<String>,
    },
    Script {
        interpreter: String,
        interpreter_args: Vec<String>,
        args: Vec<String>,
        entry: ScriptEntry,
    },
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Argv { .. } => "Command::Argv(<redacted>)",
            Self::Script { .. } => "Command::Script(<redacted>)",
        })
    }
}

impl Command {
    pub fn kind(&self) -> CommandKind {
        match self {
            Self::Argv { .. } => CommandKind::Argv,
            Self::Script { .. } => CommandKind::Script,
        }
    }
    pub fn program(&self) -> &str {
        match self {
            Self::Argv { program, .. } => program,
            Self::Script { interpreter, .. } => interpreter,
        }
    }
    pub fn args(&self) -> &[String] {
        match self {
            Self::Argv { args, .. } | Self::Script { args, .. } => args,
        }
    }
    pub fn validate(&self) -> Result<()> {
        let program = self.program();
        if program.is_empty() || program.contains('\0') {
            return Err(Error::new(
                ErrorCode::InvalidRequest,
                "program must be explicit and contain no NUL",
            ));
        }
        let interpreter_args = match self {
            Self::Script {
                interpreter_args, ..
            } => interpreter_args.as_slice(),
            _ => &[],
        };
        let mut size = program.len();
        for arg in self.args().iter().chain(interpreter_args) {
            if arg.contains('\0') {
                return Err(Error::new(
                    ErrorCode::InvalidRequest,
                    "argument contains NUL",
                ));
            }
            size = size.saturating_add(arg.len()).saturating_add(1);
        }
        if size > MAX_ARGS_BYTES {
            return Err(Error::new(
                ErrorCode::QuotaExceeded,
                "arguments exceed 32 KiB",
            ));
        }
        if let Self::Script { entry, .. } = self {
            match entry {
                ScriptEntry::Inline { value }
                    if value.len() > MAX_SCRIPT_BYTES || value.contains('\0') =>
                {
                    return Err(Error::new(
                        ErrorCode::InvalidRequest,
                        "script is oversized or contains NUL",
                    ));
                }
                ScriptEntry::FileEntry { path }
                    if path.is_empty()
                        || path.contains('\0')
                        || path.len() > 4096
                        || path.contains("://") =>
                {
                    return Err(Error::new(
                        ErrorCode::InvalidRequest,
                        "script entry must be a bounded local file path",
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    Argv,
    Script,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScriptEntry {
    Inline { value: String },
    FileEntry { path: String },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Stdin {
    Text { value: String },
}
impl Default for Stdin {
    fn default() -> Self {
        Self::Text {
            value: String::new(),
        }
    }
}
impl Stdin {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Text { value } => value.as_bytes(),
        }
    }
}

pub const MAX_ARGS_BYTES: usize = 32 * 1024;
pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;
pub const MAX_STDIN_BYTES: usize = 64 * 1024;
pub const MAX_READ_BYTES: usize = 64 * 1024;
pub const MAX_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_WALL_TIME_MS: u64 = 600_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub wall_time_ms: u64,
    pub output_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            wall_time_ms: 120_000,
            output_bytes: MAX_OUTPUT_BYTES,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        if self.wall_time_ms == 0
            || self.wall_time_ms > MAX_WALL_TIME_MS
            || self.output_bytes == 0
            || self.output_bytes > MAX_OUTPUT_BYTES
        {
            return Err(Error::new(
                ErrorCode::QuotaExceeded,
                "task limits exceed the supported profile",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Policy {
    Automatic,
    Review,
    Rules { policy: RuleSet },
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        if let Self::Rules { policy } = self {
            policy.validate()?;
        }
        Ok(())
    }
    pub fn revision(&self) -> u64 {
        match self {
            Self::Rules { policy } => policy.revision,
            _ => 1,
        }
    }
    pub fn evaluate(&self, context: &RuleContext<'_>) -> PolicyDecision {
        match self {
            Self::Automatic => PolicyDecision {
                effect: RuleEffect::Allow,
                matched_rules: vec![],
                unrestricted_fields: vec![],
            },
            Self::Review => PolicyDecision {
                effect: RuleEffect::Review,
                matched_rules: vec![],
                unrestricted_fields: vec![],
            },
            Self::Rules { policy } => policy.evaluate(context),
        }
    }
}

/// Externally tagged enums match the design's `{"exact": value}` / `{"any": true}`.
/// `any: false` is invalid; an omitted field is never a wildcard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FieldMatch<T> {
    Exact(T),
    Any(bool),
}
impl<T: PartialEq> FieldMatch<T> {
    fn matches(&self, value: &T) -> bool {
        match self {
            Self::Exact(expected) => expected == value,
            Self::Any(enabled) => *enabled,
        }
    }
    fn valid(&self) -> bool {
        !matches!(self, Self::Any(false))
    }
    fn any(&self) -> bool {
        matches!(self, Self::Any(true))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArgsMatch {
    Exact(Vec<String>),
    Any(bool),
    Positions(PositionMatch),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PositionMatch {
    pub values: BTreeMap<usize, String>,
    pub allow_extra: bool,
}
impl ArgsMatch {
    fn matches(&self, args: &[String]) -> bool {
        match self {
            Self::Exact(expected) => expected == args,
            Self::Any(enabled) => *enabled,
            Self::Positions(p) => {
                p.values
                    .iter()
                    .all(|(index, value)| args.get(*index) == Some(value))
                    && (p.allow_extra
                        || (p.values.len() == args.len()
                            && p.values.keys().copied().eq(0..args.len())))
            }
        }
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Any(false) => {
                return Err(Error::new(ErrorCode::InvalidPolicy, "any must be true"));
            }
            Self::Positions(p)
                if p.values.is_empty()
                    || p.values.keys().any(|index| *index > MAX_ARGS_BYTES)
                    || (!p.allow_extra && !p.values.keys().copied().eq(0..p.values.len())) =>
            {
                return Err(Error::new(
                    ErrorCode::InvalidPolicy,
                    "positional args must define a nonempty contiguous array when extra arguments are forbidden",
                ));
            }
            _ => {}
        }
        let values: Vec<&String> = match self {
            Self::Exact(v) => v.iter().collect(),
            Self::Positions(p) => p.values.values().collect(),
            _ => vec![],
        };
        if values.iter().any(|v| v.contains('\0'))
            || values.iter().map(|v| v.len()).sum::<usize>() > MAX_ARGS_BYTES
        {
            return Err(Error::new(
                ErrorCode::InvalidPolicy,
                "invalid or oversized argument rule",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    Allow,
    Review,
    Deny,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnmatchedEffect {
    Review,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    pub revision: u64,
    pub unmatched: UnmatchedEffect,
    pub rules: Vec<Rule>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub effect: RuleEffect,
    #[serde(rename = "match")]
    pub matches: RuleMatch,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleMatch {
    pub principal: FieldMatch<PrincipalId>,
    pub device: FieldMatch<DeviceId>,
    pub account: FieldMatch<u32>,
    pub environment: FieldMatch<String>,
    pub action: FieldMatch<Action>,
    pub cwd: FieldMatch<String>,
    pub command_kind: FieldMatch<CommandKind>,
    pub program: FieldMatch<String>,
    pub args: ArgsMatch,
}

pub struct RuleContext<'a> {
    pub principal: &'a PrincipalId,
    pub device: &'a DeviceId,
    pub account: u32,
    pub environment: &'a str,
    pub action: Action,
    pub cwd: &'a str,
    pub command_kind: CommandKind,
    /// Resolved immutable entry identity, not the untrusted program spelling.
    pub program: &'a str,
    /// Interpreter flags precede script arguments for a script command.
    pub args: &'a [String],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    pub effect: RuleEffect,
    pub matched_rules: Vec<String>,
    pub unrestricted_fields: Vec<String>,
}

impl RuleMatch {
    fn validate(&self) -> Result<()> {
        if !(self.principal.valid()
            && self.device.valid()
            && self.account.valid()
            && self.environment.valid()
            && self.action.valid()
            && self.cwd.valid()
            && self.command_kind.valid()
            && self.program.valid())
        {
            return Err(Error::new(
                ErrorCode::InvalidPolicy,
                "wildcards must explicitly be any:true",
            ));
        }
        if let FieldMatch::Exact(program) = &self.program
            && (program.is_empty() || program.contains('\0'))
        {
            return Err(Error::new(
                ErrorCode::InvalidPolicy,
                "program identity must be nonempty",
            ));
        }
        if let FieldMatch::Exact(cwd) = &self.cwd
            && (!cwd.starts_with('/')
                || cwd.contains('\0')
                || cwd.split('/').any(|p| p == "." || p == ".."))
        {
            return Err(Error::new(
                ErrorCode::InvalidPolicy,
                "rule cwd must be an explicit resolved absolute directory",
            ));
        }
        self.args.validate()
    }

    fn matches(&self, c: &RuleContext<'_>) -> bool {
        self.principal.matches(c.principal)
            && self.device.matches(c.device)
            && self.account.matches(&c.account)
            && self.environment.matches(&c.environment.to_owned())
            && self.action.matches(&c.action)
            && self.cwd.matches(&c.cwd.to_owned())
            && self.command_kind.matches(&c.command_kind)
            && self.program.matches(&c.program.to_owned())
            && self.args.matches(c.args)
    }

    fn unrestricted(&self) -> Vec<String> {
        [
            ("principal", self.principal.any()),
            ("device", self.device.any()),
            ("account", self.account.any()),
            ("environment", self.environment.any()),
            ("action", self.action.any()),
            ("cwd", self.cwd.any()),
            ("command_kind", self.command_kind.any()),
            ("program", self.program.any()),
            ("args", matches!(self.args, ArgsMatch::Any(true))),
            (
                "extra_args",
                matches!(&self.args, ArgsMatch::Positions(p) if p.allow_extra),
            ),
        ]
        .into_iter()
        .filter(|(_, enabled)| *enabled)
        .map(|(name, _)| name.to_owned())
        .collect()
    }
}

impl RuleSet {
    pub fn validate(&self) -> Result<()> {
        if self.revision == 0 || self.rules.len() > 256 {
            return Err(Error::new(
                ErrorCode::InvalidPolicy,
                "rule revision and count are invalid",
            ));
        }
        let mut ids = BTreeSet::new();
        for rule in &self.rules {
            validate_id(&rule.id)?;
            if !ids.insert(&rule.id) {
                return Err(Error::new(
                    ErrorCode::InvalidPolicy,
                    "duplicate rule identifier",
                ));
            }
            rule.matches.validate()?;
        }
        Ok(())
    }

    pub fn evaluate(&self, c: &RuleContext<'_>) -> PolicyDecision {
        // Fail closed even if a caller skipped validate() during policy installation.
        if self.validate().is_err() || c.program.is_empty() {
            return PolicyDecision {
                effect: RuleEffect::Deny,
                matched_rules: vec![],
                unrestricted_fields: vec![],
            };
        }
        let matches: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| rule.matches.matches(c))
            .collect();
        let effect = if matches.iter().any(|r| r.effect == RuleEffect::Deny) {
            RuleEffect::Deny
        } else if matches.iter().any(|r| r.effect == RuleEffect::Review) {
            RuleEffect::Review
        } else if !matches.is_empty() {
            RuleEffect::Allow
        } else {
            match self.unmatched {
                UnmatchedEffect::Deny => RuleEffect::Deny,
                UnmatchedEffect::Review => RuleEffect::Review,
            }
        };
        let unrestricted_fields: BTreeSet<_> = matches
            .iter()
            .flat_map(|rule| rule.matches.unrestricted())
            .collect();
        PolicyDecision {
            effect,
            matched_rules: matches.iter().map(|r| r.id.clone()).collect(),
            unrestricted_fields: unrestricted_fields.into_iter().collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    PendingApproval,
    Accepted,
    Starting,
    Running,
    Exited,
    NotStarted,
    Unknown,
}
impl ExecutionState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Exited | Self::NotStarted)
    }
    pub fn can_transition_to(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (Self::PendingApproval, Self::Accepted | Self::NotStarted)
                    | (
                        Self::Accepted,
                        Self::Starting | Self::NotStarted | Self::Unknown
                    )
                    | (
                        Self::Starting,
                        Self::Running | Self::Exited | Self::NotStarted | Self::Unknown
                    )
                    | (Self::Running, Self::Exited | Self::Unknown)
                    | (Self::Unknown, Self::Exited | Self::NotStarted)
            )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StopState {
    None,
    Requested,
    Confirmed,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    ExitZero,
    ExitNonzero,
    LaunchFailed,
    Cancelled,
    Deadline,
    GrantRevoked,
    GrantExpired,
    ControlLost,
    EndpointPaused,
    SupervisorLost,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskStatus {
    pub execution_state: ExecutionState,
    pub stop_state: StopState,
    pub finish_reason: Option<FinishReason>,
    pub exit_code: Option<i32>,
    pub last_confirmed_at: u64,
    pub event_seq: u64,
}
impl TaskStatus {
    pub fn new(state: ExecutionState, now: u64) -> Self {
        Self {
            execution_state: state,
            stop_state: StopState::None,
            finish_reason: None,
            exit_code: None,
            last_confirmed_at: now,
            event_seq: 1,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.exit_code.is_some() && self.execution_state != ExecutionState::Exited {
            return Err(Error::new(
                ErrorCode::InvalidState,
                "exit code requires process exit evidence",
            ));
        }
        if self.stop_state == StopState::Confirmed && !self.execution_state.is_terminal() {
            return Err(Error::new(
                ErrorCode::InvalidState,
                "confirmed stop requires terminal execution evidence",
            ));
        }
        Ok(())
    }
    pub fn transition(&mut self, next: ExecutionState, now: u64) -> Result<()> {
        if !self.execution_state.can_transition_to(next) {
            return Err(Error::new(
                ErrorCode::InvalidState,
                "execution state cannot move backwards or restart",
            ));
        }
        self.execution_state = next;
        self.last_confirmed_at = now;
        self.event_seq = self
            .event_seq
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::InvalidState, "event sequence exhausted"))?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectPolicy {
    Stop,
    ContinueUntilDeadline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidRequest,
    InvalidPolicy,
    InvalidState,
    AuthRequired,
    AccessDenied,
    DeviceOffline,
    EntryUnreachable,
    GrantExpired,
    GrantRevoked,
    ApprovalRequired,
    ApprovalConsumed,
    ApprovalExpired,
    CapabilityUnavailable,
    IncompatibleContract,
    SubmissionConflict,
    SubmissionExpired,
    PolicyChanged,
    EntryChanged,
    BaselineConflict,
    WorkspaceNotExclusive,
    PartialApply,
    OutputTruncated,
    ContentGone,
    QuotaExceeded,
    ExecutionUnknown,
    StopUnconfirmed,
    ClockSkew,
    StorageUnavailable,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error, JsonSchema)]
#[error("{code:?}: {message}")]
#[serde(deny_unknown_fields)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
}
impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;

fn validate_id(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(Error::new(
            ErrorCode::InvalidRequest,
            "identifier is empty, too long or contains control characters",
        ));
    }
    Ok(())
}

/// Safe for CLI output: escape all terminal control bytes, including ESC and C1.
pub fn sanitize_terminal(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests;

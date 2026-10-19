//! 所有者 CLI：本地初始化、身份材料、维护命令及管理 RPC 的入口。
//!
//! run 将子命令路由到 installer 或 admin socket；grant、审批和任务控制由服务端决定。
//! workspace edit 为前台编辑器保留工作区锁，避免与自动回写同时修改受管目录。
//! 外部内容经 JSON 序列化后输出，终端不直接解释任务输出中的控制字符。

mod enrollment;
mod trust;
use clap::{Parser, Subcommand, ValueEnum};
use orc_admin::Request;
use orc_installer::Role;
use orc_transport::{AnyError, IdentityFile};
use serde_json::{Value, json};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    version,
    about = "OpenRemoteConnector owner management; no secrets belong in chat or command arguments"
)]
struct Args {
    #[arg(
        long,
        global = true,
        env = "ORC_ADMIN_SOCKET",
        help = "Owner management Unix socket of the selected MCP or endpoint"
    )]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Copy, ValueEnum)]
enum RoleArg {
    Mcp,
    Endpoint,
    Complete,
}
impl From<RoleArg> for Role {
    fn from(value: RoleArg) -> Self {
        match value {
            RoleArg::Mcp => Role::Mcp,
            RoleArg::Endpoint => Role::Endpoint,
            RoleArg::Complete => Role::Complete,
        }
    }
}
#[derive(Clone, Copy, ValueEnum)]
enum IdentityKind {
    Mcp,
    Device,
}
impl IdentityKind {
    fn prefix(self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
            Self::Device => "dev",
        }
    }
}
#[derive(clap::Args)]
struct MaintenanceArgs {
    #[arg(long, value_enum)]
    role: RoleArg,
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    signature: PathBuf,
    #[arg(long)]
    public_key: PathBuf,
    #[arg(
        long,
        help = "Endpoint only: require stopped service and exclusive state lock"
    )]
    offline: bool,
}
#[derive(Subcommand)]
enum Command {
    #[command(
        about = "Verify signed release, pause/drain selected role, back up state, and switch programs"
    )]
    Upgrade(MaintenanceArgs),
    #[command(
        about = "Switch to a signed schema-compatible release; retain current security state"
    )]
    Rollback(MaintenanceArgs),
    #[command(
        about = "Stop and remove selected role programs/units while retaining security state and projects"
    )]
    Uninstall {
        #[arg(long, value_enum)]
        role: RoleArg,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        offline: bool,
    },
    Setup {
        #[arg(long, value_enum)]
        role: RoleArg,
        #[arg(long)]
        root: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8787/mcp")]
        public_url: String,
    },
    Doctor {
        #[arg(long)]
        root: PathBuf,
    },
    Install {
        #[arg(long, value_enum)]
        role: RoleArg,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        verify_only: bool,
    },
    #[command(about = "Generate a new UUIDv7 for a new submission; reuse it for retries")]
    SubmissionId,
    #[command(
        about = "Derive stable principal ID from a JSON Principal supplied by authenticated connection status"
    )]
    PrincipalId {
        #[arg(long)]
        file: PathBuf,
    },
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    #[command(about = "Call a local owner method. JSON file '-' reads stdin; no TCP management.")]
    Admin {
        method: String,
        #[arg(long)]
        file: Option<PathBuf>,
    },
    Status,
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    Grant {
        #[command(subcommand)]
        command: GrantCommand,
    },
    Approval {
        #[command(subcommand)]
        command: ApprovalCommand,
    },
    Task {
        #[command(subcommand)]
        command: TaskCommand,
    },
    Endpoint {
        #[command(subcommand)]
        command: EndpointCommand,
    },
    Workspace {
        #[command(subcommand)]
        command: WorkspaceCommand,
    },
    Changes {
        #[command(subcommand)]
        command: ChangesCommand,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}
#[derive(Subcommand)]
enum IdentityCommand {
    Create {
        #[arg(long)]
        file: PathBuf,
        #[arg(long, value_enum)]
        kind: IdentityKind,
    },
    Show {
        #[arg(long)]
        file: PathBuf,
        #[arg(long, value_enum)]
        kind: IdentityKind,
        #[arg(long)]
        certificate: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
enum McpCommand {
    InviteDevice {
        #[arg(long)]
        file: PathBuf,
    },
    RedeemDevice {
        #[arg(long)]
        file: PathBuf,
    },
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    RegisterDevice {
        #[arg(long)]
        file: PathBuf,
    },
    Allow {
        #[arg(long)]
        file: PathBuf,
    },
}
#[derive(Subcommand)]
enum AuthCommand {
    Pending,
    Show { client_id: String },
    Approve { id: String },
    Revoke { client_id: String },
}
#[derive(Subcommand)]
enum GrantCommand {
    Create {
        #[arg(long)]
        file: PathBuf,
    },
    List,
    Revoke {
        grant_id: String,
    },
}
#[derive(Subcommand)]
enum ApprovalCommand {
    List,
    Show { approval_id: String },
    Approve { approval_id: String },
    Reject { approval_id: String },
}
#[derive(Subcommand)]
enum TaskCommand {
    List,
    Show { task_id: String },
    Cancel { task_id: String },
}
#[derive(Subcommand)]
enum EndpointCommand {
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
    EnrollmentRequest {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        certificate: PathBuf,
    },
    EnrollmentProof {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        invitation: PathBuf,
    },
    Show,
    Pause,
    Resume,
}
#[derive(Subcommand)]
enum TrustCommand {
    Revoke,
    Set {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        invitation: PathBuf,
        #[arg(long)]
        peer: PathBuf,
    },
}
#[derive(Subcommand)]
enum WorkspaceCommand {
    Preview {
        #[arg(long)]
        file: PathBuf,
    },
    Approve {
        snapshot_id: String,
    },
    #[command(
        about = "Hold the managed workspace lock while a foreground editor runs; pass direct argv after --"
    )]
    Edit {
        #[arg(long)]
        path: PathBuf,
        #[arg(required=true,num_args=1..,trailing_var_arg=true)]
        command: Vec<std::ffi::OsString>,
    },
    Export {
        #[arg(long)]
        file: PathBuf,
    },
    Create {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        workspace_id: String,
    },
    Status {
        #[arg(long)]
        path: PathBuf,
    },
}
#[derive(Subcommand)]
enum ChangesCommand {
    Show {
        change_set_id: String,
    },
    Apply {
        #[arg(long)]
        file: PathBuf,
    },
}
#[derive(Subcommand)]
enum PolicyCommand {
    Validate {
        #[arg(long)]
        file: PathBuf,
    },
}

fn read_bytes(path: &Path, limit: u64) -> Result<Vec<u8>, AnyError> {
    let mut bytes = Vec::new();
    if path == Path::new("-") {
        std::io::stdin()
            .lock()
            .take(limit + 1)
            .read_to_end(&mut bytes)?;
    } else {
        std::fs::File::open(path)?
            .take(limit + 1)
            .read_to_end(&mut bytes)?;
    }
    if bytes.len() as u64 > limit {
        return Err("input exceeds limit".into());
    }
    Ok(bytes)
}
fn read_json(path: &Path) -> Result<Value, AnyError> {
    Ok(orc_protocol::strict_decode(&read_bytes(path, 256 * 1024)?)?)
}
fn private_identity(path: &Path) -> Result<IdentityFile, AnyError> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.uid() != orc_admin::current_uid()
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err("identity file must be owned by current UID with mode 0600".into());
    }
    IdentityFile::load(path)
}
fn print(value: &Value) -> Result<(), AnyError> {
    // JSON escapes ESC, control characters, and embedded line breaks. Never emit
    // raw task output or scripts to a terminal, and never print a secret key.
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
async fn rpc(socket: Option<&Path>, method: &str, params: Value) -> Result<Value, AnyError> {
    let socket = socket.ok_or("--socket or ORC_ADMIN_SOCKET is required for owner management")?;
    let response = orc_admin::call(
        socket,
        Request {
            method: method.into(),
            params,
        },
    )
    .await?;
    match (response.result, response.error) {
        (_, Some(error)) => Err(error.into()),
        (Some(value), None) => Ok(value),
        _ => Err("invalid management response".into()),
    }
}
#[tokio::main]
async fn main() {
    if let Err(error) = run(Args::parse()).await {
        eprintln!(
            "{}",
            serde_json::to_string(&json!({"error":error.to_string()})).expect("error JSON")
        );
        std::process::exit(1);
    }
}
async fn run(args: Args) -> Result<(), AnyError> {
    let socket = args.socket.as_deref();
    let result = match args.command {
        Command::Upgrade(options) => {
            maintain(options, orc_installer::maintenance::Operation::Upgrade).await?
        }
        Command::Rollback(options) => {
            maintain(options, orc_installer::maintenance::Operation::Rollback).await?
        }
        Command::Uninstall {
            role,
            root,
            offline,
        } => {
            orc_installer::maintenance::maintain(
                &root,
                role.into(),
                orc_installer::maintenance::Operation::Uninstall,
                None,
                offline,
            )
            .await?
        }
        Command::Setup {
            role,
            root,
            public_url,
        } => serde_json::to_value(orc_installer::setup(&root, role.into(), &public_url)?)?,
        Command::Doctor { root } => serde_json::to_value(orc_installer::doctor(&root)?)?,
        Command::Install {
            role,
            root,
            bundle,
            manifest,
            signature,
            public_key,
            verify_only,
        } => {
            let bytes = read_bytes(&manifest, 64 * 1024)?;
            let signature = String::from_utf8(read_bytes(&signature, 4096)?)?;
            let public_key = String::from_utf8(read_bytes(&public_key, 4096)?)?;
            if verify_only {
                let verified = orc_installer::verify_release(
                    &bytes,
                    &signature,
                    &public_key,
                    &bundle,
                    role.into(),
                )?;
                json!({"verified":true,"version":verified.version,"target":verified.target,"installed":false})
            } else {
                orc_installer::install_release(
                    &root,
                    &bundle,
                    &bytes,
                    &signature,
                    &public_key,
                    role.into(),
                )?
            }
        }
        Command::SubmissionId => {
            println!("{}", uuid::Uuid::now_v7());
            return Ok(());
        }
        Command::PrincipalId { file } => {
            let principal: orc_domain::Principal =
                orc_protocol::strict_decode(&read_bytes(&file, 16 * 1024)?)?;
            principal.validate()?;
            json!({"principal_id":principal.id()})
        }
        Command::Identity { command } => match command {
            IdentityCommand::Create { file, kind } => {
                orc_admin::secure_dir(
                    file.parent()
                        .ok_or("identity requires a parent directory")?,
                )?;
                let identity = IdentityFile::create(&file)?;
                json!({"id":identity.id(kind.prefix())?,"public_key":identity.public_key()?,"identity_file":file})
            }
            IdentityCommand::Show {
                file,
                kind,
                certificate,
            } => {
                let identity = private_identity(&file)?;
                let mut result =
                    json!({"id":identity.id(kind.prefix())?,"public_key":identity.public_key()?});
                if let Some(certificate) = certificate {
                    result["certificate_digest"] =
                        json!(orc_transport::certificate_file_digest(&certificate)?)
                }
                result
            }
        },
        Command::Admin { method, file } => {
            rpc(
                socket,
                &method,
                match file {
                    Some(file) => read_json(&file)?,
                    None => json!({}),
                },
            )
            .await?
        }
        Command::Status => rpc(socket, "status", json!({})).await?,
        Command::Mcp { command } => match command {
            McpCommand::InviteDevice { file } => {
                rpc(socket, "device.invite", read_json(&file)?).await?
            }
            McpCommand::RedeemDevice { file } => {
                rpc(socket, "device.redeem", read_json(&file)?).await?
            }
            McpCommand::Auth { command } => match command {
                AuthCommand::Pending => rpc(socket, "auth.pending", json!({})).await?,
                AuthCommand::Show { client_id } => {
                    rpc(socket, "auth.show", json!({"client_id":client_id})).await?
                }
                AuthCommand::Approve { id } => {
                    rpc(socket, "auth.approve", json!({"id":id})).await?
                }
                AuthCommand::Revoke { client_id } => {
                    rpc(socket, "auth.revoke", json!({"client_id":client_id})).await?
                }
            },
            McpCommand::RegisterDevice { file } => {
                rpc(socket, "device.register", read_json(&file)?).await?
            }
            McpCommand::Allow { file } => rpc(socket, "service.allow", read_json(&file)?).await?,
        },
        Command::Grant { command } => match command {
            GrantCommand::Create { file } => {
                let grant: orc_domain::Grant =
                    orc_protocol::strict_decode(&read_bytes(&file, 256 * 1024)?)?;
                grant.validate()?;
                rpc(socket, "grant.create", serde_json::to_value(grant)?).await?
            }
            GrantCommand::List => rpc(socket, "grant.list", json!({})).await?,
            GrantCommand::Revoke { grant_id } => {
                rpc(socket, "grant.revoke", json!({"id":grant_id})).await?
            }
        },
        Command::Approval { command } => match command {
            ApprovalCommand::List => rpc(socket, "approval.list", json!({})).await?,
            ApprovalCommand::Show { approval_id } => {
                rpc(socket, "approval.show", json!({"id":approval_id})).await?
            }
            ApprovalCommand::Approve { approval_id } => {
                rpc(socket, "approval.approve", json!({"id":approval_id})).await?
            }
            ApprovalCommand::Reject { approval_id } => {
                rpc(socket, "approval.reject", json!({"id":approval_id})).await?
            }
        },
        Command::Task { command } => match command {
            TaskCommand::List => rpc(socket, "task.list", json!({})).await?,
            TaskCommand::Show { task_id } => {
                rpc(socket, "task.show", json!({"id":task_id})).await?
            }
            TaskCommand::Cancel { task_id } => {
                rpc(socket, "task.cancel", json!({"id":task_id})).await?
            }
        },
        Command::Endpoint { command } => match command {
            EndpointCommand::Trust { command } => match command {
                TrustCommand::Revoke => rpc(socket, "trust.revoke", json!({})).await?,
                TrustCommand::Set {
                    config,
                    invitation,
                    peer,
                } => trust::set(&config, &invitation, &peer, socket).await?,
            },
            EndpointCommand::EnrollmentRequest {
                identity,
                certificate,
            } => enrollment::request(&identity, &certificate)?,
            EndpointCommand::EnrollmentProof {
                identity,
                invitation,
            } => enrollment::proof(&identity, &invitation)?,
            EndpointCommand::Show => rpc(socket, "status", json!({})).await?,
            EndpointCommand::Pause => rpc(socket, "pause", json!({"paused":true})).await?,
            EndpointCommand::Resume => rpc(socket, "resume", json!({})).await?,
        },
        Command::Workspace { command } => {
            match command {
                WorkspaceCommand::Preview { file } => {
                    rpc(socket, "workspace.preview", read_json(&file)?).await?
                }
                WorkspaceCommand::Approve { snapshot_id } => {
                    rpc(socket, "workspace.approve", json!({"id":snapshot_id})).await?
                }
                WorkspaceCommand::Edit { path, command } => {
                    let workspace = orc_workspace::ManagedWorkspace::open(&path)?;
                    let guard = workspace.lock()?;
                    let inherited_lock = guard.clone_editor_lock()?;
                    let lock_fd = std::os::fd::AsRawFd::as_raw_fd(&inherited_lock);
                    let program = Path::new(&command[0]);
                    if !program.is_absolute() {
                        return Err("editor executable must be an absolute path; pass foreground argv after --".into());
                    }
                    let mut command_builder = tokio::process::Command::new(program);
                    command_builder
                        .args(&command[1..])
                        .current_dir(&path)
                        .kill_on_drop(true);
                    // SAFETY: the child closure uses only async-signal-safe fcntl
                    // on a live cloned lock descriptor; no allocation or locks.
                    unsafe {
                        command_builder.pre_exec(move || {
                            let flags = libc::fcntl(lock_fd, libc::F_GETFD);
                            if flags < 0
                                || libc::fcntl(lock_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC)
                                    < 0
                            {
                                return Err(std::io::Error::last_os_error());
                            }
                            Ok(())
                        });
                    }
                    let mut terminate =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                    let mut hangup =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
                    let mut editor = command_builder.spawn()?;
                    let status = tokio::select! {
                        result=editor.wait()=>result?,
                        _=tokio::signal::ctrl_c()=>{let _ = editor.start_kill();let _=editor.wait().await?;return Err("editor interrupted; child stopped before releasing workspace lock".into())},
                        _=terminate.recv()=>{let _=editor.start_kill();let _=editor.wait().await?;return Err("editor terminated; child stopped before releasing workspace lock".into())},
                        _=hangup.recv()=>{let _=editor.start_kill();let _=editor.wait().await?;return Err("editor hangup; child stopped before releasing workspace lock".into())}
                    };
                    if !status.success() {
                        return Err(format!("editor exited unsuccessfully: {status}").into());
                    }
                    json!({"workspace_id":workspace.workspace_id(),"editor_completed":true})
                }
                WorkspaceCommand::Export { file } => {
                    rpc(socket, "workspace.export", read_json(&file)?).await?
                }
                WorkspaceCommand::Create { path, workspace_id } => {
                    rpc(
                        socket,
                        "workspace.create",
                        json!({"path":path,"workspace_id":workspace_id}),
                    )
                    .await?
                }
                WorkspaceCommand::Status { path } => {
                    let workspace = orc_workspace::ManagedWorkspace::open(&path)?;
                    let _guard = workspace.lock()?;
                    json!({"workspace_id":workspace.workspace_id(),"managed":true,"lock_available":true,"exclusive_writers_required":true})
                }
            }
        }
        Command::Changes { command } => match command {
            ChangesCommand::Show { change_set_id } => {
                rpc(socket, "changes.show", json!({"id":change_set_id})).await?
            }
            ChangesCommand::Apply { file } => {
                rpc(socket, "changes.apply", read_json(&file)?).await?
            }
        },
        Command::Policy { command } => match command {
            PolicyCommand::Validate { file } => {
                let policy: orc_domain::Policy =
                    orc_protocol::strict_decode(&read_bytes(&file, 256 * 1024)?)?;
                policy.validate()?;
                json!({"valid":true,"policy":policy,"enabled":false})
            }
        },
    };
    print(&result)
}

async fn maintain(
    options: MaintenanceArgs,
    operation: orc_installer::maintenance::Operation,
) -> Result<Value, AnyError> {
    let manifest = read_bytes(&options.manifest, 64 * 1024)?;
    let signature = String::from_utf8(read_bytes(&options.signature, 4096)?)?;
    let public_key = String::from_utf8(read_bytes(&options.public_key, 4096)?)?;
    let package = orc_installer::maintenance::Package {
        bundle: &options.bundle,
        manifest: &manifest,
        signature: &signature,
        public_key: &public_key,
    };
    orc_installer::maintenance::maintain(
        &options.root,
        options.role.into(),
        operation,
        Some(package),
        options.offline,
    )
    .await
}

//! 仅供本机所有者使用的管理 RPC，不作为 Agent 工具暴露。
//!
//! Unix socket 权限和双方 peer UID 校验共同建立同账户边界；每条连接处理一个有界 JSON 行。
//! 服务端限制并发及读写时间，客户端核对 socket 与对端归属后才发送审批/撤销等命令。
//! 此边界不能隔离所有者同 UID 下的任意代码，具体管理动作由 Handler 实现。

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::{path::Path, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
};
pub const MAX_MESSAGE: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("local management I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid local management message")]
    Json(#[from] serde_json::Error),
    #[error("local owner identity or socket permissions do not match")]
    Permission,
    #[error("management message exceeds limit")]
    Limit,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub method: String,
    pub params: Value,
}
#[derive(Serialize, Deserialize)]
pub struct Response {
    pub result: Option<Value>,
    pub error: Option<String>,
}
impl Response {
    pub fn ok(result: Value) -> Self {
        Self {
            result: Some(result),
            error: None,
        }
    }
    pub fn error(error: impl Into<String>) -> Self {
        Self {
            result: None,
            error: Some(error.into()),
        }
    }
}
/// 仅处理已通过本地 UID 检查的管理请求；实现方仍负责具体动作的状态与授权约束。
#[async_trait::async_trait]
pub trait Handler: Send + Sync + 'static {
    async fn handle(&self, request: Request) -> Response;
}

pub fn current_uid() -> u32 {
    // SAFETY: getuid has no arguments or memory safety preconditions.
    unsafe { libc::getuid() }
}
pub fn secure_dir(dir: &Path) -> Result<(), Error> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let m = std::fs::symlink_metadata(dir)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != current_uid()
        || m.mode() & 0o077 != 0
    {
        return Err(Error::Permission);
    }
    Ok(())
}
async fn read_message(reader: &mut BufReader<UnixStream>) -> Result<Vec<u8>, Error> {
    let mut data = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        let end = available.iter().position(|b| *b == b'\n').map(|p| p + 1);
        let len = end.unwrap_or(available.len());
        if data.len() + len > MAX_MESSAGE {
            return Err(Error::Limit);
        }
        data.extend_from_slice(&available[..len]);
        reader.consume(len);
        if end.is_some() {
            return Ok(data);
        }
    }
}
/// 验证本地对端 UID，限制并发和单行消息大小；同 UID 任意代码仍处于此信任边界内。
pub async fn serve(socket: &Path, owner_uid: u32, handler: Arc<dyn Handler>) -> Result<(), Error> {
    secure_dir(socket.parent().ok_or(Error::Permission)?)?;
    if socket.exists() {
        let meta = std::fs::symlink_metadata(socket)?;
        if meta.file_type().is_symlink() || meta.uid() != owner_uid {
            return Err(Error::Permission);
        }
        match UnixStream::connect(socket).await {
            Ok(_) => return Err(std::io::Error::from(std::io::ErrorKind::AddrInUse).into()),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(socket)?
            }
            Err(e) => return Err(e.into()),
        }
    }
    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    let capacity = Arc::new(Semaphore::new(16));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            incoming = listener.accept() => {
                let (stream, _) = incoming?;
                if stream.peer_cred()?.uid() != owner_uid {
                    continue;
                }
                let Ok(permit) = capacity.clone().try_acquire_owned() else { continue };
                let handler = handler.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let mut reader = BufReader::new(stream);
                    let Ok(Ok(bytes)) = tokio::time::timeout(
                        std::time::Duration::from_secs(10), read_message(&mut reader)
                    ).await else { return };
                    let response = match serde_json::from_slice::<Request>(&bytes) {
                        Ok(request) => handler.handle(request).await,
                        Err(_) => Response::error("INVALID_REQUEST"),
                    };
                    if let Ok(mut bytes) = serde_json::to_vec(&response) {
                        if bytes.len() >= MAX_MESSAGE {
                            bytes = b"{\"result\":null,\"error\":\"RESPONSE_TOO_LARGE\"}".to_vec();
                        }
                        bytes.push(b'\n');
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(10), reader.get_mut().write_all(&bytes)
                        ).await;
                    }
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}
/// 发送前同时核对 socket 文件和实际连接对端，避免只凭路径名称信任管理服务。
pub async fn call(socket: &Path, request: Request) -> Result<Response, Error> {
    let meta = std::fs::symlink_metadata(socket)?;
    if meta.file_type().is_symlink() || meta.uid() != current_uid() || meta.mode() & 0o077 != 0 {
        return Err(Error::Permission);
    }
    let stream = UnixStream::connect(socket).await?;
    if stream.peer_cred()?.uid() != current_uid() {
        return Err(Error::Permission);
    }
    let mut reader = BufReader::new(stream);
    let mut message = serde_json::to_vec(&request)?;
    if message.len() >= MAX_MESSAGE {
        return Err(Error::Limit);
    }
    message.push(b'\n');
    reader.get_mut().write_all(&message).await?;
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        read_message(&mut reader),
    )
    .await
    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    Ok(serde_json::from_slice(&response)?)
}

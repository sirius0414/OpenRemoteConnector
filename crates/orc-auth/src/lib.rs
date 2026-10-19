//! 单所有者 OAuth：本地同意、PKCE、单次授权码和刷新令牌轮换。
//!
//! 流程为 register → begin → 本地 approve → 浏览器 complete → exchange；
//! authenticate 返回由服务端登记信息构造的 Principal，不接受客户端指定身份。
//! 有界 actor 串行拥有 State；写操作先修改副本、持久化成功后才发布新内存状态。
//! 请求入队后即使 HTTP 断开也会完成消费，防止同一凭据因响应丢失而再次可用。
//! 登录同意只建立身份；设备访问和执行权限分别由 MCP 与 endpoint 继续检查。

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use orc_domain::{McpId, Principal};
use orc_store::Store;
use oxide_auth::code_grant::extensions::Pkce;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid_request: {0}")]
    Invalid(&'static str),
    #[error("invalid_grant")]
    InvalidGrant,
    #[error("access_denied")]
    Denied,
    #[error("authorization_pending")]
    Pending,
    #[error("temporarily_unavailable")]
    Storage,
    /// Internal signal: commit the family revocation before returning invalid_grant.
    #[error("invalid_grant")]
    ReplayedRefresh,
}
pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub registered_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
    pub resource: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingLogin {
    pub id: String,
    pub authorization: Authorization,
    pub expires_at: u64,
    pub approved: bool,
    nonce_digest: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Code {
    authorization: Authorization,
    expires_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    client_id: String,
    family: String,
    resource: String,
    expires_at: u64,
    refresh: bool,
    spent: bool,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    clients: BTreeMap<String, Client>,
    pending: BTreeMap<String, PendingLogin>,
    codes: BTreeMap<String, Code>,
    tokens: BTreeMap<String, Token>,
    families: BTreeMap<String, bool>,
}
#[derive(Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: String,
}

type Mutation = Box<dyn FnOnce(&mut State) -> Result<Value> + Send>;
struct Job {
    mutation: Mutation,
    write: bool,
    reply: oneshot::Sender<Result<Value>>,
}
struct Actor {
    sender: mpsc::Sender<Job>,
    _worker: JoinHandle<()>,
}
/// 可克隆的 actor 句柄；所有克隆共享同一凭据状态和串行消费顺序。
#[derive(Clone)]
pub struct Auth {
    actor: Arc<Actor>,
    pub resource: String,
    mcp_id: String,
    owner_id: String,
    domain_id: String,
}

fn digest(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}
pub fn random_secret() -> Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AuthError::Storage)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn encode<T: Serialize>(value: T) -> Result<Value> {
    serde_json::to_value(value).map_err(|_| AuthError::Storage)
}
fn validate_redirect(value: &str) -> Result<()> {
    if value.len() > 2048 {
        return Err(AuthError::Invalid("redirect_uri"));
    }
    let url = Url::parse(value).map_err(|_| AuthError::Invalid("redirect_uri"))?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        _ => false,
    };
    if url.host().is_none()
        || !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(AuthError::Invalid(
            "HTTPS or literal loopback redirect required",
        ));
    }
    Ok(())
}
fn pkce_challenge(
    authorization: &Authorization,
) -> Result<Option<oxide_auth::primitives::grant::Value>> {
    if authorization.code_challenge_method != "S256"
        || URL_SAFE_NO_PAD
            .decode(&authorization.code_challenge)
            .map(|v| v.len())
            .ok()
            != Some(32)
    {
        return Err(AuthError::Invalid("S256 PKCE is required"));
    }
    Pkce::required()
        .challenge(
            Some(authorization.code_challenge_method.as_str().into()),
            Some(authorization.code_challenge.as_str().into()),
        )
        .map_err(|_| AuthError::Invalid("PKCE challenge"))
}

impl Auth {
    /// 加载持久 OAuth 状态并启动唯一写入 actor；存储结果不确定时停止服务凭据请求。
    pub async fn open(
        store: Store,
        resource: String,
        mcp_id: String,
        owner_id: String,
        domain_id: String,
    ) -> Result<Self> {
        validate_redirect(&resource)?;
        if [mcp_id.as_str(), owner_id.as_str(), domain_id.as_str()]
            .iter()
            .any(|v| v.is_empty())
        {
            return Err(AuthError::Invalid("identity"));
        }
        let mut state: State = match store
            .get_record("oauth", "state")
            .await
            .map_err(|_| AuthError::Storage)?
        {
            Some(v) => serde_json::from_value(v).map_err(|_| AuthError::Storage)?,
            None => State::default(),
        };
        let (sender, mut receiver) = mpsc::channel::<Job>(32);
        let worker = tokio::spawn(async move {
            while let Some(job) = receiver.recv().await {
                let mut next = state.clone();
                let mut result = (job.mutation)(&mut next);
                // 刷新令牌重放虽然对外失败，却带有必须提交的家族撤销，不能丢弃 next。
                let must_commit = job.write
                    && (result.is_ok() || matches!(result, Err(AuthError::ReplayedRefresh)));
                if must_commit {
                    let persisted = match serde_json::to_value(&next) {
                        Ok(value) => store
                            .put_record("oauth", "state", value)
                            .await
                            .map_err(|_| AuthError::Storage),
                        Err(_) => Err(AuthError::Storage),
                    };
                    match persisted {
                        Ok(()) => state = next,
                        Err(error) => {
                            // The store may have synchronized its journal before a later
                            // failure. Never serve from possibly stale authority again.
                            let _ = job.reply.send(Err(error));
                            break;
                        }
                    }
                }
                if matches!(result, Err(AuthError::ReplayedRefresh)) {
                    result = Err(AuthError::InvalidGrant);
                }
                let _ = job.reply.send(result);
            }
        });
        Ok(Self {
            actor: Arc::new(Actor {
                sender,
                _worker: worker,
            }),
            resource,
            mcp_id,
            owner_id,
            domain_id,
        })
    }

    async fn call<T: DeserializeOwned>(
        &self,
        write: bool,
        mutation: impl FnOnce(&mut State) -> Result<Value> + Send + 'static,
    ) -> Result<T> {
        let (reply, response) = oneshot::channel();
        self.actor
            .sender
            .send(Job {
                mutation: Box::new(mutation),
                write,
                reply,
            })
            .await
            .map_err(|_| AuthError::Storage)?;
        let value = response.await.map_err(|_| AuthError::Storage)??;
        serde_json::from_value(value).map_err(|_| AuthError::Storage)
    }

    /// 创建独立客户端登记 ID；显示名称相同也不合并身份或继承旧权限。
    pub async fn register(&self, name: String, redirects: Vec<String>, now: u64) -> Result<Client> {
        if name.is_empty()
            || name.len() > 128
            || name.chars().any(char::is_control)
            || redirects.is_empty()
            || redirects.len() > 8
        {
            return Err(AuthError::Invalid("client metadata"));
        }
        for redirect in &redirects {
            validate_redirect(redirect)?;
        }
        self.call(true, move |state| {
            if state.clients.len() >= 128
                || state
                    .clients
                    .values()
                    .filter(|c| c.registered_at > now.saturating_sub(60))
                    .count()
                    >= 10
            {
                return Err(AuthError::Invalid("registration quota"));
            }
            let client = Client {
                client_id: uuid::Uuid::new_v4().to_string(),
                client_name: name,
                redirect_uris: redirects,
                registered_at: now,
            };
            state
                .clients
                .insert(client.client_id.clone(), client.clone());
            encode(client)
        })
        .await
    }

    /// 校验资源/redirect/PKCE，创建待所有者同意记录，并返回绑定浏览器的 nonce。
    pub async fn begin(&self, request: Authorization, now: u64) -> Result<(PendingLogin, String)> {
        pkce_challenge(&request)?;
        let resource = self.resource.clone();
        self.call(true, move |state| {
            let client = state
                .clients
                .get(&request.client_id)
                .ok_or(AuthError::Denied)?;
            if !client.redirect_uris.contains(&request.redirect_uri)
                || request.resource != resource
                || request.scope != "orc"
                || request.response_type != "code"
                || request.state.len() > 1024
                || request.state.is_empty()
            {
                return Err(AuthError::Invalid("authorization binding"));
            }
            state.pending.retain(|_, p| p.expires_at > now);
            state.codes.retain(|_, code| code.expires_at > now);
            if state.pending.len() >= 32 {
                return Err(AuthError::Invalid("login quota"));
            }
            let nonce = random_secret()?;
            let login = PendingLogin {
                id: uuid::Uuid::new_v4().to_string(),
                authorization: request,
                expires_at: now.saturating_add(300),
                approved: false,
                nonce_digest: digest(&nonce),
            };
            state.pending.insert(login.id.clone(), login.clone());
            encode((login, nonce))
        })
        .await
    }

    pub async fn pending(&self, now: u64) -> Vec<PendingLogin> {
        self.pending_checked(now).await.unwrap_or_default()
    }

    /// Management entrypoints should use this variant so a failed authority
    /// store is never presented to the owner as an empty approval queue.
    pub async fn pending_checked(&self, now: u64) -> Result<Vec<PendingLogin>> {
        self.call(false, move |state| {
            encode(
                state
                    .pending
                    .values()
                    .filter(|p| p.expires_at > now)
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        })
        .await
    }

    /// 仅标记本地同意；浏览器仍需持有 begin 返回的 nonce 才能领取授权码。
    pub async fn approve(&self, id: &str, now: u64) -> Result<()> {
        let id = id.to_owned();
        self.call(true, move |state| {
            let pending = state.pending.get_mut(&id).ok_or(AuthError::InvalidGrant)?;
            if pending.expires_at <= now {
                return Err(AuthError::InvalidGrant);
            }
            pending.approved = true;
            encode(())
        })
        .await
    }

    /// 消费已批准且 nonce 匹配的登录，签发短期单次授权码及回跳地址。
    pub async fn complete(&self, id: &str, nonce: &str, now: u64) -> Result<String> {
        let id = id.to_owned();
        let nonce_digest = digest(nonce);
        self.call(true, move |state| {
            let p = state.pending.get(&id).ok_or(AuthError::InvalidGrant)?;
            if p.expires_at <= now
                || !bool::from(p.nonce_digest.as_bytes().ct_eq(nonce_digest.as_bytes()))
            {
                return Err(AuthError::InvalidGrant);
            }
            if !p.approved {
                return Err(AuthError::Pending);
            }
            let p = state.pending.remove(&id).ok_or(AuthError::InvalidGrant)?;
            let code = random_secret()?;
            let mut redirect =
                Url::parse(&p.authorization.redirect_uri).map_err(|_| AuthError::InvalidGrant)?;
            redirect
                .query_pairs_mut()
                .append_pair("code", &code)
                .append_pair("state", &p.authorization.state);
            state.codes.insert(
                digest(&code),
                Code {
                    authorization: p.authorization,
                    expires_at: now.saturating_add(60),
                },
            );
            encode(redirect.to_string())
        })
        .await
    }

    fn issue(
        state: &mut State,
        client: &str,
        resource: &str,
        family: String,
        now: u64,
        refresh_expires: u64,
    ) -> Result<Tokens> {
        state.tokens.retain(|_, token| token.expires_at > now);
        // Spent refresh hashes remain until the family's absolute expiry for replay detection.
        if state.tokens.len() >= 768 {
            return Err(AuthError::Invalid("token quota"));
        }
        state
            .families
            .retain(|family, _| state.tokens.values().any(|token| &token.family == family));
        let access = random_secret()?;
        let refresh = random_secret()?;
        state.families.entry(family.clone()).or_insert(false);
        state.tokens.insert(
            digest(&access),
            Token {
                client_id: client.into(),
                resource: resource.into(),
                family: family.clone(),
                expires_at: now.saturating_add(600),
                refresh: false,
                spent: false,
            },
        );
        state.tokens.insert(
            digest(&refresh),
            Token {
                client_id: client.into(),
                resource: resource.into(),
                family,
                expires_at: refresh_expires,
                refresh: true,
                spent: false,
            },
        );
        Ok(Tokens {
            access_token: access,
            refresh_token: refresh,
            token_type: "Bearer".into(),
            expires_in: 600,
            scope: "orc".into(),
        })
    }

    /// PKCE、客户端、资源和 redirect 全部匹配后，在同一次 actor 写入中消费码并发令牌。
    #[allow(clippy::too_many_arguments)]
    pub async fn exchange(
        &self,
        client: &str,
        code: &str,
        redirect: &str,
        verifier: &str,
        resource: &str,
        now: u64,
    ) -> Result<Tokens> {
        if !(43..=128).contains(&verifier.len())
            || !verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        {
            return Err(AuthError::InvalidGrant);
        }
        let client = client.to_owned();
        let code_digest = digest(code);
        let redirect = redirect.to_owned();
        let verifier = verifier.to_owned();
        let resource = resource.to_owned();
        let expected_resource = self.resource.clone();
        self.call(true, move |state| {
            let c = state
                .codes
                .get(&code_digest)
                .ok_or(AuthError::InvalidGrant)?;
            if c.expires_at <= now
                || c.authorization.client_id != client
                || c.authorization.redirect_uri != redirect
                || resource != expected_resource
                || c.authorization.resource != resource
            {
                return Err(AuthError::InvalidGrant);
            }
            let challenge =
                pkce_challenge(&c.authorization).map_err(|_| AuthError::InvalidGrant)?;
            Pkce::required()
                .verify(challenge, Some(verifier.as_str().into()))
                .map_err(|_| AuthError::InvalidGrant)?;
            state.codes.remove(&code_digest);
            encode(Self::issue(
                state,
                &client,
                &resource,
                random_secret()?,
                now,
                now.saturating_add(30 * 86400),
            )?)
        })
        .await
    }

    /// 轮换刷新令牌并沿用家族的绝对到期时间；重用旧令牌撤销整个家族。
    /// 重放返回错误，但撤销必须先持久化，不能按普通失败丢弃状态副本。
    pub async fn refresh(
        &self,
        client: &str,
        refresh: &str,
        resource: &str,
        now: u64,
    ) -> Result<Tokens> {
        let client = client.to_owned();
        let token_digest = digest(refresh);
        let resource = resource.to_owned();
        let expected_resource = self.resource.clone();
        self.call(true, move |state| {
            let t = state
                .tokens
                .get(&token_digest)
                .ok_or(AuthError::InvalidGrant)?
                .clone();
            if !t.refresh
                || t.client_id != client
                || t.resource != resource
                || resource != expected_resource
                || t.expires_at <= now
                || state.families.get(&t.family) != Some(&false)
            {
                return Err(AuthError::InvalidGrant);
            }
            if t.spent {
                state.families.insert(t.family, true);
                return Err(AuthError::ReplayedRefresh);
            }
            state
                .tokens
                .get_mut(&token_digest)
                .ok_or(AuthError::InvalidGrant)?
                .spent = true;
            encode(Self::issue(
                state,
                &client,
                &resource,
                t.family,
                now,
                t.expires_at,
            )?)
        })
        .await
    }

    /// 只接受有效访问令牌，从登记记录构造 Principal；不信任请求中的身份字段。
    pub async fn authenticate(&self, token: &str, now: u64) -> Result<Principal> {
        let token_digest = digest(token);
        let resource = self.resource.clone();
        let principal = Principal {
            mcp_id: McpId(self.mcp_id.clone()),
            auth_domain_id: self.domain_id.clone(),
            owner_id: self.owner_id.clone(),
            client_registration_id: String::new(),
        };
        self.call(false, move |state| {
            let t = state.tokens.get(&token_digest).ok_or(AuthError::Denied)?;
            if t.refresh
                || t.spent
                || t.expires_at <= now
                || t.resource != resource
                || state.families.get(&t.family) != Some(&false)
            {
                return Err(AuthError::Denied);
            }
            encode(Principal {
                client_registration_id: t.client_id.clone(),
                ..principal
            })
        })
        .await
    }

    pub async fn revoke_token(&self, token: &str, client: &str) -> Result<()> {
        let token_digest = digest(token);
        let client = client.to_owned();
        self.call(true, move |state| {
            if let Some(t) = state.tokens.get(&token_digest)
                && t.client_id == client
            {
                state.families.insert(t.family.clone(), true);
            }
            encode(())
        })
        .await
    }

    /// Stable registration identities retained for owner-driven revocation.
    pub async fn registered_client_ids(&self) -> Result<Vec<String>> {
        self.call(false, |state| {
            encode(state.clients.keys().cloned().collect::<Vec<_>>())
        })
        .await
    }

    pub async fn revoke_client(&self, client: &str) -> Result<()> {
        let client = client.to_owned();
        self.call(true, move |state| {
            for token in state.tokens.values().filter(|t| t.client_id == client) {
                state.families.insert(token.family.clone(), true);
            }
            state
                .pending
                .retain(|_, p| p.authorization.client_id != client);
            state
                .codes
                .retain(|_, c| c.authorization.client_id != client);
            encode(())
        })
        .await
    }
}

#[cfg(test)]
mod tests;

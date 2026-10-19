//! 本地所有者管理的设备登记和服务可见范围。
//!
//! invite_device 保存短期邀请，redeem_device 验证设备签名后原子消费邀请并登记。
//! service_allow 另行指定主体可访问的设备；登记和允许转发均不创建终端执行 grant。

use super::*;
use orc_transport::{EnrollmentProof, EnrollmentRequest, Invitation};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteParams {
    name: String,
    request: EnrollmentRequest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemParams {
    invitation: Invitation,
    proof: EnrollmentProof,
}

impl Mcp {
    pub(super) async fn invite_device(&self, params: Value) -> Result<Value, AnyError> {
        let params: InviteParams = serde_json::from_value(params)?;
        if params.name.is_empty()
            || params.name.len() > 128
            || params.name.chars().any(char::is_control)
        {
            return Err("INVALID_DEVICE_NAME".into());
        }
        params.request.verify(now())?;
        let _guard = self.permissions.lock().await;
        if self
            .store
            .get_record("maintenance", "state")
            .await?
            .is_some_and(|s| s["active"] == true)
        {
            return Err("MAINTENANCE".into());
        }
        if self
            .store
            .get_record("device", &params.request.device_id)
            .await?
            .is_some()
        {
            return Err("DEVICE_ALREADY_REGISTERED".into());
        }
        if self.store.list_records("device").await?.len() >= 16 {
            return Err("DEVICE_QUOTA".into());
        }
        if self
            .store
            .list_records("enrollment_invitation")
            .await?
            .iter()
            .filter(|v| {
                v["consumed"] != true
                    && v["expires_at"]
                        .as_u64()
                        .is_some_and(|expiry| expiry > now())
            })
            .count()
            >= 32
        {
            return Err("INVITATION_QUOTA".into());
        }
        let invitation = Invitation::issue(&self.identity, params.request, now())?;
        self.store.put_record("enrollment_invitation",&invitation.nonce,json!({"invitation_digest":invitation.digest()?,"expires_at":invitation.expires_at,"consumed":false,"name":params.name})).await?;
        Ok(serde_json::to_value(invitation)?)
    }
    /// 验证双方签名后交 Store 原子消费邀请和登记设备；成功仍是 trusted_ungranted。
    pub(super) async fn redeem_device(&self, params: Value) -> Result<Value, AnyError> {
        let params: RedeemParams = serde_json::from_value(params)?;
        params.invitation.verify(
            &self.identity.id("mcp")?,
            &self.identity.public_key()?,
            &params.proof.device_id,
            now(),
        )?;
        params.proof.verify(&params.invitation)?;
        let _guard = self.permissions.lock().await;
        if self
            .store
            .get_record("maintenance", "state")
            .await?
            .is_some_and(|s| s["active"] == true)
        {
            return Err("MAINTENANCE".into());
        }
        if self.store.list_records("device").await?.len() >= 16 {
            return Err("DEVICE_QUOTA".into());
        }
        let pending = self
            .store
            .get_record("enrollment_invitation", &params.invitation.nonce)
            .await?
            .ok_or("INVITATION_UNKNOWN")?;
        let request = &params.invitation.request;
        let registration = DeviceRegistration {
            device_id: request.device_id.clone(),
            name: field(&pending, "name")?.into(),
            public_key: request.device_public_key.clone(),
            certificate_digest: request.certificate_digest.clone(),
            revoked: false,
        };
        self.store
            .redeem_invitation(
                &params.invitation.nonce,
                &params.invitation.digest()?,
                &request.device_id,
                serde_json::to_value(&registration)?,
                now(),
            )
            .await?;
        self.repair_delivery_records().await?;
        Ok(
            json!({"state":"trusted_ungranted","device":registration,"execution_grant_created":false}),
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceAllowParams {
    principal_id: String,
    device_ids: BTreeSet<String>,
}
impl Mcp {
    pub(super) async fn register_device(&self, params: Value) -> Result<Value, AnyError> {
        let device: DeviceRegistration = serde_json::from_value(params)?;
        if device.revoked
            || orc_transport::key_id("dev", &orc_transport::verifying_key(&device.public_key)?)
                != device.device_id
        {
            return Err("INVALID_DEVICE_IDENTITY".into());
        }
        if device.name.is_empty()
            || device.name.len() > 128
            || device.name.chars().any(char::is_control)
        {
            return Err("INVALID_DEVICE_NAME".into());
        }
        if !device
            .certificate_digest
            .strip_prefix("sha256:")
            .is_some_and(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
        {
            return Err("INVALID_CERTIFICATE_DIGEST".into());
        }
        let _guard = self.permissions.lock().await;
        if self
            .store
            .get_record("maintenance", "state")
            .await?
            .is_some_and(|state| state["active"] == true)
        {
            return Err("MAINTENANCE".into());
        }
        if self
            .store
            .get_record("device", &device.device_id)
            .await?
            .is_some()
        {
            return Err("DEVICE_ALREADY_REGISTERED".into());
        }
        if self.store.list_records("device").await?.len() >= 16 {
            return Err("DEVICE_QUOTA".into());
        }
        self.store
            .put_record("device", &device.device_id, serde_json::to_value(&device)?)
            .await?;
        self.repair_delivery_records().await?;
        Ok(json!({"state":"trusted_ungranted", "execution_grant_created":false}))
    }
    pub(super) async fn allow_service(&self, params: Value) -> Result<Value, AnyError> {
        let params: ServiceAllowParams = serde_json::from_value(params)?;
        if params.principal_id.is_empty()
            || params.principal_id.len() > 256
            || params.device_ids.len() > 16
        {
            return Err("INVALID_SERVICE_PERMISSION".into());
        }
        let _guard = self.permissions.lock().await;
        if self
            .store
            .get_record("maintenance", "state")
            .await?
            .is_some_and(|value| value["active"] == true)
        {
            return Err("MAINTENANCE".into());
        }

        if self
            .store
            .get_record("service_revoked", &params.principal_id)
            .await?
            .is_some()
        {
            return Err("PRINCIPAL_REVOKED_REAUTHORIZE_NEW_CLIENT".into());
        }
        let previous: BTreeSet<String> = self
            .store
            .get_record("service_allow", &params.principal_id)
            .await?
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default();
        if !previous.is_subset(&params.device_ids) {
            return Err("SERVICE_PERMISSION_NARROWING_REQUIRES_AUTH_REVOKE".into());
        }
        for device in &params.device_ids {
            if !self
                .store
                .get_record("device", device)
                .await?
                .is_some_and(|record| record["revoked"] == false)
            {
                return Err("DEVICE_UNKNOWN_OR_REVOKED".into());
            }
        }
        self.store
            .put_record(
                "service_allow",
                &params.principal_id,
                serde_json::to_value(params.device_ids)?,
            )
            .await?;
        Ok(json!({"updated":true,"endpoint_grants_unchanged":true}))
    }
}

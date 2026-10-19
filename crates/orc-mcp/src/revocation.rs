//! Delivery evidence is an owner-visible acknowledgement of durable revocation,
//! never execution-stop evidence. The global revocation set remains authority.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delivery {
    principal_id: String,
    device_id: String,
    revision: u64,
    state: String,
    requested_at: u64,
    delivered_at: Option<u64>,
}
fn delivery_key(principal: &str, device: &str) -> String {
    format!("{principal}:{device}")
}
impl Mcp {
    pub(super) async fn uninstall_prepare(&self) -> Result<Value, AnyError> {
        let _maintenance = self.maintenance_gate.lock().await;
        self.begin_maintenance().await?;
        for client in self.auth.registered_client_ids().await? {
            let id = self.client_principal(&client)?.id().0;
            match self.store.get_record("service_revoked", &id).await? {
                None => {
                    self.revoke_access(&client).await?;
                }
                Some(record) if record["oauth_revoked"] != true => {
                    let _guard = self.permissions.lock().await;
                    let mut record = self
                        .store
                        .get_record("service_revoked", &id)
                        .await?
                        .ok_or("REVOCATION_UNKNOWN")?;
                    self.auth.revoke_client(&client).await?;
                    record["oauth_revoked"] = json!(true);
                    self.store
                        .put_record("service_revoked", &id, record)
                        .await?;
                    self.repair_delivery_records().await?;
                }
                _ => {}
            }
        }
        let mut evidence = self.maintenance_prepare_inner(true).await?;
        evidence["revocation_applied"] = json!(true);
        evidence["pending_revocation_deliveries"] = json!(0);
        Ok(evidence)
    }
    pub(super) fn client_principal(&self, client: &str) -> Result<Principal, AnyError> {
        Ok(Principal {
            mcp_id: McpId(self.identity.id("mcp")?),
            auth_domain_id: self.config.auth_domain_id.clone(),
            owner_id: self.config.owner_id.clone(),
            client_registration_id: client.into(),
        })
    }
    /// Caller holds permissions except during unpublished startup construction.
    pub(super) async fn repair_delivery_records(&self) -> Result<(), AnyError> {
        let devices = self.store.list_records("device").await?;
        for revoked in self.store.list_records("service_revoked").await? {
            let principal = field(&revoked, "principal_id")?;
            let revision = revoked["revision"]
                .as_u64()
                .ok_or("INVALID_REVOCATION_RECORD")?;
            for device in &devices {
                let device = field(device, "device_id")?;
                let key = delivery_key(principal, device);
                if let Some(existing) = self.store.get_record("revocation_delivery", &key).await? {
                    let existing: Delivery = serde_json::from_value(existing)?;
                    if existing.principal_id != principal
                        || existing.device_id != device
                        || existing.revision > revision
                    {
                        return Err("INVALID_DELIVERY_RECORD".into());
                    }
                    if existing.revision == revision {
                        continue;
                    }
                }
                self.store
                    .put_record(
                        "revocation_delivery",
                        &key,
                        serde_json::to_value(Delivery {
                            principal_id: principal.into(),
                            device_id: device.into(),
                            revision,
                            state: "requested".into(),
                            requested_at: revoked["requested_at"].as_u64().unwrap_or_else(now),
                            delivered_at: None,
                        })?,
                    )
                    .await?;
            }
        }
        Ok(())
    }
    async fn mark_delivered(
        &self,
        device: &str,
        principal: &str,
        revision: u64,
    ) -> Result<(), AnyError> {
        let key = delivery_key(principal, device);
        let mut delivery: Delivery = serde_json::from_value(
            self.store
                .get_record("revocation_delivery", &key)
                .await?
                .ok_or("REVOCATION_DELIVERY_UNKNOWN")?,
        )?;
        if delivery.device_id != device
            || delivery.principal_id != principal
            || delivery.revision != revision
        {
            return Err("REVOCATION_ACK_MISMATCH".into());
        }
        if delivery.state == "delivered" {
            return Ok(());
        }
        delivery.state = "delivered".into();
        delivery.delivered_at = Some(now());
        self.store
            .put_record("revocation_delivery", &key, serde_json::to_value(delivery)?)
            .await?;
        Ok(())
    }
    pub(super) async fn acknowledge_revocation(
        &self,
        device: &str,
        epoch: u64,
        principal: &str,
        revision: u64,
    ) -> Result<(), AnyError> {
        let _guard = self.permissions.lock().await;
        let connection = self
            .connections
            .lock()
            .await
            .get(device)
            .cloned()
            .ok_or("REVOCATION_ACK_OFFLINE")?;
        if connection.epoch != epoch || revision > connection.service_revision {
            return Err("REVOCATION_ACK_MISMATCH".into());
        }
        let record = self
            .store
            .get_record("service_revoked", principal)
            .await?
            .ok_or("REVOCATION_ACK_UNKNOWN")?;
        let expected = record["revision"]
            .as_u64()
            .ok_or("INVALID_REVOCATION_RECORD")?;
        if revision < expected {
            return Ok(());
        } // A newer revoke is still pending.
        if revision != expected {
            return Err("REVOCATION_ACK_MISMATCH".into());
        }
        self.mark_delivered(device, principal, revision).await
    }
    /// Called under the permission lock after verifying Ready's signed sync.
    pub(super) async fn acknowledge_sync(
        &self,
        device: &str,
        revision: u64,
    ) -> Result<(), AnyError> {
        self.repair_delivery_records().await?;
        for revoked in self.store.list_records("service_revoked").await? {
            let record_revision = revoked["revision"]
                .as_u64()
                .ok_or("INVALID_REVOCATION_RECORD")?;
            if record_revision > revision {
                return Err("SYNC_CHANGED".into());
            }
            self.mark_delivered(device, field(&revoked, "principal_id")?, record_revision)
                .await?;
        }
        Ok(())
    }
    pub(super) async fn revocation_deliveries(
        &self,
        principal: Option<&str>,
    ) -> Result<Value, AnyError> {
        let devices = self.store.list_records("device").await?;
        let mut deliveries = vec![];
        // A missing or older derived record is pending, including while a
        // partially completed revoke is awaiting startup/sync repair.
        for revoked in self.store.list_records("service_revoked").await? {
            let id = field(&revoked, "principal_id")?;
            if principal.is_some_and(|requested| requested != id) {
                continue;
            }
            let revision = revoked["revision"]
                .as_u64()
                .ok_or("INVALID_REVOCATION_RECORD")?;
            for device in &devices {
                let device = field(device, "device_id")?;
                let delivery = self
                    .store
                    .get_record("revocation_delivery", &delivery_key(id, device))
                    .await?
                    .map(serde_json::from_value::<Delivery>)
                    .transpose()?;
                if let Some(delivery) = delivery.filter(|delivery| {
                    delivery.revision == revision
                        && delivery.principal_id == id
                        && delivery.device_id == device
                }) {
                    deliveries.push(delivery);
                } else {
                    deliveries.push(Delivery {
                        principal_id: id.into(),
                        device_id: device.into(),
                        revision,
                        state: "requested".into(),
                        requested_at: revoked["requested_at"].as_u64().unwrap_or(0),
                        delivered_at: None,
                    });
                }
            }
        }
        let requested = deliveries
            .iter()
            .filter(|delivery| delivery.state != "delivered")
            .count();
        Ok(
            json!({"requested":requested,"delivered":deliveries.len()-requested,"devices":deliveries,"stop_state":"not_implied_by_delivery"}),
        )
    }
    pub(super) async fn auth_show(&self, client: &str) -> Result<Value, AnyError> {
        let principal = self.client_principal(client)?.id();
        Ok(
            json!({"principal_id":principal,"access_revoked":self.store.get_record("service_revoked",&principal.0).await?.is_some(),"delivery":self.revocation_deliveries(Some(&principal.0)).await?}),
        )
    }
}

pub(super) fn owner_audit(method: &str, success: bool) -> Option<orc_store::AuditEvent> {
    if !matches!(
        method,
        "auth.approve"
            | "auth.revoke"
            | "service.allow"
            | "device.invite"
            | "device.redeem"
            | "device.register"
            | "uninstall.prepare"
    ) {
        return None;
    }
    Some(orc_store::AuditEvent {
        timestamp: now(),
        principal_id: None,
        device_id: None,
        task_id: None,
        action: format!("owner.{method}"),
        outcome: if success { "succeeded" } else { "denied" }.into(),
    })
}

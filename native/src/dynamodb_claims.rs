use crate::{ClaimCode, ClaimInput, ClaimStatus};
use aws_sdk_dynamodb::{Client, types::AttributeValue};
use aws_smithy_types::error::metadata::ProvideErrorMetadata;
use std::env;
use tokio::runtime::Runtime;

pub struct DynamoClaimStore {
    rt: Runtime,
    client: Client,
    table: String,
    execution_timeout: u64,
    clock_skew: u64,
}

impl DynamoClaimStore {
    pub fn from_env() -> Result<Self, ClaimCode> {
        let table =
            env::var("AXIOMATIC_DYNAMODB_CLAIM_TABLE").map_err(|_| ClaimCode::StoreUnavailable)?;
        let execution_timeout = env::var("AXIOMATIC_EXECUTION_TIMEOUT_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);
        let clock_skew = env::var("AXIOMATIC_CLOCK_SKEW_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5);
        let rt = Runtime::new().map_err(|_| ClaimCode::StoreUnavailable)?;
        let config = rt.block_on(async {
            aws_config::defaults(aws_config::BehaviorVersion::latest())
                .load()
                .await
        });
        let client = Client::new(&config);
        rt.block_on(client.describe_table().table_name(&table).send())
            .map_err(|_| ClaimCode::StoreUnavailable)?;
        Ok(Self {
            rt,
            client,
            table,
            execution_timeout,
            clock_skew,
        })
    }

    fn map_write_error<E>(err: &aws_sdk_dynamodb::error::SdkError<E>) -> ClaimCode
    where
        E: ProvideErrorMetadata + std::fmt::Debug,
    {
        if err.as_service_error().and_then(ProvideErrorMetadata::code)
            == Some("ConditionalCheckFailedException")
        {
            ClaimCode::Replay
        } else {
            ClaimCode::StoreUnavailable
        }
    }

    fn reserve(
        &self,
        key: String,
        input: &ClaimInput<'_>,
        approval_id: Option<&str>,
    ) -> Result<(), ClaimCode> {
        let ttl = input.expires.saturating_add(self.clock_skew);
        let mut req = self
            .client
            .put_item()
            .table_name(&self.table)
            .item("claimKey", AttributeValue::S(key))
            .item(
                "envelopeId",
                AttributeValue::S(input.envelope_id.to_owned()),
            )
            .item("kid", AttributeValue::S(input.kid.to_owned()))
            .item(
                "canonicalActionHash",
                AttributeValue::S(input.action_hash.to_owned()),
            )
            .item("issuedAt", AttributeValue::N(input.issued.to_string()))
            .item("expiresAt", AttributeValue::N(input.expires.to_string()))
            .item("claimedAt", AttributeValue::N(input.now.to_string()))
            .item("ttlEpoch", AttributeValue::N(ttl.to_string()))
            .item("state", AttributeValue::S("claimed".to_owned()))
            .condition_expression("attribute_not_exists(claimKey)");
        if let Some(id) = approval_id {
            req = req.item("approvalId", AttributeValue::S(id.to_owned()));
        }
        self.rt
            .block_on(req.send())
            .map(|_| ())
            .map_err(|e| Self::map_write_error(&e))
    }

    pub fn claim(&self, input: &ClaimInput<'_>) -> Result<(), ClaimCode> {
        if let Some(approval_id) = input.approval_id {
            self.reserve(format!("approval#{approval_id}"), input, Some(approval_id))?;
        }
        self.reserve(
            format!("decision#{}", input.envelope_id),
            input,
            input.approval_id,
        )
    }

    pub fn complete(
        &self,
        envelope_id: &str,
        executed: bool,
        now: u64,
        reason: Option<&str>,
    ) -> Result<(), ClaimCode> {
        let state = if executed { "executed" } else { "failed" };
        let reason = reason.unwrap_or("");
        let req = self
            .client
            .update_item()
            .table_name(&self.table)
            .key(
                "claimKey",
                AttributeValue::S(format!("decision#{envelope_id}")),
            )
            .update_expression("SET #state = :new, outcomeAt = :now, failureReason = :reason")
            .condition_expression("#state = :claimed")
            .expression_attribute_names("#state", "state")
            .expression_attribute_values(":new", AttributeValue::S(state.to_owned()))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .expression_attribute_values(":reason", AttributeValue::S(reason.to_owned()))
            .expression_attribute_values(":claimed", AttributeValue::S("claimed".to_owned()));
        self.rt
            .block_on(req.send())
            .map(|_| ())
            .map_err(|e| Self::map_write_error(&e))
    }

    pub fn status(&self, envelope_id: &str, now: u64) -> Result<ClaimStatus, ClaimCode> {
        let out = self
            .rt
            .block_on(
                self.client
                    .get_item()
                    .table_name(&self.table)
                    .key(
                        "claimKey",
                        AttributeValue::S(format!("decision#{envelope_id}")),
                    )
                    .consistent_read(true)
                    .send(),
            )
            .map_err(|_| ClaimCode::StoreUnavailable)?;
        let item = out.item().ok_or(ClaimCode::StoreUnavailable)?;
        let state = item
            .get("state")
            .and_then(|v| v.as_s().ok())
            .ok_or(ClaimCode::StoreUnavailable)?;
        match state.as_str() {
            "executed" => Ok(ClaimStatus::Executed),
            "failed" => Ok(ClaimStatus::Failed),
            "claimed" => {
                let claimed = item
                    .get("claimedAt")
                    .and_then(|v| v.as_n().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or(ClaimCode::StoreUnavailable)?;
                if now > claimed.saturating_add(self.execution_timeout) {
                    Ok(ClaimStatus::Unknown)
                } else {
                    Ok(ClaimStatus::Claimed)
                }
            }
            _ => Err(ClaimCode::StoreUnavailable),
        }
    }
}
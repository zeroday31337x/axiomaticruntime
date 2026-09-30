#[cfg(feature = "marketplace")]
use aws_sdk_licensemanager::{
    Client,
    operation::checkout_license::CheckoutLicenseOutput,
    types::{CheckoutType, EntitlementData, EntitlementDataUnit},
};
#[cfg(feature = "marketplace")]
use aws_smithy_types::timeout::TimeoutConfig;
#[cfg(feature = "marketplace")]
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

#[cfg(feature = "marketplace")]
const PRODUCT_SKU: &str = "prod-czd7ovaeogbya";
#[cfg(feature = "marketplace")]
const MARKETPLACE_FINGERPRINT: &str = "aws:294406891311:AWS/Marketplace:issuer-fingerprint";
#[cfg(feature = "marketplace")]
const ENTITLEMENT: &str = "AxiomaticRuntime";
#[cfg(feature = "marketplace")]
const RECHECK_SECONDS: u64 = 15 * 60;

#[cfg(not(feature = "marketplace"))]
pub struct LicenseLease;

#[cfg(not(feature = "marketplace"))]
pub fn checkout() -> Result<LicenseLease, String> {
    Ok(LicenseLease)
}

#[cfg(feature = "marketplace")]
pub struct LicenseLease {
    client: Client,
    token: Arc<Mutex<String>>,
    stop: Arc<AtomicBool>,
}

#[cfg(feature = "marketplace")]
fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Runtime::new().map_err(|e| format!("license runtime: {e}"))
}

#[cfg(feature = "marketplace")]
fn current_token(token: &Mutex<String>) -> Result<String, String> {
    token
        .lock()
        .map_err(|_| "license token lock poisoned".to_owned())
        .map(|v| v.clone())
}

#[cfg(feature = "marketplace")]
fn requested_entitlement() -> Result<EntitlementData, String> {
    EntitlementData::builder()
        .name(ENTITLEMENT)
        .unit(EntitlementDataUnit::Count)
        .value("1")
        .build()
        .map_err(|e| format!("license entitlement config: {e}"))
}

#[cfg(feature = "marketplace")]
fn validate_checkout(output: &CheckoutLicenseOutput) -> Result<String, String> {
    if output.checkout_type() != Some(&CheckoutType::Provisional) {
        return Err("marketplace license returned wrong checkout type".into());
    }
    let allowed = output.entitlements_allowed().iter().any(|e| {
        e.name() == ENTITLEMENT
            && e.unit() == &EntitlementDataUnit::Count
            && e.value()
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|v| v >= 1)
    });
    if !allowed {
        return Err("marketplace license did not grant one AxiomaticRuntime entitlement".into());
    }
    if output.issued_at().filter(|v| !v.is_empty()).is_none() {
        return Err("marketplace license returned no issued-at time".into());
    }
    if output.expiration().filter(|v| !v.is_empty()).is_none() {
        return Err("marketplace license returned no expiration".into());
    }
    output
        .license_consumption_token()
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "marketplace license returned no consumption token".to_owned())
}

#[cfg(feature = "marketplace")]
fn fresh_checkout(rt: &tokio::runtime::Runtime, client: &Client) -> Result<String, String> {
    let entitlement = requested_entitlement()?;
    let output = rt
        .block_on(
            client
                .checkout_license()
                .product_sku(PRODUCT_SKU)
                .checkout_type(CheckoutType::Provisional)
                .key_fingerprint(MARKETPLACE_FINGERPRINT)
                .entitlements(entitlement)
                .client_token(uuid::Uuid::new_v4().to_string())
                .send(),
        )
        .map_err(|e| format!("marketplace license checkout failed: {e}"))?;
    validate_checkout(&output)
}

#[cfg(feature = "marketplace")]
impl LicenseLease {
    pub fn start_heartbeat(&self) -> Result<(), String> {
        let client = self.client.clone();
        let token = Arc::clone(&self.token);
        let stop = Arc::clone(&self.stop);
        thread::Builder::new()
            .name("axiomatic-license-heartbeat".to_owned())
            .spawn(move || {
                loop {
                    for _ in 0..RECHECK_SECONDS {
                        if stop.load(Ordering::Acquire) {
                            return;
                        }
                        thread::sleep(Duration::from_secs(1));
                    }

                    // Marketplace recommends a fresh CheckoutLicense on a regular cadence so
                    // upgrades, renewals and expiry are observed. For a one-count floating
                    // entitlement we check the current token in before acquiring a new one.
                    // Any failure is fail-closed: the runtime exits instead of continuing on
                    // stale entitlement state.
                    let current = match current_token(&token) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("license recheck failed: {e}");
                            std::process::exit(1)
                        }
                    };
                    let rt = match runtime() {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("license recheck failed: {e}");
                            std::process::exit(1)
                        }
                    };
                    if let Err(e) = rt.block_on(
                        client
                            .check_in_license()
                            .license_consumption_token(current)
                            .send(),
                    ) {
                        eprintln!("license recheck failed during check-in: {e}");
                        std::process::exit(1)
                    }
                    let next = match fresh_checkout(&rt, &client) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("license recheck failed: {e}");
                            std::process::exit(1)
                        }
                    };
                    match token.lock() {
                        Ok(mut guard) => *guard = next,
                        Err(_) => {
                            eprintln!("license recheck failed: token lock poisoned");
                            std::process::exit(1)
                        }
                    }
                }
            })
            .map_err(|e| format!("license heartbeat spawn: {e}"))?;
        Ok(())
    }

    pub fn install_shutdown_handler(&self) -> Result<(), String> {
        let client = self.client.clone();
        let token = Arc::clone(&self.token);
        let stop = Arc::clone(&self.stop);
        ctrlc::set_handler(move || {
            stop.store(true, Ordering::Release);
            if let Ok(current) = current_token(&token)
                && let Ok(rt) = runtime()
                && let Err(e) = rt.block_on(
                    client
                        .check_in_license()
                        .license_consumption_token(current)
                        .send(),
                )
            {
                eprintln!("license check-in failed during shutdown: {e}");
            }
            std::process::exit(0)
        })
        .map_err(|e| format!("license shutdown handler: {e}"))
    }
}

#[cfg(feature = "marketplace")]
pub fn checkout() -> Result<LicenseLease, String> {
    let timeout_ms = 3000u64;
    let rt = runtime()?;
    let timeout = TimeoutConfig::builder()
        .operation_attempt_timeout(Duration::from_millis(timeout_ms))
        .operation_timeout(Duration::from_millis(timeout_ms.saturating_add(500)))
        .build();
    let shared = rt.block_on(async {
        aws_config::defaults(aws_config::BehaviorVersion::latest())
            .timeout_config(timeout)
            .load()
            .await
    });
    let client = Client::new(&shared);
    let token = fresh_checkout(&rt, &client)?;
    Ok(LicenseLease {
        client,
        token: Arc::new(Mutex::new(token)),
        stop: Arc::new(AtomicBool::new(false)),
    })
}
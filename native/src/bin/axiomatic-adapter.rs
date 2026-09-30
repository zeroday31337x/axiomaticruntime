#[cfg(feature = "dynamodb-claims")]
use axiomatic_runtime_native::dynamodb_claims::DynamoClaimStore;
use axiomatic_runtime_native::{
    COMPILED_RELEASE_ID, ClaimInput, ClaimStatus, DecisionKind, FileClaimStore, VerifyContext,
    disable_core_dumps, load_keyring_file, verify_approval, verify_decision,
};
use std::{env, fs, io::Write, path::Path};

fn now() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock_error".to_owned())
        .map(|d| d.as_secs())
}
fn audit(code: &str, detail: &str) {
    if let Ok(path) = env::var("AXIOMATIC_AUDIT_LOG")
        && let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        let _ = writeln!(f, "code={code} detail={detail}");
    }
}
fn cfg_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn context<'a>(
    keys: &'a std::collections::HashMap<String, axiomatic_runtime_native::TrustedKey>,
    revoked: &'a std::collections::HashSet<String>,
    audience: &'a str,
    release: &'a str,
    now: u64,
) -> VerifyContext<'a> {
    VerifyContext {
        keys,
        revoked,
        expected_audience: audience,
        expected_release: release,
        now,
        skew: cfg_u64("AXIOMATIC_CLOCK_SKEW_SECONDS", 5),
        max_validity: cfg_u64("AXIOMATIC_MAX_VALIDITY_SECONDS", 60),
        max_body: 1_048_576,
    }
}

enum ClaimBackend {
    File(FileClaimStore),
    #[cfg(feature = "dynamodb-claims")]
    Dynamo(DynamoClaimStore),
}
impl ClaimBackend {
    fn claim(&self, input: &ClaimInput<'_>) -> Result<(), axiomatic_runtime_native::ClaimCode> {
        match self {
            Self::File(s) => s.claim(input),
            #[cfg(feature = "dynamodb-claims")]
            Self::Dynamo(s) => s.claim(input),
        }
    }
    fn complete(
        &self,
        id: &str,
        executed: bool,
        now: u64,
        reason: Option<&str>,
    ) -> Result<(), axiomatic_runtime_native::ClaimCode> {
        match self {
            Self::File(s) => s.complete(id, executed, now, reason),
            #[cfg(feature = "dynamodb-claims")]
            Self::Dynamo(s) => s.complete(id, executed, now, reason),
        }
    }
    fn status(
        &self,
        id: &str,
        now: u64,
    ) -> Result<ClaimStatus, axiomatic_runtime_native::ClaimCode> {
        match self {
            Self::File(s) => s.status(id, now),
            #[cfg(feature = "dynamodb-claims")]
            Self::Dynamo(s) => s.status(id, now),
        }
    }
}
fn store() -> Result<ClaimBackend, String> {
    match env::var("AXIOMATIC_CLAIM_BACKEND")
        .unwrap_or_else(|_| "file".to_owned())
        .as_str()
    {
        "file" => {
            let dir = env::var("AXIOMATIC_CLAIM_DIR")
                .map_err(|_| "claim_store_unconfigured".to_owned())?;
            Ok(ClaimBackend::File(FileClaimStore::new(
                Path::new(&dir),
                cfg_u64("AXIOMATIC_EXECUTION_TIMEOUT_SECONDS", 30),
            )))
        }
        "dynamodb" => {
            #[cfg(feature = "dynamodb-claims")]
            {
                DynamoClaimStore::from_env()
                    .map(ClaimBackend::Dynamo)
                    .map_err(|_| "claim_store_unavailable".to_owned())
            }
            #[cfg(not(feature = "dynamodb-claims"))]
            {
                Err("claim_store_backend_not_compiled".to_owned())
            }
        }
        _ => Err("claim_store_backend_invalid".to_owned()),
    }
}

fn run() -> Result<(), String> {
    disable_core_dumps().map_err(|e| {
        audit("STARTUP_CORE_DUMP", &e);
        "startup_failed".to_owned()
    })?;
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "verify-claim".to_owned());
    if cmd == "complete" {
        let id = args.next().ok_or("operation_failed")?;
        let state = args.next().ok_or("operation_failed")?;
        let executed = match state.as_str() {
            "executed" => true,
            "failed" => false,
            _ => return Err("operation_failed".into()),
        };
        let reason = args.next();
        store()?
            .complete(&id, executed, now()?, reason.as_deref())
            .map_err(|e| {
                audit(e.as_str(), "claim completion failed");
                "operation_failed".to_owned()
            })?;
        println!("ok");
        return Ok(());
    }
    if cmd == "status" {
        let id = args.next().ok_or("operation_failed")?;
        let st = store()?.status(&id, now()?).map_err(|e| {
            audit(e.as_str(), "claim status failed");
            "operation_failed".to_owned()
        })?;
        let s = match st {
            ClaimStatus::Claimed => "claimed",
            ClaimStatus::Executed => "executed",
            ClaimStatus::Failed => "failed",
            ClaimStatus::Unknown => "unknown",
        };
        println!("{s}");
        return Ok(());
    }
    let decision_path = if cmd == "verify-claim" {
        args.next()
    } else {
        Some(cmd)
    }
    .ok_or("invalid_envelope")?;
    let approval_path = args.next();
    let keyring_path =
        env::var("AXIOMATIC_TRUSTED_KEYS_FILE").map_err(|_| "invalid_envelope".to_owned())?;
    let kr = load_keyring_file(&keyring_path).map_err(|e| {
        audit("KEYRING_STARTUP", &e);
        "invalid_envelope".to_owned()
    })?;
    let audience = env::var("AXIOMATIC_AUDIENCE").map_err(|_| "invalid_envelope".to_owned())?;
    let release = COMPILED_RELEASE_ID.to_owned();
    let n = now()?;
    let ctx = context(&kr.keys, &kr.revoked, &audience, &release, n);
    let raw = fs::read(decision_path).map_err(|_| "invalid_envelope".to_owned())?;
    let decision = verify_decision(&raw, &ctx).map_err(|e| {
        audit(e.as_str(), "decision verification rejected");
        "invalid_envelope".to_owned()
    })?;
    let approval_id = match decision.decision {
        DecisionKind::Retain => None,
        DecisionKind::Gate => {
            let p = approval_path.ok_or_else(|| {
                audit("E033_APPROVAL_REQUIRED", "GATE requires approval artifact");
                "invalid_envelope".to_owned()
            })?;
            let a = fs::read(p).map_err(|_| "invalid_envelope".to_owned())?;
            let verified = verify_approval(&a, &decision, &ctx).map_err(|e| {
                audit(e.as_str(), "approval verification rejected");
                "invalid_envelope".to_owned()
            })?;
            Some(verified.approval_id)
        }
    };
    let st = store()?;
    st.claim(&ClaimInput {
        envelope_id: &decision.envelope_id,
        kid: &decision.kid,
        action_hash: &decision.action_hash,
        issued: decision.issued_at,
        expires: decision.expires_at,
        now: n,
        approval_id: approval_id.as_deref(),
    })
    .map_err(|e| {
        audit(e.as_str(), "consume-once claim rejected");
        "invalid_envelope".to_owned()
    })?;
    let out = serde_json::to_string(&decision.canonical_action)
        .map_err(|_| "invalid_envelope".to_owned())?;
    println!("{out}");
    Ok(())
}
fn main() {
    if let Err(public) = run() {
        eprintln!("{public}");
        std::process::exit(1)
    }
}
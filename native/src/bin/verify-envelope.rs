use axiomatic_runtime_native::{
    COMPILED_RELEASE_ID, VerifyContext, load_keyring_file, verify_decision,
};
use std::{env, fs};

fn run() -> Result<(), String> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: verify-envelope <decision.json>")?;
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    let kr = load_keyring_file(
        env::var("AXIOMATIC_TRUSTED_KEYS_FILE")
            .map_err(|_| "AXIOMATIC_TRUSTED_KEYS_FILE required")?,
    )?;
    let audience = env::var("AXIOMATIC_AUDIENCE").map_err(|_| "AXIOMATIC_AUDIENCE required")?;
    let release = COMPILED_RELEASE_ID.to_owned();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let ctx = VerifyContext {
        keys: &kr.keys,
        revoked: &kr.revoked,
        expected_audience: &audience,
        expected_release: &release,
        now,
        skew: 5,
        max_validity: 60,
        max_body: 1_048_576,
    };
    let d = verify_decision(&raw, &ctx).map_err(|e| e.as_str().to_owned())?;
    println!("{}", d.decision.as_str());
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("invalid_envelope ({e})");
        std::process::exit(1)
    }
}
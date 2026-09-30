use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn write_private(path: &Path, key: &SigningKey) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    f.write_all(&key.to_bytes()).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}
fn kid(key: &SigningKey) -> String {
    hex::encode(Sha256::digest(key.verifying_key().to_bytes()))
}
fn run() -> Result<(), String> {
    let dir = PathBuf::from(
        env::args()
            .nth(1)
            .unwrap_or_else(|| "./axiomatic-keys".to_owned()),
    );
    fs::create_dir(&dir).map_err(|e| format!("create key directory: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    let mut rng = OsRng;
    let decision = SigningKey::generate(&mut rng);
    let approval = SigningKey::generate(&mut rng);
    write_private(&dir.join("decision.key"), &decision)?;
    write_private(&dir.join("approval.key"), &approval)?;
    let keyring = json!({"keys":[
        {"kid":kid(&decision),"role":"decision","publicKey":B64.encode(decision.verifying_key().to_bytes())},
        {"kid":kid(&approval),"role":"approval","publicKey":B64.encode(approval.verifying_key().to_bytes())}
    ],"revokedKids":[]});
    fs::write(
        dir.join("keyring.json"),
        serde_json::to_vec_pretty(&keyring).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "created decision.key, approval.key, and keyring.json in {}",
        dir.display()
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("key generation failed: {e}");
        std::process::exit(1)
    }
}
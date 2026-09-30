use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{env, fs};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    pk: String,
    msg: String,
    sig: String,
}

#[derive(Serialize)]
struct ResultRow {
    id: String,
    accepted: bool,
}

fn decode_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = hex::decode(s).ok()?;
    <[u8; N]>::try_from(bytes).ok()
}

fn verify(c: &Case) -> bool {
    let Some(pk) = decode_hex::<32>(&c.pk) else {
        return false;
    };
    let Some(sig_bytes) = decode_hex::<64>(&c.sig) else {
        return false;
    };
    let Ok(msg) = hex::decode(&c.msg) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    vk.verify_strict(&msg, &sig).is_ok()
}

fn run() -> Result<(), String> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: ed25519-strict-check <cases.json>")?;
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    let cases: Vec<Case> = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let rows: Vec<ResultRow> = cases
        .into_iter()
        .map(|c| ResultRow {
            accepted: verify(&c),
            id: c.id,
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string(&rows).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
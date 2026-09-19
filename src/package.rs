// package.rs — TRONSPK1 delivery package (spec/package-format.md)
//
// Binary layout (all integers little-endian unless noted):
//   0   8   magic "TRONSPK1"
//   8   2   version 0x0001
//   10  4   signer_key_id
//   14  2   pattern_len
//   16  N   pattern (UTF-8, split-key.md §3.1)
//   16+N 33  B (compressed secp256k1)
//   49+N 32  d (big-endian scalar)
//   81+N 8   timestamp (unix seconds, informational only)
//   89+N 64  Ed25519 signature over bytes [0 .. 89+N)
// Total: 153 + N bytes, exact — trailing bytes MUST be rejected.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use subtle::ConstantTimeEq;

pub const MAGIC: &[u8; 8] = b"TRONSPK1";
pub const VERSION: u16 = 0x0001;
pub const MAX_PATTERN_LEN: usize = 64;
pub const BODY_LEN: usize = 89; // header+trailer bytes before the signature
pub const SIG_LEN: usize = 64;
pub const HEADER_LEN: usize = 16;

/// Embedded signer key table, `key_id → Ed25519 public key` (rotation-ready).
/// DEV PLACEHOLDER: key 0x00000001 is a throwaway development key — replace
/// with the production signing key at P4. The matching secret key lives
/// offline outside all repositories and is never committed.
pub static SIGNER_KEYS: &[(u32, [u8; 32])] = &[(0x00000001, crate::devkey::PUBLIC_KEY)];

/// A parsed, signature-verified package.
#[derive(Debug, Clone)]
pub struct Package {
    pub key_id: u32,
    pub pattern: String,
    pub b: [u8; 33],
    pub d: [u8; 32],
    pub timestamp: u64,
}

/// Parse + verify a package against the embedded key table (§3 procedure:
/// parse → magic/version → pubkey lookup → Ed25519 verify → return fields).
/// Signature failure aborts before any further processing.
pub fn parse(data: &[u8]) -> Result<Package, String> {
    parse_with_keys(data, SIGNER_KEYS)
}

/// Same as `parse` but against a caller-supplied key table (test seam).
pub fn parse_with_keys(data: &[u8], keys: &[(u32, [u8; 32])]) -> Result<Package, String> {
    if data.len() < HEADER_LEN + 137 {
        return Err(format!("invalid package: too short ({} bytes)", data.len()));
    }
    if !bool::from(data[..8].ct_eq(MAGIC)) {
        return Err("invalid or tampered package".into());
    }
    if u16::from_le_bytes(data[8..10].try_into().unwrap()) != VERSION {
        return Err("invalid or tampered package".into());
    }
    let key_id = u32::from_le_bytes(data[10..14].try_into().unwrap());
    let pattern_len = u16::from_le_bytes(data[14..16].try_into().unwrap()) as usize;
    if pattern_len > MAX_PATTERN_LEN {
        return Err(format!(
            "invalid package: pattern_len {pattern_len} > {MAX_PATTERN_LEN}"
        ));
    }
    // Exact-length rule: signature must land exactly at EOF (§1.2).
    if data.len() != 153 + pattern_len {
        return Err(format!(
            "invalid package: length {} != 153 + pattern_len {pattern_len}",
            data.len()
        ));
    }
    let n = pattern_len;
    let sig_offset = BODY_LEN + n;
    let sig_bytes: &[u8; 64] = data[sig_offset..sig_offset + SIG_LEN].try_into().unwrap();

    let key_bytes = keys
        .iter()
        .find(|(id, _)| *id == key_id)
        .map(|(_, k)| k)
        .ok_or_else(|| format!("unknown signer_key_id 0x{key_id:08x}"))?;
    let vkey = VerifyingKey::from_bytes(key_bytes)
        .map_err(|_| "invalid embedded signer key".to_string())?;
    let sig = Signature::from_slice(sig_bytes).map_err(|e| format!("malformed signature: {e}"))?;
    vkey.verify(&data[..sig_offset], &sig)
        .map_err(|_| "invalid or tampered package".to_string())?;

    // Only now, post-verify, interpret the payload fields.
    let pattern = std::str::from_utf8(&data[HEADER_LEN..HEADER_LEN + n])
        .map_err(|_| "invalid package: pattern is not UTF-8".to_string())?
        .to_owned();
    crate::pattern::Pattern::parse(&pattern)
        .map_err(|e| format!("invalid package: bad pattern field: {e}"))?;
    let mut pkg = Package {
        key_id,
        pattern,
        b: [0u8; 33],
        d: [0u8; 32],
        timestamp: u64::from_le_bytes(data[81 + n..89 + n].try_into().unwrap()),
    };
    pkg.b.copy_from_slice(&data[16 + n..49 + n]);
    pkg.d.copy_from_slice(&data[49 + n..81 + n]);
    Ok(pkg)
}

/// Serialize the unsigned package body: magic..timestamp, exactly 89+N
/// bytes. Shared by `build_and_sign` and the seller-side offline signer
/// (`tron pkg-sign` signs a body produced without a signing key).
pub fn build_body(
    key_id: u32,
    pattern: &str,
    b: &[u8; 33],
    d: &[u8; 32],
    timestamp: u64,
) -> Vec<u8> {
    let n = pattern.len();
    let mut out = Vec::with_capacity(153 + n);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&key_id.to_le_bytes());
    out.extend_from_slice(&(n as u16).to_le_bytes());
    out.extend_from_slice(pattern.as_bytes());
    out.extend_from_slice(b);
    out.extend_from_slice(d);
    out.extend_from_slice(&timestamp.to_le_bytes());
    out
}

/// Serialize + sign a package (issuer side: pkg-sign-dev, tests).
/// `key_id` must match `signing_key`'s embedded identity.
pub fn build_and_sign(
    key_id: u32,
    pattern: &str,
    b: &[u8; 33],
    d: &[u8; 32],
    timestamp: u64,
    signing_key: &SigningKey,
) -> Vec<u8> {
    let mut out = build_body(key_id, pattern, b, d, timestamp);
    let sig = signing_key.sign(&out);
    out.extend_from_slice(&sig.to_bytes());
    out
}

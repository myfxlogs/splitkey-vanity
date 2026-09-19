// order.rs — §8 order commitment + TIP-191 shared ECDSA plumbing
//
// Both the order commitment (split-key.md §8) and TIP-191 message signing
// (message-signing.md) use the same wire convention:
//   digest = keccak256( "\x19<domain>:\n" ‖ decimal(len_bytes) ‖ payload )
//   sig    = secp256k1_sign(digest, key)   // r ‖ s ‖ v, low-s, v ∈ {27,28}
// The digest is signed as-is — the signature primitive MUST NOT hash again.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

pub const ORDER_DOMAIN: &str = "\x19TRON Vanity Order:\n";
pub const TIP191_DOMAIN: &str = "\x19TRON Signed Message:\n";
pub const ORDER_VERSION: &str = "TRONSPK-ORDER-v1";

/// Canonical order message (§8, exact bytes):
/// `TRONSPK-ORDER-v1|<pattern-canonical>|<B-hex-66-lowercase>`
pub fn build_order_text(pattern_canonical: &str, b_hex: &str) -> String {
    format!("{ORDER_VERSION}|{pattern_canonical}|{b_hex}")
}

/// keccak256( domain ‖ decimal(len_bytes(payload)) ‖ payload )
/// len_bytes is the UTF-8 byte length, not the character count.
fn prefixed_digest(domain: &str, payload: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(domain.as_bytes());
    h.update(payload.len().to_string().as_bytes());
    h.update(payload);
    h.finalize().into()
}

/// §8 order digest.
pub fn order_digest(order_text: &str) -> [u8; 32] {
    prefixed_digest(ORDER_DOMAIN, order_text.as_bytes())
}

/// TIP-191 message digest.
pub fn tip191_digest(msg: &str) -> [u8; 32] {
    prefixed_digest(TIP191_DOMAIN, msg.as_bytes())
}

/// H = keccak256(order) — the escrow payment-binding fingerprint (§8).
pub fn order_fingerprint(order_text: &str) -> [u8; 32] {
    Keccak256::digest(order_text.as_bytes()).into()
}

/// Sign a 32-byte digest as-is with RFC6979 + low-s + v ∈ {27,28}
/// (65 bytes: r ‖ s ‖ v). Interoperates with libsecp256k1/TronWeb.
pub fn sign_digest(
    digest: &[u8; 32],
    priv_key: &[u8; 32],
) -> Result<zeroize::Zeroizing<[u8; 65]>, String> {
    let signing_key =
        SigningKey::from_slice(priv_key).map_err(|e| format!("invalid signing key: {e}"))?;
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(digest)
        .map_err(|e| format!("signing failed: {e}"))?;

    // Signers MUST emit low-s. k256 does not normalize here, so negate s and
    // flip the recovery parity ourselves — same convention as libsecp256k1.
    let (sig, flipped) = match sig.normalize_s() {
        Some(low) => (low, true),
        None => (sig, false),
    };
    let recid = RecoveryId::new(recid.is_y_odd() ^ flipped, recid.is_x_reduced());

    let mut out = zeroize::Zeroizing::new([0u8; 65]);
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = 27 + u8::from(recid.is_y_odd());
    Ok(out)
}

/// Recover the verifying key from (digest, r‖s‖v). Verifiers accept
/// v ∈ {0,1,27,28} (normalizing 0/1) and MUST reject any other value.
pub fn recover_pubkey(digest: &[u8; 32], sig: &[u8]) -> Result<VerifyingKey, String> {
    if sig.len() != 65 {
        return Err(format!("signature must be 65 bytes, got {}", sig.len()));
    }
    let v = sig[64];
    let y_odd = match v {
        0 | 27 => false,
        1 | 28 => true,
        _ => return Err(format!("invalid recovery id v={v} (accepted: 0,1,27,28)")),
    };
    let sig = Signature::from_slice(&sig[..64]).map_err(|e| format!("invalid signature: {e}"))?;
    VerifyingKey::recover_from_prehash(digest, &sig, RecoveryId::new(y_odd, false))
        .map_err(|e| format!("ecrecover failed: {e}"))
}

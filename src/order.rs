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
pub const ORDER_VERSION_V2: &str = "TRONSPK-ORDER-v2";

/// Canonical order message (§8, exact bytes):
/// `TRONSPK-ORDER-v1|<pattern-canonical>|<B-hex-66-lowercase>`
pub fn build_order_text(pattern_canonical: &str, b_hex: &str) -> String {
    format!("{ORDER_VERSION}|{pattern_canonical}|{b_hex}")
}

/// §8 v2 order — adds the grant credential as a fourth field. The buyer
/// signature covers the full text including the grant, so a swapped or
/// stripped grant invalidates the order.
/// `TRONSPK-ORDER-v2|<pattern-canonical>|<B-hex>|<TG1.…​.…>`
pub fn build_order_text_v2(pattern_canonical: &str, b_hex: &str, grant: &str) -> String {
    format!("{ORDER_VERSION_V2}|{pattern_canonical}|{b_hex}|{grant}")
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

/// Parsed `.tronorder` file (§8): order text + buyer signature.
/// `grant` is Some for v2 orders (raw `TG1.…​.…` string), None for v1.
pub struct OrderFile {
    pub order_text: String,
    pub pattern: crate::pattern::Pattern,
    /// Compressed-pubkey B as written in the order text (lowercase hex).
    pub b_hex: String,
    /// v2 grant credential as embedded in the order text.
    pub grant: Option<String>,
    pub signature: [u8; 65],
}

/// Parse a `.tronorder` file: `<order_text>\n0x<130-hex sig>\n` — exactly
/// two lines. v1 = 3 fields, v2 = 4 fields (grant). For v2 the embedded
/// grant must parse AND its payload pattern must equal the order pattern.
/// Structural parse only; call [`order_signature_ok`] for the
/// cryptographic check.
pub fn parse_order_file(data: &[u8]) -> Result<OrderFile, String> {
    let text = std::str::from_utf8(data).map_err(|_| "order file is not UTF-8".to_string())?;
    let mut lines = text.lines();
    let order_text = lines.next().ok_or("order file is empty")?.to_string();
    let sig_line = lines
        .next()
        .ok_or("order file missing signature line")?
        .trim();
    if lines.next().is_some() {
        return Err("order file has extra lines".into());
    }
    let mut fields = order_text.split('|');
    let version = fields.next().unwrap_or("");
    let is_v2 = match version {
        v if v == ORDER_VERSION => false,
        v if v == ORDER_VERSION_V2 => true,
        _ => return Err(format!("not a {ORDER_VERSION} order")),
    };
    let pattern =
        crate::pattern::Pattern::parse(fields.next().ok_or("order missing pattern field")?)?;
    let b_hex = fields.next().ok_or("order missing B field")?.to_string();
    let grant = if is_v2 {
        let g = fields.next().ok_or("v2 order missing grant field")?;
        let parsed =
            crate::grant::Grant::parse(g).map_err(|e| format!("v2 order grant field: {e}"))?;
        if parsed.pattern != pattern {
            return Err(format!(
                "v2 order pattern {} != grant pattern {}",
                pattern.canonical(),
                parsed.pattern.canonical()
            ));
        }
        Some(g.to_string())
    } else {
        None
    };
    if fields.next().is_some() {
        return Err("order text has extra fields".into());
    }
    crate::point::parse_pubkey_compressed(&b_hex)?;
    let sig_bytes = crate::hex_decode(crate::strip_0x(sig_line), Some(65))
        .map_err(|e| format!("invalid signature encoding: {e}"))?;
    let mut signature = [0u8; 65];
    signature.copy_from_slice(&sig_bytes);
    Ok(OrderFile {
        order_text,
        pattern,
        b_hex,
        grant,
        signature,
    })
}

/// ecrecover(sig, order_digest) == B — the §8 buyer-signature check.
pub fn order_signature_ok(of: &OrderFile) -> bool {
    let (Ok(recovered), Ok(b)) = (
        recover_pubkey(&order_digest(&of.order_text), &of.signature),
        crate::point::parse_pubkey_compressed(&of.b_hex),
    ) else {
        return false;
    };
    recovered.as_affine() == &b
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

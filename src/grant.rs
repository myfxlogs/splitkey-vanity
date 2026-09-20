// grant.rs — seller-issued purchase credential ("grant") codec.
//
// A grant binds an auction outcome (or an admin-issued entitlement) to an
// order: the buyer pastes it into a v2 order, the seller verifies the
// signature and burns the nonce exactly once.
//
// Wire form:  `TG1.<bs58(kid ‖ payload)>.<bs58(sig)>`
//   kid     := u32 little-endian signer key id (package.rs SIGNER_KEYS table)
//   payload := "<pattern-canonical>|<nonce-hex16>|<expiry-unix>|<price-minor>"
//   sig     := ed25519_sign( "TRONVEND-GRANT-v1|" ‖ payload )
//
// `TG1.` is a literal prefix (not base58); fields split on '.', so payload
// must never produce '.' inside its bs58 encoding — bs58 alphabet has no '.'.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::pattern::Pattern;

pub const GRANT_PREFIX: &str = "TG1";
pub const GRANT_DOMAIN: &str = "TRONVEND-GRANT-v1|";

/// A parsed grant. `raw` is the exact wire string — v2 orders embed it
/// verbatim (the signature covers the payload bytes, so re-encoding is
/// forbidden).
#[derive(Clone, Debug)]
pub struct Grant {
    pub key_id: u32,
    /// The signed payload text `pattern|nonce|expiry|price_minor`.
    pub payload: String,
    pub pattern: Pattern,
    pub nonce_hex: String,
    pub expiry_unix: u64,
    /// Price in USDT minor units (6 dp), decimal ASCII.
    pub price_minor: u64,
    /// The full `TG1.…​.…` string as received.
    pub raw: String,
}

impl Grant {
    /// Structural parse: splits `TG1.<bs58>.<bs58>`, decodes kid+payload,
    /// and validates the four payload fields. Does NOT verify the
    /// signature — call [`Grant::verify`].
    pub fn parse(s: &str) -> Result<Grant, String> {
        let s = s.trim();
        let (p1, rest) = s.split_once('.').ok_or("grant: not a TG1.<..>.<..> string")?;
        let (p2, p3) = rest
            .split_once('.')
            .ok_or("grant: not a TG1.<..>.<..> string")?;
        if p1 != GRANT_PREFIX {
            return Err(format!("grant: bad prefix {p1:?} (want TG1)"));
        }
        if p3.contains('.') {
            return Err("grant: extra segments".into());
        }
        let body = bs58::decode(p2)
            .into_vec()
            .map_err(|_| "grant: payload part is not bs58".to_string())?;
        let sig = bs58::decode(p3)
            .into_vec()
            .map_err(|_| "grant: signature part is not bs58".to_string())?;
        if sig.len() != 64 {
            return Err(format!("grant: signature must decode to 64 bytes, got {}", sig.len()));
        }
        if body.len() < 4 {
            return Err("grant: payload part too short".into());
        }
        let key_id = u32::from_le_bytes(body[..4].try_into().unwrap());
        let payload = std::str::from_utf8(&body[4..])
            .map_err(|_| "grant: payload is not UTF-8".to_string())?
            .to_string();

        let (pattern, nonce_hex, expiry_unix, price_minor) = parse_payload(&payload)?;

        Ok(Grant {
            key_id,
            payload,
            pattern,
            nonce_hex: nonce_hex.to_string(),
            expiry_unix,
            price_minor,
            raw: s.to_string(),
        })
    }

    /// Ed25519-verify `TRONVEND-GRANT-v1|<payload>` against a key table
    /// (`package::SIGNER_KEYS` for production).
    pub fn verify(&self, keys: &[(u32, [u8; 32])]) -> Result<(), String> {
        let sig_part = self
            .raw
            .rsplit_once('.')
            .map(|(_, p)| p)
            .ok_or("grant: malformed raw string")?;
        let sig_bytes = bs58::decode(sig_part)
            .into_vec()
            .map_err(|_| "grant: signature part is not bs58".to_string())?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|e| format!("grant: invalid signature: {e}"))?;
        let vkey = keys
            .iter()
            .find(|(id, _)| *id == self.key_id)
            .map(|(_, k)| VerifyingKey::from_bytes(k))
            .ok_or_else(|| format!("grant: unknown signer key_id 0x{:08x}", self.key_id))?
            .map_err(|e| format!("grant: bad signer pubkey: {e}"))?;
        let msg = format!("{GRANT_DOMAIN}{}", self.payload);
        vkey.verify(msg.as_bytes(), &sig)
            .map_err(|_| "grant: signature verification failed".into())
    }

    /// Issue a grant: sign `"TRONVEND-GRANT-v1|" ‖ payload` and wrap.
    /// Seller-side (offline signer); the nonce is assigned by the caller
    /// (vend allocates it at auction close so the order table can consume it).
    pub fn issue(key_id: u32, payload: &str, signing_key: &SigningKey) -> Result<String, String> {
        let msg = format!("{GRANT_DOMAIN}{payload}");
        let sig = signing_key.sign(msg.as_bytes());
        let mut body = Vec::with_capacity(4 + payload.len());
        body.extend_from_slice(&key_id.to_le_bytes());
        body.extend_from_slice(payload.as_bytes());
        Ok(format!(
            "{GRANT_PREFIX}.{}.{}",
            bs58::encode(&body).into_string(),
            bs58::encode(sig.to_bytes()).into_string()
        ))
    }
}

/// Parse and validate a raw `pattern|nonce|expiry|price_minor` payload.
/// Shared by `Grant::parse` (wire side) and the offline `grant-sign` tool
/// (signing side) so both ends enforce identical field rules.
/// Returns (pattern, nonce_hex, expiry_unix, price_minor).
pub fn parse_payload(payload: &str) -> Result<(Pattern, String, u64, u64), String> {
    let mut f = payload.split('|');
    let pattern_str = f.next().ok_or("grant payload: missing pattern")?;
    let nonce = f.next().ok_or("grant payload: missing nonce")?;
    let expiry = f.next().ok_or("grant payload: missing expiry")?;
    let price = f.next().ok_or("grant payload: missing price")?;
    if f.next().is_some() {
        return Err("grant payload: extra fields".into());
    }
    let pattern = Pattern::parse(pattern_str)
        .map_err(|e| format!("grant payload pattern: {e}"))?;
    if pattern.canonical() != pattern_str {
        return Err(format!("grant payload: non-canonical pattern {pattern_str:?}"));
    }
    if nonce.len() != 16 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("grant payload: nonce must be 16 hex chars, got {nonce:?}"));
    }
    let expiry_unix: u64 = expiry
        .parse()
        .map_err(|_| format!("grant payload: bad expiry {expiry:?}"))?;
    let price_minor: u64 = price
        .parse()
        .map_err(|_| format!("grant payload: bad price {price:?}"))?;
    Ok((pattern, nonce.to_string(), expiry_unix, price_minor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_key() -> (u32, SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        (3, sk, vk.to_bytes())
    }

    const PAYLOAD: &str = "suffix:8888|0123456789abcdef|1800000000|5990000";

    #[test]
    fn roundtrip_issue_parse_verify() {
        let (kid, sk, pk) = test_key();
        let g = Grant::issue(kid, PAYLOAD, &sk).unwrap();
        assert!(g.starts_with("TG1."));
        let parsed = Grant::parse(&g).unwrap();
        assert_eq!(parsed.key_id, kid);
        assert_eq!(parsed.payload, PAYLOAD);
        assert_eq!(parsed.pattern, Pattern::Suffix("8888".into()));
        assert_eq!(parsed.nonce_hex, "0123456789abcdef");
        assert_eq!(parsed.expiry_unix, 1800000000);
        assert_eq!(parsed.price_minor, 5990000);
        parsed.verify(&[(kid, pk)]).unwrap();
    }

    #[test]
    fn verify_fails_on_tamper_and_wrong_key() {
        let (kid, sk, pk) = test_key();
        let g = Grant::issue(kid, PAYLOAD, &sk).unwrap();
        // Tampered payload → signature fails: decode the body part,
        // mutate the payload text, re-encode, keep the original signature.
        let tampered = {
            let (body_part, sig_part) = g.split_once('.').unwrap().1.rsplit_once('.').unwrap();
            let mut body = bs58::decode(body_part).into_vec().unwrap();
            let pos = body.windows(4).position(|w| w == b"8888").unwrap();
            body[pos..pos + 4].copy_from_slice(b"8887");
            format!("TG1.{}.{}", bs58::encode(&body).into_string(), sig_part)
        };
        let tp = Grant::parse(&tampered).unwrap();
        assert_eq!(tp.pattern, Pattern::Suffix("8887".into())); // parse is structural — it succeeds
        assert!(tp.verify(&[(kid, pk)]).is_err());
        // Unknown kid.
        let g2 = Grant::issue(9, PAYLOAD, &sk).unwrap();
        assert!(Grant::parse(&g2).unwrap().verify(&[(kid, pk)]).is_err());
        // Wrong key entirely.
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let g3 = Grant::issue(kid, PAYLOAD, &other).unwrap();
        assert!(Grant::parse(&g3).unwrap().verify(&[(kid, pk)]).is_err());
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "TG1",
            "TG1.x",
            "TG1.x.y.z",
            "XX1.abc.def",
            "TG1.!!!!.abcd",
            "",
            "TG1..",
        ] {
            assert!(Grant::parse(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn rejects_bad_payload_fields() {
        let (kid, sk, _) = test_key();
        for payload in [
            "repeat:04|0123456789abcdef|1|1",     // non-canonical leading zero
            "bogus:1|0123456789abcdef|1|1",       // unknown type
            "suffix:8888|xyz|1|1",                // bad nonce
            "suffix:8888|0123456789abcdef|x|1",   // bad expiry
            "suffix:8888|0123456789abcdef|1|x",   // bad price
            "suffix:8888|0123456789abcdef|1",     // short
            "suffix:8888|0123456789abcdef|1|1|x", // extra field
        ] {
            let g = Grant::issue(kid, payload, &sk).unwrap();
            assert!(Grant::parse(&g).is_err(), "payload {payload:?} must be rejected");
        }
    }
}

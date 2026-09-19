// point.rs — secp256k1 point handling (spec/split-key.md §3)
//
// B is a 33-byte compressed public key (prefix 0x02/0x03). The public
// verification path computes Q = B + d·G without any secret.

use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar, SecretKey};

/// Parse a compressed public key from hex (66 chars, 0x02/0x03 prefix).
/// Accepts either case and trims whitespace per §3 hex rules.
pub fn parse_pubkey_compressed(hex_str: &str) -> Result<AffinePoint, String> {
    let bytes = crate::hex_decode(crate::strip_0x(hex_str), Some(33))
        .map_err(|e| format!("invalid B encoding: {e}"))?;
    // §3 requires strictly 0x02/0x03 — k256 tolerates other tags, so check first.
    if !matches!(bytes[0], 0x02 | 0x03) {
        return Err(format!(
            "invalid compressed point prefix 0x{:02x}",
            bytes[0]
        ));
    }
    Ok(*VerifyingKey::from_sec1_bytes(&bytes)
        .map_err(|e| format!("invalid compressed secp256k1 point: {e}"))?
        .as_affine())
}

/// Compressed SEC1 encoding (33 bytes) of a point → lowercase hex.
pub fn pubkey_compressed_hex(point: &AffinePoint) -> String {
    crate::hex_encode(point.to_encoded_point(true).as_bytes())
}

/// B = b·G from a secret scalar.
pub fn pubkey_from_secret(b: &[u8; 32]) -> Result<AffinePoint, String> {
    point_from_secret(b)
}

/// priv·G — the buyer path.
pub fn point_from_secret(priv_key: &[u8; 32]) -> Result<AffinePoint, String> {
    let sk = SecretKey::from_slice(priv_key).map_err(|e| format!("invalid secret scalar: {e}"))?;
    Ok(*sk.public_key().as_affine())
}

/// Q = B + d·G — the public/arbiter path (§5). `d` must satisfy 1 ≤ d < n.
pub fn add_offset(b: &AffinePoint, d: &[u8; 32]) -> Result<AffinePoint, String> {
    let d_scalar = Option::<Scalar>::from(Scalar::from_repr((*d).into()))
        .filter(|s| !bool::from(s.is_zero()))
        .ok_or_else(|| "d out of range (need 1 ≤ d < n)".to_string())?;
    Ok((ProjectivePoint::from(*b) + ProjectivePoint::GENERATOR * d_scalar).to_affine())
}

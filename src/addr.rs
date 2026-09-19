// addr.rs — TRON address derivation (spec/split-key.md §3.2, normative)
//
//   addr = base58check( 0x41 ‖ keccak256(x ‖ y)[12..32] )
//
// x‖y is the 64-byte uncompressed point WITHOUT the 0x04 prefix.
// keccak256 is original Keccak, not NIST SHA3. Checksum is sha256d.

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::AffinePoint;
use sha3::{Digest, Keccak256};

/// Derive the TRON address (34-char base58check string starting with 'T')
/// from a secp256k1 affine point.
pub fn point_to_address(point: &AffinePoint) -> String {
    let ep = point.to_encoded_point(false); // 0x04 ‖ x ‖ y, 65 bytes
    base58check_payload(&keccak_address_bytes(&ep.as_bytes()[1..]))
}

/// Convenience: address of a secret scalar's public key.
pub fn privkey_to_address(priv_key: &[u8; 32]) -> Result<String, String> {
    Ok(point_to_address(&crate::point::point_from_secret(
        priv_key,
    )?))
}

/// keccak256(x‖y)[12..32] — the 20-byte TRON hash of an uncompressed point.
fn keccak_address_bytes(xy64: &[u8]) -> [u8; 21] {
    debug_assert_eq!(xy64.len(), 64);
    let hash = Keccak256::digest(xy64);
    let mut payload = [0u8; 21];
    payload[0] = 0x41;
    payload[1..].copy_from_slice(&hash[12..]);
    payload
}

/// base58check(payload21) → 34-char address. 'T' is emergent (§3.2), never prepended.
fn base58check_payload(payload: &[u8; 21]) -> String {
    let checksum = sha256d(payload);
    let mut full = [0u8; 25];
    full[..21].copy_from_slice(payload);
    full[21..].copy_from_slice(&checksum[..4]);
    bs58::encode(&full).into_string()
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = sha2::Sha256::digest(data);
    sha2::Sha256::digest(first).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::PrimeField;
    use k256::{ProjectivePoint, Scalar};

    fn scalar(hex: &str) -> Scalar {
        let bytes: [u8; 32] = crate::hex_decode(hex, Some(32))
            .unwrap()
            .try_into()
            .unwrap();
        Option::<Scalar>::from(Scalar::from_repr(bytes.into())).unwrap()
    }

    // spec/split-key.md Appendix A — a conforming implementation must
    // reproduce all five lines exactly.
    #[test]
    fn appendix_a_five_tuple() {
        let b = scalar("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        let d = scalar("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");

        // B = b·G compressed
        let point_b = (ProjectivePoint::GENERATOR * b).to_affine();
        let b_hex = crate::hex_encode(point_b.to_encoded_point(true).as_bytes());
        assert_eq!(
            b_hex,
            "034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff"
        );

        // buyer path: addr((b+d)·G) — public path: addr(B + d·G)
        let addr_priv = {
            let priv_bytes = crate::scalar::add_scalars(
                &crate::hex_decode(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    Some(32),
                )
                .unwrap()
                .try_into()
                .unwrap(),
                &crate::hex_decode(
                    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                    Some(32),
                )
                .unwrap()
                .try_into()
                .unwrap(),
            )
            .unwrap();
            privkey_to_address(&priv_bytes).unwrap()
        };
        let q = ProjectivePoint::from(point_b) + ProjectivePoint::GENERATOR * d;
        let addr_pub = point_to_address(&q.to_affine());

        assert_eq!(addr_priv, addr_pub, "split-key paths must agree");
        assert_eq!(addr_priv, "TSrCk3n9VDyDYtdGnTigc7mTLEUEGwcGPm");
    }
}

// scalar.rs — secret scalar handling (spec/split-key.md §3, §7.1)
//
// Canonical at-rest form: 64 lowercase hex chars + optional single trailing
// newline, file mode 0600. Parsers trim whitespace and validate 1 ≤ x < n.

use std::path::Path;

use k256::elliptic_curve::PrimeField;
use k256::{Scalar, SecretKey};
use zeroize::{Zeroize, Zeroizing};

/// Read a §7.1 scalar file: trim → 64 hex → validate 1 ≤ x < n.
/// Accepts either hex case (§3); rejects `0x` prefixes and any other
/// non-canonical content (fixed trivial format, no labels).
pub fn read_scalar_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let trimmed = raw.trim().to_owned();
    raw.zeroize();

    let bytes = crate::hex_decode(&trimmed, Some(32)).map_err(|e| {
        format!(
            "{}: invalid scalar file (§7.1 wants 64 hex chars): {e}",
            path.display()
        )
    })?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);

    // SecretKey::from_slice enforces exactly 1 ≤ x < n.
    SecretKey::from_slice(&arr)
        .map_err(|_| format!("{}: scalar out of range (need 1 ≤ x < n)", path.display()))?;
    Ok(Zeroizing::new(arr))
}

/// Write a scalar as 64 lowercase hex + trailing newline, mode 0600.
pub fn write_scalar_file(path: &Path, scalar: &[u8; 32]) -> std::io::Result<()> {
    let mut content = crate::hex_encode(scalar);
    content.push('\n');
    crate::write_secret_file(path, content.as_bytes())
}

/// Generate a scalar by CSPRNG rejection sampling (§3 normative): draw 32
/// bytes, reject-and-redraw if 0 or ≥ n. Never reduce mod n (would bias).
pub fn generate_scalar() -> Zeroizing<[u8; 32]> {
    loop {
        let mut cand = Zeroizing::new([0u8; 32]);
        crate::fill_random(&mut *cand);
        if SecretKey::from_slice(&*cand).is_ok() {
            return cand;
        }
    }
}

/// Error from `add_scalars` — degenerate result is a distinct case (§3).
#[derive(Debug, PartialEq, Eq)]
pub enum AddError {
    /// (b + d) mod n == 0 — degenerate, MUST be rejected explicitly.
    Degenerate,
    /// An input was not a canonical scalar (1 ≤ x < n).
    OutOfRange(String),
}

impl std::fmt::Display for AddError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AddError::Degenerate => "degenerate key: priv = (b + d) mod n == 0",
            AddError::OutOfRange(m) => m,
        })
    }
}

/// priv = (b + d) mod n, with the degenerate priv == 0 result explicitly
/// rejected (§3 validation rules). Inputs must already be in range.
pub fn add_scalars(b: &[u8; 32], d: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, AddError> {
    let b_s = scalar_from_bytes(b)?;
    let d_s = scalar_from_bytes(d)?;
    let priv_s = b_s + d_s;
    if bool::from(priv_s.is_zero()) {
        return Err(AddError::Degenerate);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&priv_s.to_bytes());
    Ok(Zeroizing::new(out))
}

fn scalar_from_bytes(x: &[u8; 32]) -> Result<Scalar, AddError> {
    Option::<Scalar>::from(Scalar::from_repr((*x).into()))
        .filter(|s| !bool::from(s.is_zero()))
        .ok_or_else(|| AddError::OutOfRange("scalar out of range (need 1 ≤ x < n)".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const B_VEC: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const D_VEC: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const PRIV_VEC: &str = "000000000000000000000000000000014551231950b75fc4402da1732fc9bebe";

    fn hex32(s: &str) -> [u8; 32] {
        crate::hex_decode(s, Some(32)).unwrap().try_into().unwrap()
    }

    #[test]
    fn add_scalars_matches_appendix_a() {
        let priv_key = add_scalars(&hex32(B_VEC), &hex32(D_VEC)).unwrap();
        assert_eq!(crate::hex_encode(&*priv_key), PRIV_VEC);
    }

    #[test]
    fn add_scalars_rejects_degenerate_zero() {
        // b = 1, d = n - 1  →  (b + d) mod n == 0
        let mut b = [0u8; 32];
        b[31] = 1;
        // n - 1 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
        let d: [u8; 32] = crate::hex_decode(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
            Some(32),
        )
        .unwrap()
        .try_into()
        .unwrap();
        assert_eq!(add_scalars(&b, &d).unwrap_err(), AddError::Degenerate);
    }

    #[test]
    fn generated_scalar_in_range() {
        let s = generate_scalar();
        assert!(SecretKey::from_slice(&*s).is_ok());
    }
}

// redeem.rs — buyer-side acceptance chain (spec/split-key.md §4)
//
// Order context comes ONLY from the buyer's local order record
// (--expect-pattern). The package's pattern field is seller-signed data —
// it describes what was delivered, not what was ordered.

use std::fmt;

use crate::package::Package;
use crate::pattern::Pattern;

/// Failure identifiers — verbatim strings per §4 (distinct errors).
#[derive(Debug, PartialEq, Eq)]
pub enum RedeemError {
    /// priv·G != B_pkg + d·G — package issued for a different b.
    NotBound,
    /// Derived address does not satisfy --expect-pattern.
    OrderMismatch,
    /// Derived address does not satisfy the package's own pattern field.
    PatternMismatch,
    /// Degenerate priv == 0 (§3 explicit rejection).
    DegenerateKey,
    /// Malformed secret material / package fields.
    BadInput(String),
}

impl fmt::Display for RedeemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RedeemError::NotBound => "package not bound to this key file",
            RedeemError::OrderMismatch => "order mismatch",
            RedeemError::PatternMismatch => "pattern mismatch",
            RedeemError::DegenerateKey => "degenerate key: priv = (b + d) mod n == 0",
            RedeemError::BadInput(m) => m,
        })
    }
}

/// Result of a successful redemption.
pub struct RedeemResult {
    pub address: String,
    /// priv = (b + d) mod n — zeroized on drop.
    pub priv_key: zeroize::Zeroizing<[u8; 32]>,
    /// pattern_pkg differs from --expect-pattern (warning, not an error).
    pub pattern_field_differs: bool,
}

/// The §4 verification chain, in order:
///
/// 0. binding check    `priv·G == B_pkg + d·G` → "package not bound to this key file"
/// 1. order check      addr satisfies --expect-pattern → "order mismatch"
/// 2. self-consistency addr satisfies pattern_pkg → "pattern mismatch"
///
/// All checks MUST pass before any private-key material is released.
pub fn verify_delivery(
    pkg: &Package,
    b: &[u8; 32],
    expect: &Pattern,
) -> Result<RedeemResult, RedeemError> {
    // priv = (b + d) mod n (degenerate priv == 0 explicitly rejected, §3)
    let priv_key = crate::scalar::add_scalars(b, &pkg.d).map_err(|e| match e {
        crate::scalar::AddError::Degenerate => RedeemError::DegenerateKey,
        crate::scalar::AddError::OutOfRange(m) => RedeemError::BadInput(m),
    })?;
    let q_priv = crate::point::point_from_secret(&priv_key)
        .map_err(|e| RedeemError::BadInput(e.to_string()))?;

    let b_pkg = crate::point::parse_pubkey_compressed(&crate::hex_encode(&pkg.b))
        .map_err(|e| RedeemError::BadInput(format!("package B invalid: {e}")))?;
    let q_pkg = crate::point::add_offset(&b_pkg, &pkg.d)
        .map_err(|e| RedeemError::BadInput(e.to_string()))?;

    // 0. Binding check — equality holds iff b·G == B_pkg.
    if q_priv != q_pkg {
        return Err(RedeemError::NotBound);
    }

    let addr = crate::addr::point_to_address(&q_priv);

    // 1. Order check — semantic (type, n) tuple, never raw-string equality.
    let pattern_pkg = Pattern::parse(&pkg.pattern)
        .map_err(|e| RedeemError::BadInput(format!("package pattern invalid: {e}")))?;
    if !expect.matches(&addr) {
        return Err(RedeemError::OrderMismatch);
    }
    let pattern_field_differs = pattern_pkg != *expect;

    // 2. Package self-consistency.
    if !pattern_pkg.matches(&addr) {
        return Err(RedeemError::PatternMismatch);
    }

    Ok(RedeemResult {
        address: addr,
        priv_key,
        pattern_field_differs,
    })
}

// redeem.rs — §4 acceptance chain tests (distinct errors, verbatim strings).

use tron_tool::package::Package;
use tron_tool::pattern::Pattern;
use tron_tool::redeem::{verify_delivery, RedeemError};
use tron_tool::{hex_decode, hex_encode};

const B_SCALAR: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const B_PUB: &str = "034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff";
// Brute-forced: addr(B + d·G) = TC14y24mHW2NhihvBtSRo41KpMtjwMPPPP (run of 4).
const D_FOUND: &str = "000000000000000000000000000000000000000000000000000000000003846c";
const ADDR: &str = "TC14y24mHW2NhihvBtSRo41KpMtjwMPPPP";
const PRIV: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789af525b";

fn pkg(pattern: &str, d_hex: &str) -> Package {
    Package {
        key_id: 1,
        pattern: pattern.to_string(),
        b: hex_decode(B_PUB, Some(33)).unwrap().try_into().unwrap(),
        d: hex_decode(d_hex, Some(32)).unwrap().try_into().unwrap(),
        timestamp: 0,
    }
}

fn b_scalar() -> [u8; 32] {
    hex_decode(B_SCALAR, Some(32)).unwrap().try_into().unwrap()
}

#[test]
fn happy_path_releases_priv() {
    let r = verify_delivery(&pkg("repeat:4", D_FOUND), &b_scalar(), &Pattern::Repeat(4)).unwrap();
    assert_eq!(r.address, ADDR);
    assert_eq!(hex_encode(&*r.priv_key), PRIV);
    assert!(!r.pattern_field_differs);
}

#[test]
fn wrong_key_file_is_not_bound() {
    // A package issued for B is presented with a different b.
    let mut other_b = b_scalar();
    other_b[31] ^= 0x01;
    let err = verify_delivery(&pkg("repeat:4", D_FOUND), &other_b, &Pattern::Repeat(4))
        .err()
        .unwrap();
    assert_eq!(err, RedeemError::NotBound);
    assert_eq!(err.to_string(), "package not bound to this key file");
}

#[test]
fn degraded_delivery_is_order_mismatch() {
    // Ordered repeat:5, delivered a repeat:4 result → §4 check 1.
    let err = verify_delivery(&pkg("repeat:4", D_FOUND), &b_scalar(), &Pattern::Repeat(5))
        .err()
        .unwrap();
    assert_eq!(err, RedeemError::OrderMismatch);
    assert_eq!(err.to_string(), "order mismatch");
}

#[test]
fn self_inconsistent_package_is_pattern_mismatch() {
    // Field claims repeat:5, address only has a 4-run → §4 check 2.
    let err = verify_delivery(&pkg("repeat:5", D_FOUND), &b_scalar(), &Pattern::Repeat(4))
        .err()
        .unwrap();
    assert_eq!(err, RedeemError::PatternMismatch);
    assert_eq!(err.to_string(), "pattern mismatch");
}

#[test]
fn degenerate_priv_zero_rejected() {
    // b = 1, d = n - 1 → (b + d) mod n == 0 — §3 explicit rejection.
    let d = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
    let mut b = [0u8; 32];
    b[31] = 1;
    let err = verify_delivery(&pkg("repeat:4", d), &b, &Pattern::Repeat(4))
        .err()
        .unwrap();
    assert_eq!(err, RedeemError::DegenerateKey);
}

#[test]
fn binding_checked_before_pattern_checks() {
    // Wrong key file + inconsistent pattern field → reports binding, not pattern.
    let mut other_b = b_scalar();
    other_b[31] ^= 0x01;
    let err = verify_delivery(&pkg("repeat:5", D_FOUND), &other_b, &Pattern::Repeat(4))
        .err()
        .unwrap();
    assert_eq!(err, RedeemError::NotBound);
}

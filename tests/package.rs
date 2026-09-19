// package.rs — TRONSPK1 parse/verify tests (spec/package-format.md §1.2, §3)
//
// Uses the pinned Appendix B.2 package (signed by the embedded dev key) and
// ephemeral keys via parse_with_keys for round-trips.

use tron_tool::package;
use tron_tool::{hex_decode, hex_encode};

// spec/split-key.md Appendix B.2 — pinned dev-signed package (161 bytes).
const PKG_HEX: &str = "54524f4e53504b3101000100000008007265706561743a34034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff000000000000000000000000000000000000000000000000000000000003846cc072ad6a00000000db1d9f772bc0f6944fa8bf1867736ff9f8ebd17b4083bd99692cc4ec6ac96f12749fcae2bc503660917ffe24dacf29b5ac082b5f82999d50b139886dbf1a8809";

const B_PUB: &str = "034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff";
const D_FOUND: &str = "000000000000000000000000000000000000000000000000000000000003846c";

fn pinned_pkg() -> Vec<u8> {
    hex_decode(PKG_HEX, None).unwrap()
}

#[test]
fn parses_pinned_appendix_b_package() {
    let pkg = package::parse(&pinned_pkg()).unwrap();
    assert_eq!(pkg.key_id, 0x00000001);
    assert_eq!(pkg.pattern, "repeat:4");
    assert_eq!(hex_encode(&pkg.b), B_PUB);
    assert_eq!(hex_encode(&pkg.d), D_FOUND);
    assert_eq!(pkg.timestamp, 1789752000);
}

#[test]
fn rejects_any_byte_tamper() {
    let good = pinned_pkg();
    // Flip one byte at every position — signature region included.
    for i in 0..good.len() {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        // Skip positions whose change is caught by structural checks first;
        // the requirement is: never Ok.
        assert!(
            package::parse(&bad).is_err(),
            "byte {i} tamper must be rejected"
        );
    }
}

#[test]
fn rejects_trailing_and_truncated() {
    let good = pinned_pkg();
    let mut longer = good.clone();
    longer.push(0);
    assert!(
        package::parse(&longer).is_err(),
        "trailing byte must be rejected"
    );
    for cut in [0usize, 8, 16, 100, 160] {
        assert!(
            package::parse(&good[..cut]).is_err(),
            "len {cut} must be rejected"
        );
    }
}

#[test]
fn rejects_bad_magic_and_version() {
    let good = pinned_pkg();
    let mut bad = good.clone();
    bad[0] = b'X';
    assert!(package::parse(&bad).is_err());
    let mut bad = good.clone();
    bad[8] = 0x02; // version 0x0002
    assert!(package::parse(&bad).is_err());
}

#[test]
fn rejects_unknown_key_id() {
    let mut bad = pinned_pkg();
    bad[10..14].copy_from_slice(&9u32.to_le_bytes());
    let err = package::parse(&bad).unwrap_err();
    assert!(err.contains("unknown signer_key_id"), "got: {err}");
}

#[test]
fn rejects_oversize_pattern_len() {
    // pattern_len = 65 > 64 must fail before any allocation/verify.
    let mut bad = pinned_pkg();
    bad[14..16].copy_from_slice(&65u16.to_le_bytes());
    assert!(package::parse(&bad).unwrap_err().contains("pattern_len"));
}

#[test]
fn roundtrip_with_ephemeral_key() {
    let mut sk_bytes = [0u8; 32];
    tron_tool::fill_random(&mut sk_bytes);
    let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
    let table = [(0xdeadbeefu32, sk.verifying_key().to_bytes())];

    let b: [u8; 33] = hex_decode(B_PUB, Some(33)).unwrap().try_into().unwrap();
    let d: [u8; 32] = hex_decode(D_FOUND, Some(32)).unwrap().try_into().unwrap();
    let raw = package::build_and_sign(0xdeadbeef, "repeat:4", &b, &d, 42, &sk);
    assert_eq!(raw.len(), 153 + 8);
    let pkg = package::parse_with_keys(&raw, &table).unwrap();
    assert_eq!(pkg.pattern, "repeat:4");
    assert_eq!(pkg.b, b);
    assert_eq!(pkg.d, d);
    assert_eq!(pkg.timestamp, 42);
}

#[test]
fn verifies_before_pattern_interpretation() {
    // A correctly-signed package with a bogus pattern field must still fail —
    // signature first, grammar after.
    let mut sk_bytes = [0u8; 32];
    tron_tool::fill_random(&mut sk_bytes);
    let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
    let table = [(1u32, sk.verifying_key().to_bytes())];
    let b = [0x02u8; 33];
    let d = [0x01u8; 32];
    let raw = package::build_and_sign(1, "bogus:9", &b, &d, 0, &sk);
    let err = package::parse_with_keys(&raw, &table).unwrap_err();
    assert!(err.contains("pattern"), "got: {err}");
}

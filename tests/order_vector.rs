// order_vector.rs — §8 order signature byte-exact vector (review2 附A).
//
// The candidate vector was produced by an independent second-path
// implementation (libsecp256k1, RFC6979 deterministic nonce, forced low-s).
// tron-tool's k256/RFC6979 path must reproduce digest AND signature
// byte-for-byte — a mismatch means a real implementation bug (re-hash,
// endianness, v-convention divergence), not a spec ambiguity.

use tron_tool::{hex_decode, hex_encode, order, point, scalar};

const B_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ORDER: &str =
    "TRONSPK-ORDER-v1|repeat:8|034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff";
const DIGEST: &str = "f89548aadf0c6d43971742f986b0d3576847cf451150ff7cbd14f7b8151ef960";
const SIG: &str = "420e3ce12529e139633692048f9419bb720ee1af59e3c5b0a8e9e7e62cd9c06e6928f5772a65749c4c31f268bae62ffafdad7baab71fd6676c5de8ba2c9148641c";

fn b_bytes() -> [u8; 32] {
    hex_decode(B_HEX, Some(32)).unwrap().try_into().unwrap()
}

#[test]
fn order_text_is_exactly_92_bytes() {
    let b_point = point::pubkey_from_secret(&b_bytes()).unwrap();
    let order_text = order::build_order_text("repeat:8", &point::pubkey_compressed_hex(&b_point));
    assert_eq!(order_text, ORDER);
    assert_eq!(order_text.len(), 92);
}

#[test]
fn order_digest_matches_candidate_vector() {
    assert_eq!(hex_encode(&order::order_digest(ORDER)), DIGEST);
}

#[test]
fn order_signature_matches_candidate_vector_byte_exact() {
    let digest = order::order_digest(ORDER);
    let sig = order::sign_digest(&digest, &b_bytes()).unwrap();
    assert_eq!(
        hex_encode(&*sig),
        SIG,
        "r‖s‖v must match libsecp256k1 byte-exact"
    );
    assert_eq!(sig[64], 28, "v must be 28 (low-s normalized)");
}

#[test]
fn recovered_pubkey_equals_b() {
    let digest = order::order_digest(ORDER);
    let sig = hex_decode(SIG, Some(65)).unwrap();
    let recovered = order::recover_pubkey(&digest, &sig).unwrap();
    let recovered_hex = tron_tool::hex_encode(
        k256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(recovered.as_affine(), true)
            .as_bytes(),
    );
    assert_eq!(
        recovered_hex,
        "034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff"
    );
}

#[test]
fn parse_order_file_pinned_vector() {
    let data = format!("{ORDER}\n0x{SIG}\n").into_bytes();
    let of = order::parse_order_file(&data).unwrap();
    assert_eq!(of.order_text, ORDER);
    assert_eq!(of.pattern, tron_tool::pattern::Pattern::Repeat(8));
    assert_eq!(
        of.b_hex,
        "034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff"
    );
    assert!(order::order_signature_ok(&of));

    // Flip one signature byte → structural parse still works, crypto check fails.
    let mut bad = data.clone();
    let pos = bad.len() - 3;
    bad[pos] = if bad[pos] == b'0' { b'1' } else { b'0' };
    let of_bad = order::parse_order_file(&bad).unwrap();
    assert!(!order::order_signature_ok(&of_bad));

    for broken in [
        b"".as_slice(),
        b"\n".as_slice(),
        format!("{ORDER}\n").as_bytes(),
        format!("{ORDER}\n0x{SIG}\nextra\n").as_bytes(),
        format!("WRONG-V|repeat:8|034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff\n0x{SIG}\n").as_bytes(),
        format!("{ORDER}|extra\n0x{SIG}\n").as_bytes(),
    ] {
        assert!(order::parse_order_file(broken).is_err(), "{broken:?} must be rejected");
    }
}

#[test]
fn scalar_file_roundtrip_0600() {
    let dir = std::env::temp_dir().join(format!("tron-tool-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("b.key");
    scalar::write_scalar_file(&path, &b_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let loaded = scalar::read_scalar_file(&path).unwrap();
    assert_eq!(*loaded, b_bytes());
    std::fs::remove_dir_all(&dir).ok();
}

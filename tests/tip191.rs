// tip191.rs — TIP-191 message signing (spec/message-signing.md)
//
// Byte-exact pinned vector from spec Appendix B.3 (Chinese statement —
// exercises the UTF-8 byte-length rule) plus English round-trip and
// v-normalization acceptance.

use tron_tool::{addr, hex_decode, hex_encode, order};

const PRIV: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789af525b";
const ADDR: &str = "TC14y24mHW2NhihvBtSRo41KpMtjwMPPPP";
const MSG_CN: &str =
    "收款地址声明：TC14y24mHW2NhihvBtSRo41KpMtjwMPPPP — 商户：SpecTest — 签发：2026-09-19";
const SIG_CN: &str = "3b6b0db55bddf6ab92c55a718d601a4476358be13a93b23fd74ee094d371fb92588171747dc5cbf16cce5f46c6655d8ab8b5d8af3afa7e828c42e541763e7da21b";

fn priv_bytes() -> [u8; 32] {
    hex_decode(PRIV, Some(32)).unwrap().try_into().unwrap()
}

#[test]
fn chinese_message_uses_byte_length() {
    assert_eq!(MSG_CN.chars().count(), 71);
    assert_eq!(MSG_CN.len(), 101); // UTF-8 bytes feed the length prefix
}

#[test]
fn pinned_appendix_b3_signature_byte_exact() {
    let digest = order::tip191_digest(MSG_CN);
    let sig = order::sign_digest(&digest, &priv_bytes()).unwrap();
    assert_eq!(hex_encode(&*sig), SIG_CN);
    assert_eq!(sig[64], 27, "v = 27 per pinned vector");
}

#[test]
fn recovered_address_matches_signer() {
    let digest = order::tip191_digest(MSG_CN);
    let sig = hex_decode(SIG_CN, Some(65)).unwrap();
    let vk = order::recover_pubkey(&digest, &sig).unwrap();
    assert_eq!(addr::point_to_address(vk.as_affine()), ADDR);
}

#[test]
fn english_message_roundtrip() {
    let msg = "Official receive address: TC14y24mHW2NhihvBtSRo41KpMtjwMPPPP — Merchant: SpecTest — Issued: 2026-09-19 — Expiry: 2027-09-19";
    let digest = order::tip191_digest(msg);
    let sig = order::sign_digest(&digest, &priv_bytes()).unwrap();
    let vk = order::recover_pubkey(&digest, &sig[..]).unwrap();
    assert_eq!(addr::point_to_address(vk.as_affine()), ADDR);
}

#[test]
fn v_normalization_accepts_0_1_27_28() {
    let digest = order::tip191_digest(MSG_CN);
    let sig = order::sign_digest(&digest, &priv_bytes()).unwrap();
    // All of {0,1,27,28} are accepted wire values (parity determines which
    // key recovers — wrong parity recovers a different key, still no error).
    for v in [0u8, 1, 27, 28] {
        let mut s = *sig;
        s[64] = v;
        assert!(
            order::recover_pubkey(&digest, &s).is_ok(),
            "v={v} must be accepted"
        );
    }
    // 0/1 normalize to 27/28: v' = v - 27 recovers the signer.
    let mut s = *sig;
    s[64] -= 27;
    let vk = order::recover_pubkey(&digest, &s).unwrap();
    assert_eq!(addr::point_to_address(vk.as_affine()), ADDR);
}

#[test]
fn rejects_other_v_values() {
    let digest = order::tip191_digest(MSG_CN);
    let sig = order::sign_digest(&digest, &priv_bytes()).unwrap();
    for v in [2u8, 26, 29, 30, 255] {
        let mut s = *sig;
        s[64] = v;
        let err = order::recover_pubkey(&digest, &s).unwrap_err();
        assert!(err.contains("recovery id"), "v={v}: {err}");
    }
}

#[test]
fn wrong_message_fails() {
    let digest = order::tip191_digest("different message");
    let sig = hex_decode(SIG_CN, Some(65)).unwrap();
    let vk = order::recover_pubkey(&digest, &sig).unwrap();
    assert_ne!(addr::point_to_address(vk.as_affine()), ADDR);
}

#[test]
fn rejects_malformed_signature() {
    let digest = order::tip191_digest(MSG_CN);
    assert!(order::recover_pubkey(&digest, &[0u8; 64]).is_err());
    assert!(order::recover_pubkey(&digest, &[0u8; 66]).is_err());
}

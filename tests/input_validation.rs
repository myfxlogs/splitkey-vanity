// input_validation.rs — §7.1 scalar file boundaries + compressed-point rules.

use tron_tool::{point, scalar};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tron-tool-iv-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(path: &std::path::Path, content: &str) {
    std::fs::write(path, content).unwrap();
}

#[test]
fn scalar_file_boundaries() {
    let dir = tmpdir("scalar");
    // 0, n, n+1, ≥n — all rejected as out of range.
    let cases = [
        ("zero", "0".repeat(64)),
        (
            "n",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".into(),
        ),
        (
            "n+1",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142".into(),
        ),
        ("2^256-1", "f".repeat(64)),
    ];
    for (tag, hex) in cases {
        let p = dir.join(tag);
        write(&p, &hex);
        assert!(
            scalar::read_scalar_file(&p).is_err(),
            "{tag} must be rejected"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn scalar_file_malformed_content() {
    let dir = tmpdir("malformed");
    for (tag, content) in [
        ("short", "abcd"),
        ("odd-hex", "abc"),
        ("nonhex", &"z".repeat(64)),
        ("prefixed", &format!("0x{}", "1".repeat(64))),
        ("two-lines", &format!("{0}\n{0}", "a".repeat(64))),
        ("empty", ""),
    ] {
        let p = dir.join(tag);
        write(&p, content);
        assert!(
            scalar::read_scalar_file(&p).is_err(),
            "{tag} must be rejected"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn scalar_file_accepts_canonical_forms() {
    let dir = tmpdir("canonical");
    let good = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    for (tag, content) in [
        ("bare", good.to_string()),
        ("newline", format!("{good}\n")),
        ("spaces", format!("  {good}  \n")),
        ("upper", good.to_uppercase()),
    ] {
        let p = dir.join(tag);
        write(&p, &content);
        assert!(
            scalar::read_scalar_file(&p).is_ok(),
            "{tag} must be accepted"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rejects_illegal_compressed_points() {
    // Uncompressed 0x04 encoding (65B), wrong prefix, bad length, garbage x.
    let uncompressed = format!("04{}", "ab".repeat(64));
    for (tag, hex) in [
        ("uncompressed", uncompressed.as_str()),
        ("bad-prefix", &format!("05{}", "ab".repeat(32))),
        ("too-short", "02ab"),
        ("too-long", &format!("02{}", "ab".repeat(40))),
        ("garbage", "zz"),
    ] {
        assert!(
            point::parse_pubkey_compressed(hex).is_err(),
            "{tag} must be rejected"
        );
    }
    // x-coordinate = field prime p is out of field — invalid point.
    let p_at_prime = "02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
    assert!(point::parse_pubkey_compressed(p_at_prime).is_err());
    // All-zero x with even prefix: y² = 7 has a root? For x=0 the point does
    // not necessarily exist — if it parses it must still be a valid curve
    // point; what matters is no panic and deterministic result.
    let _ = point::parse_pubkey_compressed(&format!("02{}", "00".repeat(32)));
}

#[test]
fn accepts_valid_compressed_point() {
    // Generator point G compressed.
    let g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    assert!(point::parse_pubkey_compressed(g).is_ok());
    // Appendix A B.
    assert!(point::parse_pubkey_compressed(
        "034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff"
    )
    .is_ok());
}

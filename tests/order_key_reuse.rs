// order_key_reuse.rs — N-05 / spec §3.3: a buyer key is single-use.
//
// Reusing B across two orders links the resulting private keys by the
// public delta priv₂ − priv₁ = d₂ − d₁: anyone who learns both offsets
// derives every key in the set from any one. `tron-tool order` must
// refuse to mint a second .tronorder with a key that already fronted
// one in the same directory; the seller-side rejection is the backstop
// for order files kept elsewhere.

use std::path::PathBuf;
use std::process::Command;

fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tron-tool-kr-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tron-tool"))
        .args(args)
        .output()
        .expect("spawn failed")
}

#[test]
fn second_order_with_same_key_refused() {
    let dir = tmpdir("reuse");
    let key = dir.join("b.key");
    let o1 = dir.join("first.tronorder");
    let o2 = dir.join("second.tronorder");
    std::fs::write(&key, format!("{}\n", "07".repeat(32))).unwrap();

    let first = run(&[
        "order",
        "-k",
        key.to_str().unwrap(),
        "-p",
        "repeat:4",
        "-o",
        o1.to_str().unwrap(),
    ]);
    assert!(
        first.status.success(),
        "first order failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(o1.exists());

    let second = run(&[
        "order",
        "-k",
        key.to_str().unwrap(),
        "-p",
        "repeat:5",
        "-o",
        o2.to_str().unwrap(),
    ]);
    assert!(!second.status.success(), "second order must be refused");
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("single-use") || stderr.contains("already used"),
        "got: {stderr}"
    );
    assert!(!o2.exists(), "refused order must not be written");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn b_hex_normalizes_to_lowercase() {
    // §3 hex rules: parsers normalize before validation. A mixed-case B
    // in the order text must land in `b_hex` as canonical lowercase —
    // case-variant strings must not evade B-equality checks downstream.
    let order_text = "TRONSPK-ORDER-v1|repeat:8|034646AE5047316B4230D0086C8ACEC687F00B1CD9D1DC634F6CB358AC0A9A8FFF";
    let sig = "420e3ce12529e139633692048f9419bb720ee1af59e3c5b0a8e9e7e62cd9c06e6928f5772a65749c4c31f268bae62ffafdad7baab71fd6676c5de8ba2c9148641c";
    // Signature was made over the lowercase form — a case-tweaked order
    // text won't verify, but structural parse + normalization still hold.
    let of =
        tron_tool::order::parse_order_file(format!("{order_text}\n0x{sig}\n").as_bytes()).unwrap();
    assert_eq!(
        of.b_hex,
        "034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff"
    );
}

#[test]
fn same_key_in_other_dir_not_detected_locally() {
    // The local scan sees only sibling .tronorder files — a key reused
    // across directories slips past the buyer-side guard (the seller's
    // orders_for_b check is the authoritative rejection).
    let dir_a = tmpdir("reuse-a");
    let dir_b = tmpdir("reuse-b");
    let key_a = dir_a.join("b.key");
    let key_b = dir_b.join("b.key");
    let key_hex = format!("{}\n", "08".repeat(32));
    std::fs::write(&key_a, &key_hex).unwrap();
    std::fs::write(&key_b, &key_hex).unwrap();

    let o1 = dir_a.join("a.tronorder");
    let o2 = dir_b.join("b.tronorder");
    assert!(run(&[
        "order",
        "-k",
        key_a.to_str().unwrap(),
        "-p",
        "repeat:4",
        "-o",
        o1.to_str().unwrap()
    ])
    .status
    .success());
    assert!(
        run(&[
            "order",
            "-k",
            key_b.to_str().unwrap(),
            "-p",
            "repeat:4",
            "-o",
            o2.to_str().unwrap()
        ])
        .status
        .success(),
        "cross-directory reuse is the seller-side guard's job"
    );
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}

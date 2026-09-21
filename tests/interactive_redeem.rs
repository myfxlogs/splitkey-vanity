// interactive_redeem.rs — A-02 regression: in guided redeem, --expect-pattern
// must come from the buyer's own order record, never default to the
// seller-signed package field (spec §4).
//
//   * the .tronorder auto-match keys on B ALONE — a degraded package
//     (delivered pattern weaker than ordered) still finds the order, warns,
//     and verifies against the ORDER's pattern;
//   * with no matching order the expect-pattern prompt has no default —
//     empty input is rejected, not silently the package's own field.
//
// Binary-level: spawns `tron-tool` with piped stdin inside a fixture cwd.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tron-tool-a02-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Embedded dev signer (key_id 1) — secret lives outside the repo at
/// ~/tron-dev-keys/ (same convention as vend's api.rs tests); absent → skip.
fn dev_key() -> Option<ed25519_dalek::SigningKey> {
    let home = std::env::var("HOME").ok()?;
    let bytes = tron_tool::scalar::read_scalar_file(
        &std::path::Path::new(&home).join("tron-dev-keys/ed25519-dev.key"),
    )
    .ok()?;
    Some(ed25519_dalek::SigningKey::from_bytes(&bytes))
}

/// Write b-x.key + pkg.tronspk (dev-signed, arbitrary d) into `dir`.
fn fixtures(dir: &Path, pkg_pattern: &str) -> (zeroize::Zeroizing<[u8; 32]>, String) {
    let b = tron_tool::scalar::generate_scalar();
    tron_tool::scalar::write_scalar_file(&dir.join("b-x.key"), &b).unwrap();
    let b_pub = tron_tool::point::pubkey_from_secret(&b).unwrap();
    let b_hex = tron_tool::point::pubkey_compressed_hex(&b_pub);
    let b33: [u8; 33] = tron_tool::hex_decode(&b_hex, Some(33))
        .unwrap()
        .try_into()
        .unwrap();
    let pkg = tron_tool::package::build_and_sign(
        1,
        pkg_pattern,
        &b33,
        &[1u8; 32],
        1_789_000_000,
        &dev_key().unwrap(),
    );
    std::fs::write(dir.join("pkg.tronspk"), pkg).unwrap();
    (b, b_hex)
}

fn write_order(dir: &Path, pattern: &str, b: &[u8; 32], b_hex: &str) {
    let text = tron_tool::order::build_order_text(pattern, b_hex);
    let sig = tron_tool::order::sign_digest(&tron_tool::order::order_digest(&text), b).unwrap();
    std::fs::write(
        dir.join("order.tronorder"),
        format!("{text}\n0x{}\n", tron_tool::hex_encode(&*sig)),
    )
    .unwrap();
}

fn run_menu(dir: &Path, stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tron-tool"))
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tron-tool");
    if let Some(mut s) = child.stdin.take() {
        let _ = s.write_all(stdin.as_bytes());
    }
    child.wait_with_output().unwrap()
}

/// Downgrade path: ordered repeat:6, delivered repeat:4. Pre-fix the order
/// was filtered out (pattern mismatch) and Enter accepted the package's own
/// field; now the order is found by B and its pattern drives verification.
#[test]
fn degraded_package_verified_against_order() {
    if dev_key().is_none() {
        eprintln!("dev signing key absent — skipping");
        return;
    }
    let dir = tmpdir("downgrade");
    let (b, b_hex) = fixtures(&dir, "repeat:4");
    write_order(&dir, "repeat:6", &b, &b_hex);

    // lang=EN → redeem → pkg/key/order auto-picked → export N → QR skip.
    let out = run_menu(&dir, "1\n3\nN\n0\n");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("differs from your order"),
        "downgrade must surface the mismatch warning, got:\n{err}"
    );
    assert!(
        err.contains("ordered=repeat:6 delivered=repeat:4"),
        "got:\n{err}"
    );
    // Verification ran against the ORDER's repeat:6 — the derived address
    // can't satisfy it → "order mismatch" (not a silent accept).
    assert!(err.contains("order mismatch"), "got:\n{err}");
    std::fs::remove_dir_all(&dir).ok();
}

/// No matching order: the expect-pattern prompt must not default to the
/// package field — empty input is rejected and re-prompted.
#[test]
fn no_order_empty_expect_rejected() {
    if dev_key().is_none() {
        eprintln!("dev signing key absent — skipping");
        return;
    }
    let dir = tmpdir("noorder");
    fixtures(&dir, "repeat:4");

    // Empty line at expect-pattern → refused; then manual "repeat:4".
    let out = run_menu(&dir, "1\n3\n\nrepeat:4\nN\n0\n");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("never the default"),
        "empty expect-pattern must be rejected, got:\n{err}"
    );
    // The manual entry then drove verification — the random address fails
    // the typed pattern at the order check, proving it was used.
    assert!(err.contains("order mismatch"), "got:\n{err}");
    std::fs::remove_dir_all(&dir).ok();
}

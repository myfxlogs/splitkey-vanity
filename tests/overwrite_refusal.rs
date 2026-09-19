// overwrite_refusal.rs — F1 rework: every output path refuses to overwrite.
//
// Library level: write_secret_file / write_scalar_file / qr::render.
// Binary level: tron-tool keygen|order, pkg-sign-dev genkey|sign — each must
// exit non-zero with the unified "{path} exists — refusing to overwrite"
// message and leave the pre-existing file byte-identical.

use std::path::{Path, PathBuf};
use std::process::Command;

fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tron-tool-ow-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn preexisting(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, b"sentinel\n").unwrap();
    p
}

fn assert_untouched(path: &Path) {
    assert_eq!(
        std::fs::read(path).unwrap(),
        b"sentinel\n",
        "refused write must not alter the existing file"
    );
}

fn run(bin: &str, args: &[&str]) -> std::process::Output {
    Command::new(bin).args(args).output().expect("spawn failed")
}

#[test]
fn write_secret_file_refuses_existing() {
    let dir = tmpdir("wsf");
    let p = preexisting(&dir, "out.bin");
    let err = tron_tool::write_secret_file(&p, b"new").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(err.to_string().contains("refusing to overwrite"));
    assert_untouched(&p);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn write_scalar_file_refuses_existing() {
    let dir = tmpdir("wsc");
    let p = preexisting(&dir, "b.key");
    let scalar = [7u8; 32];
    let err = tron_tool::scalar::write_scalar_file(&p, &scalar).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_untouched(&p);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn qr_image_output_refuses_existing() {
    let dir = tmpdir("qr");
    let p = preexisting(&dir, "qr.png");
    let payload = "ab".repeat(32);
    let err = tron_tool::qr::render(&payload, Some(&p), 0).unwrap_err();
    assert!(err.contains("refusing to overwrite"), "got: {err}");
    assert_untouched(&p);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn keygen_refuses_existing() {
    let dir = tmpdir("keygen");
    let p = preexisting(&dir, "b.key");
    let out = run(
        env!("CARGO_BIN_EXE_tron-tool"),
        &["keygen", "-o", p.to_str().unwrap()],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refusing to overwrite"), "got: {stderr}");
    assert_untouched(&p);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn order_refuses_existing() {
    let dir = tmpdir("order");
    let p = preexisting(&dir, "o.tronorder");
    // Exists-check fires before the key is even read — any args suffice.
    let out = run(
        env!("CARGO_BIN_EXE_tron-tool"),
        &[
            "order",
            "--key",
            "/nonexistent-b",
            "--pattern",
            "repeat:4",
            "-o",
            p.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refusing to overwrite"), "got: {stderr}");
    assert_untouched(&p);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn pkg_sign_dev_refuses_existing() {
    let dir = tmpdir("pkgsign");
    let key_out = preexisting(&dir, "ed.key");
    let out = run(
        env!("CARGO_BIN_EXE_pkg-sign-dev"),
        &["genkey", "-o", key_out.to_str().unwrap()],
    );
    assert!(!out.status.success());
    assert_untouched(&key_out);

    let pkg_out = preexisting(&dir, "pkg.bin");
    let out = run(
        env!("CARGO_BIN_EXE_pkg-sign-dev"),
        &[
            "sign",
            "--key",
            "/nonexistent-ed",
            "--pattern",
            "repeat:4",
            "--b",
            "00",
            "--d",
            "00",
            "-o",
            pkg_out.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refusing to overwrite"), "got: {stderr}");
    assert_untouched(&pkg_out);
    std::fs::remove_dir_all(&dir).ok();
}

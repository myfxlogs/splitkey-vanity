// lib.rs — tron-tool shared modules
//
// Buyer-side tool for the split-key vanity protocol (spec/split-key.md).
// The seller only ever sees the buyer's public key B and returns an offset
// scalar d; the final private key priv = (b + d) mod n is computed locally
// and never leaves this machine.

pub mod addr;
pub mod devkey;
pub mod order;
pub mod package;
pub mod pattern;
pub mod point;
pub mod qr;
pub mod redeem;
pub mod scalar;

use std::io;
use std::path::Path;

/// Fill `buf` with cryptographically secure random bytes via `getrandom`.
/// CSPRNG failure aborts — there is no safe fallback.
pub fn fill_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("getrandom failed: CSPRNG unavailable");
}

/// Open `path` for writing with secure permissions: Unix 0600, default elsewhere.
pub fn secure_open_write(path: &Path) -> io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Write `data` to `path` with 0600 permissions (all secret/secret-adjacent
/// output goes through this). Refuses to overwrite an existing path — no
/// tool output may silently clobber a file (F1 rework).
pub fn write_secret_file(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists — refusing to overwrite", path.display()),
        ));
    }
    let mut f = secure_open_write(path)?;
    f.write_all(data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Covers the pre-existing-file case where OpenOptions .mode() is a no-op.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Lowercase hex encode (canonical hex form per split-key.md §3).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Hex decode with §3 rules: trim whitespace, accept either case.
/// `want_len` is the required byte count (None = any even length).
pub fn hex_decode(s: &str, want_len: Option<usize>) -> Result<Vec<u8>, String> {
    let t = s.trim();
    if !t.len().is_multiple_of(2) {
        return Err(format!("hex: odd length {}", t.len()));
    }
    if let Some(n) = want_len {
        if t.len() != n * 2 {
            return Err(format!("hex: expected {} chars, got {}", n * 2, t.len()));
        }
    }
    (0..t.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&t[i..i + 2], 16).map_err(|_| format!("hex: invalid byte at {i}"))
        })
        .collect()
}

/// Strip an optional `0x`/`0X` prefix (input convenience only; emitters never
/// produce it except where a spec requires the `0x` sig field).
pub fn strip_0x(s: &str) -> &str {
    let t = s.trim();
    t.strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t)
}

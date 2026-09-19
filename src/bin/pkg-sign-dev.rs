// pkg-sign-dev — DEV-ONLY TRONSPK1 package signer (not for README/public docs).
//
// Used during construction to produce test vectors and test packages, and at
// P4 for end-to-end bring-up. The production pkg-signer ships in the private
// `vanity` repo; this one exists so tron-tool can generate packages without
// sharing code with the seller side.
//
// Subcommands:
//   genkey -o <file>   generate an Ed25519 key file (§7.1 64-hex, 0600) + print pubkey
//   sign               build + sign a package with issuer self-check (§5)

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use tron_tool::{addr, package, pattern::Pattern, point, scalar};

#[derive(Parser)]
#[command(name = "pkg-sign-dev", about = "DEV-ONLY TRONSPK1 package signer")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an Ed25519 signing key file (64-hex, 0600); prints the pubkey.
    Genkey {
        #[arg(short = 'o', long)]
        out: PathBuf,
    },
    /// Build + sign a TRONSPK1 package (issuer self-check enforced, §5).
    Sign {
        /// Ed25519 secret key file (§7.1 64-hex format).
        #[arg(long)]
        key: PathBuf,
        /// signer_key_id embedded in the package (must match the key).
        #[arg(long, default_value_t = 1)]
        key_id: u32,
        /// Order pattern, e.g. 'repeat:8' (canonicalized before embedding).
        #[arg(long)]
        pattern: String,
        /// Buyer's compressed public key B (66 hex).
        #[arg(long)]
        b: String,
        /// Offset scalar d (64 hex).
        #[arg(long)]
        d: String,
        /// Unix seconds timestamp (default: now).
        #[arg(long)]
        timestamp: Option<u64>,
        /// Output package file.
        #[arg(short = 'o', long)]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Command::Genkey { out } => genkey(&out),
        Command::Sign {
            key,
            key_id,
            pattern,
            b,
            d,
            timestamp,
            out,
        } => sign(&key, key_id, &pattern, &b, &d, timestamp, &out),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn genkey(out: &Path) -> Result<(), String> {
    let mut sk_bytes = [0u8; 32];
    tron_tool::fill_random(&mut sk_bytes);
    let sk = SigningKey::from_bytes(&sk_bytes);
    scalar::write_scalar_file(out, &sk_bytes)
        .map_err(|e| format!("write {}: {e}", out.display()))?;
    println!("{}", tron_tool::hex_encode(&sk.verifying_key().to_bytes()));
    eprintln!(
        "wrote Ed25519 secret key to {} (mode 0600) — never commit it",
        out.display()
    );
    Ok(())
}

fn sign(
    key: &Path,
    key_id: u32,
    pattern: &str,
    b_hex: &str,
    d_hex: &str,
    timestamp: Option<u64>,
    out: &Path,
) -> Result<(), String> {
    let sk_bytes = scalar::read_scalar_file(key)?;
    let signing_key = SigningKey::from_bytes(&sk_bytes);

    let pat = Pattern::parse(pattern)?;
    let canonical = pat.canonical();
    let b_point = point::parse_pubkey_compressed(b_hex)?;
    let d: [u8; 32] = tron_tool::hex_decode(tron_tool::strip_0x(d_hex), Some(32))
        .map_err(|e| format!("invalid d: {e}"))?
        .try_into()
        .unwrap();

    // Issuer self-check (package-format.md §5): 1 ≤ d < n AND
    // addr(B + d·G) satisfies the order's pattern — a signed package MUST
    // be valid on its own terms.
    let q = point::add_offset(&b_point, &d)?;
    let q_addr = addr::point_to_address(&q);
    if !pat.matches(&q_addr) {
        return Err(format!(
            "issuer self-check failed: addr(B + d·G) = {q_addr} does not satisfy {canonical}"
        ));
    }

    let mut b_bytes = [0u8; 33];
    b_bytes.copy_from_slice(b_point.to_encoded_point(true).as_bytes());
    let ts = timestamp.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });
    let pkg = package::build_and_sign(key_id, &canonical, &b_bytes, &d, ts, &signing_key);
    std::fs::write(out, &pkg).map_err(|e| format!("write {}: {e}", out.display()))?;
    eprintln!(
        "wrote {} ({} bytes, key_id 0x{key_id:08x}, {canonical}, addr {q_addr})",
        out.display(),
        pkg.len()
    );
    Ok(())
}

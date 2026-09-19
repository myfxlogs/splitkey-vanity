// tron-tool — buyer-side tool for split-key TRON vanity addresses.
//
// Five commands, three functions:
//   keygen / order — custom order flow (b stays local, seller sees only B)
//   redeem         — accept a signed TRONSPK1 delivery package
//   sign / verify  — TIP-191 merchant statements

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tron_tool::{addr, order, package, pattern::Pattern, point, qr, redeem, scalar};

#[derive(Parser)]
#[command(
    name = "tron-tool",
    about = "Buyer-side tool for split-key TRON vanity addresses"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate (b, B): b written to a 0600 file, B printed for the order.
    Keygen {
        /// Output file for the secret scalar b (required — b is never printed).
        #[arg(short = 'o', long)]
        out: PathBuf,
    },
    /// Sign an order commitment with b → .tronorder file + fingerprint H.
    Order {
        /// Secret scalar file (§7.1 format).
        #[arg(long)]
        key: PathBuf,
        /// Order pattern, e.g. 'repeat:8'.
        #[arg(long)]
        pattern: String,
        /// Output .tronorder file.
        #[arg(short = 'o', long)]
        out: PathBuf,
    },
    /// Redeem a signed delivery package: verify → binding → order → consistency.
    Redeem {
        /// TRONSPK1 package file.
        #[arg(long)]
        package: PathBuf,
        /// Secret scalar file (§7.1 format) — the same b used for the order.
        #[arg(long)]
        key: PathBuf,
        /// The pattern from YOUR local order record, e.g. 'repeat:8' (required).
        #[arg(long)]
        expect_pattern: String,
        /// Export priv = (b + d) mod n to a §7.1 file (0600) for sign/wallet use.
        #[arg(long)]
        export_priv: Option<PathBuf>,
        /// Self-destruct countdown seconds for QR output (0 = keep).
        #[arg(long, default_value_t = 60)]
        timeout: u64,
        /// QR output image (.svg → SVG, otherwise PNG), mode 0600.
        /// Omit to render in the terminal.
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
    },
    /// TIP-191 sign a message (merchant receive-address statement).
    Sign {
        /// Secret scalar file (§7.1 format).
        #[arg(long)]
        key: PathBuf,
        /// Statement text (UTF-8; byte length feeds the digest, not chars).
        #[arg(long)]
        message: String,
    },
    /// Verify a TIP-191 signature against a claimed address.
    Verify {
        /// Claimed TRON address (T...).
        #[arg(long)]
        address: String,
        /// Statement text that was signed.
        #[arg(long)]
        message: String,
        /// Signature hex (0x-prefixed or bare, 130 hex chars).
        #[arg(long)]
        signature: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Command::Keygen { out } => cmd_keygen(&out).map(|_| true),
        Command::Order { key, pattern, out } => cmd_order(&key, &pattern, &out).map(|_| true),
        Command::Redeem {
            package,
            key,
            expect_pattern,
            export_priv,
            timeout,
            out,
        } => cmd_redeem(&package, &key, &expect_pattern, export_priv, timeout, out).map(|_| true),
        Command::Sign { key, message } => cmd_sign(&key, &message).map(|_| true),
        Command::Verify {
            address,
            message,
            signature,
        } => cmd_verify(&address, &message, &signature),
    };
    match r {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_keygen(out: &std::path::Path) -> Result<(), String> {
    let b = scalar::generate_scalar(); // CSPRNG rejection sampling (§3)
    let b_point = point::pubkey_from_secret(&b)?;
    scalar::write_scalar_file(out, &b).map_err(|e| format!("write {}: {e}", out.display()))?;
    println!("{}", point::pubkey_compressed_hex(&b_point));
    eprintln!(
        "wrote b to {} (mode 0600) — back it up now: losing b forfeits the order\n\
         备份 b 文件：丢失 = 订单全损，卖家也无法恢复",
        out.display()
    );
    Ok(())
}

fn cmd_order(key: &std::path::Path, pattern: &str, out: &std::path::Path) -> Result<(), String> {
    let pat = Pattern::parse(pattern)?;
    if pat.needs_reachability_warning() {
        eprintln!(
            "warning: repeat:{n} is effectively undeliverable — no such addresses are \
             known to exist for n ≥ 29 (§3.1 reachability)",
            n = match pat {
                Pattern::Repeat(n) => n,
            }
        );
    }
    let b = scalar::read_scalar_file(key)?;
    let b_point = point::pubkey_from_secret(&b)?;
    let order_text =
        order::build_order_text(&pat.canonical(), &point::pubkey_compressed_hex(&b_point));

    let digest = order::order_digest(&order_text);
    let sig = order::sign_digest(&digest, &b)?;

    // .tronorder: two LF-separated lines — order text / 0x+130-hex sig (§8).
    let content = format!("{order_text}\n0x{}\n", tron_tool::hex_encode(&*sig));
    std::fs::write(out, &content).map_err(|e| format!("write {}: {e}", out.display()))?;

    // H = keccak256(order) — verify the escrow binds payment to this fingerprint.
    println!(
        "order fingerprint H = {}",
        tron_tool::hex_encode(&order::order_fingerprint(&order_text))
    );
    eprintln!("wrote {}", out.display());
    Ok(())
}

fn cmd_redeem(
    package_path: &std::path::Path,
    key: &std::path::Path,
    expect_pattern: &str,
    export_priv: Option<PathBuf>,
    timeout: u64,
    out: Option<PathBuf>,
) -> Result<(), String> {
    let expect = Pattern::parse(expect_pattern)?;
    let data = std::fs::read(package_path)
        .map_err(|e| format!("cannot read {}: {e}", package_path.display()))?;
    let pkg = package::parse(&data)?; // signature verified before anything else
    let b = scalar::read_scalar_file(key)?;

    // §4 chain: binding → order → self-consistency (distinct errors, verbatim).
    let result = redeem::verify_delivery(&pkg, &b, &expect).map_err(|e| e.to_string())?;
    if result.pattern_field_differs {
        eprintln!(
            "warning: package pattern field '{}' differs from ordered '{}' — \
             acceptance is by your order terms, not the package field",
            pkg.pattern, expect
        );
    }

    println!("{}", result.address);

    if let Some(path) = export_priv {
        scalar::write_scalar_file(&path, &result.priv_key)
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        eprintln!(
            "exported priv to {} (mode 0600) — a priv file looks identical to a b file; \
             keep them in clearly named separate files",
            path.display()
        );
    }

    let priv_hex = zeroize::Zeroizing::new(tron_tool::hex_encode(&*result.priv_key));
    qr::render(&priv_hex, out.as_deref(), timeout)
}

fn cmd_sign(key: &std::path::Path, message: &str) -> Result<(), String> {
    let priv_key = scalar::read_scalar_file(key)?;
    // §2.1: a b file and a priv file are byte-indistinguishable — always show
    // which address is signing before emitting the signature.
    eprintln!("signing as {}", addr::privkey_to_address(&priv_key)?);
    let digest = order::tip191_digest(message);
    let sig = order::sign_digest(&digest, &priv_key)?;
    println!("0x{}", tron_tool::hex_encode(&*sig));
    Ok(())
}

fn cmd_verify(address: &str, message: &str, signature: &str) -> Result<bool, String> {
    let sig = tron_tool::hex_decode(tron_tool::strip_0x(signature), Some(65))
        .map_err(|e| format!("invalid signature encoding: {e}"))?;
    let digest = order::tip191_digest(message);
    let recovered = order::recover_pubkey(&digest, &sig)?;
    let recovered_addr = addr::point_to_address(recovered.as_affine());
    println!("recovered: {recovered_addr}");
    let matched = recovered_addr == address.trim();
    println!("{matched}");
    Ok(matched)
}

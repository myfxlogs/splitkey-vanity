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
    version,
    about = "Buyer-side tool for split-key TRON vanity addresses"
)]
struct Cli {
    /// Omit the subcommand for the guided interactive menu / 交互菜单.
    #[command(subcommand)]
    cmd: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Generate (b, B): b written to a 0600 file, B printed for the order.
    Keygen {
        /// Output file for the secret scalar b (required — b is never printed).
        #[arg(short = 'o', long)]
        out: PathBuf,
        /// Refuse to run when a network route is detected. Best-effort
        /// self-check only — it cannot prove a machine is offline.
        #[arg(long)]
        require_offline: bool,
    },
    /// Sign an order commitment with b → .tronorder file + fingerprint H.
    Order {
        /// Secret scalar file (§7.1 format).
        #[arg(short = 'k', long)]
        key: PathBuf,
        /// Order pattern, e.g. 'repeat:8'.
        #[arg(short = 'p', long)]
        pattern: String,
        /// Output .tronorder file.
        #[arg(short = 'o', long)]
        out: PathBuf,
    },
    /// Redeem a signed delivery package: verify → binding → order → consistency.
    Redeem {
        /// TRONSPK1 package file.
        #[arg(short = 'p', long)]
        package: PathBuf,
        /// Secret scalar file (§7.1 format) — the same b used for the order.
        #[arg(short = 'k', long)]
        key: PathBuf,
        /// The pattern from YOUR local order record, e.g. 'repeat:8' (required).
        #[arg(short = 'e', long)]
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
        #[arg(short = 'k', long)]
        key: PathBuf,
        /// Statement text (UTF-8; byte length feeds the digest, not chars).
        #[arg(short = 'm', long)]
        message: String,
    },
    /// Verify a TIP-191 signature against a claimed address.
    Verify {
        /// Claimed TRON address (T...).
        #[arg(short = 'a', long)]
        address: String,
        /// Statement text that was signed.
        #[arg(short = 'm', long)]
        message: String,
        /// Signature hex (0x-prefixed or bare, 130 hex chars).
        #[arg(short = 's', long)]
        signature: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let r = match cli.cmd {
        None => interactive(),
        Some(Command::Keygen {
            out,
            require_offline,
        }) => cmd_keygen(&out, require_offline).map(|_| true),
        Some(Command::Order { key, pattern, out }) => cmd_order(&key, &pattern, &out).map(|_| true),
        Some(Command::Redeem {
            package,
            key,
            expect_pattern,
            export_priv,
            timeout,
            out,
        }) => cmd_redeem(&package, &key, &expect_pattern, export_priv, timeout, out).map(|_| true),
        Some(Command::Sign { key, message }) => cmd_sign(&key, &message).map(|_| true),
        Some(Command::Verify {
            address,
            message,
            signature,
        }) => cmd_verify(&address, &message, &signature),
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

/// Best-effort "a default route exists" probe: UDP connect() consults the
/// routing table only — no packets are sent. This CANNOT prove a machine
/// is offline (hotspots, VM bridges, hidden interfaces, or a compromised
/// host all evade it); it is a self-discipline check, not a security claim.
fn network_route_detected() -> bool {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("8.8.8.8:53"))
        .is_ok()
}

/// Read one line from stdin; empty input falls back to `default`.
/// Prompts go to stderr so stdout stays clean for pipeable output.
fn prompt(label: &str, default: &str) -> Result<String, String> {
    use std::io::Write;
    if default.is_empty() {
        eprint!("{label}: ");
    } else {
        eprint!("{label} [{default}]: ");
    }
    std::io::stderr().flush().map_err(|e| e.to_string())?;
    let mut s = String::new();
    if std::io::stdin()
        .read_line(&mut s)
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("EOF on stdin — use subcommand arguments for non-interactive use".into());
    }
    let s = s.trim();
    Ok(if s.is_empty() {
        default.to_string()
    } else {
        s.to_string()
    })
}

fn prompt_path(label: &str, default: &str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(prompt(label, default)?))
}

fn prompt_opt(label: &str) -> Result<Option<PathBuf>, String> {
    let s = prompt(label, "")?;
    Ok(if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    })
}

/// Bare `tron-tool` → guided menu covering the full buyer flow.
fn interactive() -> Result<bool, String> {
    eprintln!("tron-tool — split-key vanity buyer tool · 交互模式 interactive");
    eprintln!("  1) keygen  生成买家密钥 b → 0600 文件 + 公钥 B");
    eprintln!("  2) order   签名订单 → .tronorder + 指纹 H");
    eprintln!("  3) redeem  验收交付包 → 导出私钥 + 收款 QR");
    eprintln!("  4) sign    TIP-191 签名声明");
    eprintln!("  5) verify  验证 TIP-191 签名");
    eprintln!("  q) quit    退出");
    match prompt("choose 选择", "1")?.as_str() {
        "1" | "keygen" => {
            let out = prompt_path("b output file 密钥输出文件", "b.key")?;
            let ro = matches!(
                prompt("offline self-check 断网自检 (y/N)", "N")?.as_str(),
                "y" | "Y" | "yes"
            );
            cmd_keygen(&out, ro).map(|_| true)
        }
        "2" | "order" => {
            let key = prompt_path("key file (b) 密钥文件", "b.key")?;
            eprintln!(
                "  patterns: 4 ~ 8 — 尾号重复位数，输数字即可 (e.g. 6)；价格以提交后显示为准"
            );
            let pattern = prompt("pattern", "repeat:6")?;
            let out = prompt_path("order out 订单输出文件", "my.tronorder")?;
            cmd_order(&key, &pattern, &out).map(|_| true)
        }
        "3" | "redeem" => {
            let package = prompt_path("package file 交付包", "pkg.tronspk")?;
            let key = prompt_path("key file (b) 密钥文件", "b.key")?;
            eprintln!("  expect-pattern 必须与你本地订单记录一致 / must match YOUR order record");
            let expect = prompt("expect-pattern", "repeat:6")?;
            let export = prompt_opt("export priv to file 导出私钥 (空=不导出)")?;
            let out = prompt_opt("QR image out 收款QR图片 (空=终端显示)")?;
            cmd_redeem(&package, &key, &expect, export, 60, out).map(|_| true)
        }
        "4" | "sign" => {
            let key = prompt_path("key file (b 或 priv)", "priv.key")?;
            let message = prompt("message 声明文本", "")?;
            cmd_sign(&key, &message).map(|_| true)
        }
        "5" | "verify" => {
            let address = prompt("address 地址", "")?;
            let message = prompt("message 声明文本", "")?;
            let signature = prompt("signature 签名 (0x+130hex)", "")?;
            cmd_verify(&address, &message, &signature)
        }
        _ => Ok(true),
    }
}

fn cmd_keygen(out: &std::path::Path, require_offline: bool) -> Result<(), String> {
    if out.exists() {
        // Overwriting a live b file destroys the order — refuse silently.
        return Err(format!("{} exists — refusing to overwrite", out.display()));
    }
    if require_offline && network_route_detected() {
        return Err(
            "--require-offline: a network route was detected — disconnect networking and retry \
             (best-effort self-check; it cannot prove the machine is offline)\n\
             检测到网络路由，已按 --require-offline 拒绝生成——请断网后重试（自检非安全保证）"
                .into(),
        );
    }
    let b = scalar::generate_scalar(); // CSPRNG rejection sampling (§3)
    let b_point = point::pubkey_from_secret(&b)?;
    scalar::write_scalar_file(out, &b).map_err(|e| format!("write {}: {e}", out.display()))?;
    println!("{}", point::pubkey_compressed_hex(&b_point));
    eprintln!(
        "wrote b to {} (mode 0600) — back it up now: losing b forfeits the order\n\
         备份 b 文件：丢失 = 订单全损，卖家也无法恢复\n\
         For higher assurance generate on an offline / trusted machine \
         (self-check: --require-offline).\n\
         更高保障请在离线/可信机器上生成 b（自检开关 --require-offline）",
        out.display()
    );
    Ok(())
}

fn cmd_order(key: &std::path::Path, pattern: &str, out: &std::path::Path) -> Result<(), String> {
    if out.exists() {
        // The .tronorder record is the local source of --expect-pattern and H.
        return Err(format!("{} exists — refusing to overwrite", out.display()));
    }
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
    if expect.needs_reachability_warning() {
        eprintln!("warning: {expect} is effectively undeliverable (§3.1 reachability, n ≥ 29)");
    }
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

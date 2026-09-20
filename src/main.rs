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
    /// Show what a .tronorder file asks for: pattern, B, H, signature check.
    Inspect {
        /// .tronorder file to inspect.
        #[arg(short = 'f', long)]
        file: PathBuf,
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
        }) => cmd_redeem(
            &package,
            &key,
            &expect_pattern,
            export_priv,
            timeout,
            out,
            true,
        )
        .map(|_| true),
        Some(Command::Sign { key, message }) => cmd_sign(&key, &message).map(|_| true),
        Some(Command::Verify {
            address,
            message,
            signature,
        }) => cmd_verify(&address, &message, &signature),
        Some(Command::Inspect { file }) => cmd_inspect(&file),
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

/// Sorted files in the current directory with the given extension.
fn dir_files(ext: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(".")
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == ext))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Typed filename without extension → try `<name>.<ext>` if the bare name
/// doesn't exist as a file.
fn resolve_ext(p: PathBuf, ext: &str) -> PathBuf {
    if p.exists() || p.extension().is_some() {
        p
    } else {
        p.with_extension(ext)
    }
}

/// Pick one file from a discovered list: 1 entry → auto-selected (announced);
/// several → numbered menu. `allow_empty` lets a blank answer skip (→ None).
fn pick_file(lang: Lang, files: &[PathBuf], allow_empty: bool) -> Result<Option<PathBuf>, String> {
    match files.len() {
        0 => Ok(None),
        1 => {
            eprintln!("  → {}", files[0].display());
            Ok(Some(files[0].clone()))
        }
        _ => loop {
            for (i, f) in files.iter().enumerate() {
                eprintln!("  {}) {}", i + 1, f.display());
            }
            let label = if allow_empty {
                lang.t("选择序号 (空=跳过)", "pick # (empty=skip)")
            } else {
                lang.t("选择序号", "pick #")
            };
            let s = prompt(label, if allow_empty { "" } else { "1" })?;
            if s.is_empty() && allow_empty {
                return Ok(None);
            }
            match s
                .parse::<usize>()
                .ok()
                .filter(|&n| (1..=files.len()).contains(&n))
            {
                Some(n) => return Ok(Some(files[n - 1].clone())),
                None => eprintln!("{}", lang.t("  无效序号", "  invalid number")),
            }
        },
    }
}

/// Session language for the interactive menu — chosen once at launch.
#[derive(Clone, Copy, PartialEq)]
enum Lang {
    Zh,
    En,
}

impl Lang {
    fn t(&self, zh: &'static str, en: &'static str) -> &'static str {
        match self {
            Lang::Zh => zh,
            Lang::En => en,
        }
    }
}

/// File-name stem derived from the chosen customization: canonical pattern
/// minus ':' (Windows-safe). `repeat:6` → `repeat6`; a future `pair2`
/// pattern yields `b-pair2.key`/`pair2.tronorder` for free.
fn pattern_slug(pattern: &Pattern) -> String {
    pattern.canonical().replace(':', "")
}

/// Bare `tron-tool` → guided menu covering the full buyer flow. Language is
/// picked once at launch (1=English, 2=中文), then a sibling menu: new
/// order / keygen / redeem are independent entries — pattern is only asked
/// inside the new-order path, and generated file names derive from it
/// (`b-repeat6.key` / `repeat6.tronorder`). Loops back after each action;
/// a successful step pre-selects the natural next step. 'q' or stdin EOF
/// exits.
fn interactive() -> Result<bool, String> {
    let lang = match prompt("Language 语言 (1=English, 2=中文)", "1") {
        Ok(c) if c == "2" => Lang::Zh,
        Ok(_) => Lang::En,
        Err(e) if e.starts_with("EOF on stdin") => return Ok(false),
        Err(e) => return Err(e),
    };
    let mut suggest = "1";
    let mut did_something = false;
    loop {
        eprintln!("tron-tool — split-key vanity buyer tool");
        for line in [
            lang.t(
                "  1) new order  新订单（生成密钥 b → 选 pattern → 签名 .tronorder）",
                "  1) new order  (generate b → pick pattern → sign .tronorder)",
            ),
            lang.t(
                "  2) keygen     仅生成买家密钥 b → 0600 文件 + 公钥 B",
                "  2) keygen     generate buyer secret b only → 0600 file + pubkey B",
            ),
            lang.t(
                "  3) redeem     验收交付包 → 导出私钥 + 私钥二维码",
                "  3) redeem     accept delivery package → export priv + priv QR",
            ),
            lang.t(
                "  4) sign       TIP-191 签名声明",
                "  4) sign       TIP-191 statement",
            ),
            lang.t(
                "  5) verify     验证 TIP-191 签名",
                "  5) verify     check TIP-191 signature",
            ),
            lang.t(
                "  6) inspect    查看 .tronorder 内容（忘了定制要求看这里）",
                "  6) inspect    view .tronorder (forgot your pattern? look here)",
            ),
            lang.t("  q) quit       退出", "  q) quit       exit"),
        ] {
            eprintln!("{}", line);
        }
        let choice = match prompt(lang.t("choose 选择", "choose"), suggest) {
            Ok(c) => c,
            Err(e) if e.starts_with("EOF on stdin") => return Ok(did_something),
            Err(e) => return Err(e),
        };
        let next = match choice.as_str() {
            "1" | "new" | "order" => {
                // New-order path: pattern determines file names — ask it
                // first (with reachability warning), then keygen, then
                // sign the order.
                let pattern = loop {
                    let p = prompt(
                        lang.t(
                            "定制 pattern（repeat:<n> / pair:<k> / alt:2 / suffix:<s>；尾号重复 4~8 输数字即可）",
                            "pattern (repeat:<n> / pair:<k> / alt:2 / suffix:<s>; bare digit 4~8 = tail repeat)",
                        ),
                        "6",
                    )?;
                    match Pattern::parse(&p) {
                        Ok(pat) => break pat,
                        Err(e) => eprintln!("  {}: {e}", lang.t("无效 pattern", "invalid pattern")),
                    }
                };
                if pattern.needs_reachability_warning() {
                    eprintln!(
                        "{}",
                        lang.t(
                            "  警告：该 pattern 预期搜索量过大，交付可能极慢（§3.1 可达性）",
                            "  warning: this pattern expects a very large search (§3.1 reachability)"
                        )
                    );
                }
                let slug = pattern_slug(&pattern);
                // Closure so a failed step (e.g. key file exists) lands in
                // `next`'s Err branch — printed, menu continues — instead of
                // escaping interactive() via `?`.
                (|| {
                    let key = prompt_path(
                        lang.t("b 密钥输出文件", "b output file"),
                        &format!("b-{slug}.key"),
                    )?;
                    let ro = matches!(
                        prompt(
                            lang.t(
                                "断网自检 offline self-check (y/N)",
                                "offline self-check (y/N)"
                            ),
                            "N"
                        )?
                        .as_str(),
                        "y" | "Y" | "yes"
                    );
                    cmd_keygen(&key, ro)?;
                    let out = prompt_path(
                        lang.t("订单输出文件", "order output file"),
                        &format!("{slug}.tronorder"),
                    )?;
                    cmd_order(&key, &pattern.canonical(), &out).map(|_| "3")
                })()
            }
            "2" | "keygen" => {
                let out = prompt_path(lang.t("b 密钥输出文件", "b output file"), "b.key")?;
                let ro = matches!(
                    prompt(
                        lang.t(
                            "断网自检 offline self-check (y/N)",
                            "offline self-check (y/N)"
                        ),
                        "N"
                    )?
                    .as_str(),
                    "y" | "Y" | "yes"
                );
                cmd_keygen(&out, ro).map(|_| "1")
            }
            "3" | "redeem" => {
                // Auto-discover: scan cwd for .tronspk → parse → its (pattern, B)
                // identify the matching b-*.key (pubkey == pkg.b) and
                // *.tronorder (pattern + B both match) — user just confirms.
                let package = match pick_file(lang, &dir_files("tronspk"), false)? {
                    Some(p) => p,
                    None => resolve_ext(
                        prompt_path(lang.t("交付包文件", "package file"), "pkg.tronspk")?,
                        "tronspk",
                    ),
                };
                let data = std::fs::read(&package)
                    .map_err(|e| format!("cannot read {}: {e}", package.display()))?;
                let pkg = package::parse(&data)?;
                let bhex = tron_tool::hex_encode(&pkg.b);
                let slug = pattern_slug(&Pattern::parse(&pkg.pattern)?);
                eprintln!(
                    "  {}: {} / B={}…",
                    lang.t("交付包", "package"),
                    pkg.pattern,
                    &bhex[..16]
                );

                let keys: Vec<PathBuf> = dir_files("key")
                    .into_iter()
                    .filter(|f| {
                        scalar::read_scalar_file(f)
                            .ok()
                            .and_then(|s| point::pubkey_from_secret(&s).ok())
                            .map(|p| point::pubkey_compressed_hex(&p) == bhex)
                            .unwrap_or(false)
                    })
                    .collect();
                eprintln!(
                    "{}",
                    lang.t("  b 密钥（自动匹配 B）", "  b key (auto-matched to B)")
                );
                let key = match pick_file(lang, &keys, false)? {
                    Some(p) => p,
                    None => {
                        eprintln!(
                            "{}",
                            lang.t(
                                "  目录下没有匹配该交付包的 b 文件 — 请手动指定",
                                "  no b file in cwd matches this package — enter manually"
                            )
                        );
                        resolve_ext(
                            prompt_path(
                                lang.t("密钥文件 (b)", "key file (b)"),
                                &format!("b-{slug}.key"),
                            )?,
                            "key",
                        )
                    }
                };

                let orders: Vec<PathBuf> = dir_files("tronorder")
                    .into_iter()
                    .filter(|f| {
                        std::fs::read(f)
                            .ok()
                            .and_then(|d| order::parse_order_file(&d).ok())
                            .map(|of| of.b_hex == bhex && of.pattern.canonical() == pkg.pattern)
                            .unwrap_or(false)
                    })
                    .collect();
                eprintln!(
                    "{}",
                    lang.t(
                        "  订单文件（自动匹配 pattern+B，空=手动输 expect-pattern）",
                        "  order file (auto-matched on pattern+B, empty=manual)"
                    )
                );
                let order_path = pick_file(lang, &orders, true)?;
                let expect = match order_path {
                    Some(p) => {
                        let of = order::parse_order_file(
                            &std::fs::read(&p)
                                .map_err(|e| format!("cannot read {}: {e}", p.display()))?,
                        )?;
                        of.pattern.canonical()
                    }
                    None => prompt("expect-pattern", &pkg.pattern)?,
                };

                let export = if matches!(
                    prompt(
                        lang.t("导出私钥到文件？(y/N)", "export private key to file? (y/N)"),
                        "N",
                    )?
                    .as_str(),
                    "y" | "Y" | "yes"
                ) {
                    Some(resolve_ext(
                        prompt_path(
                            lang.t("私钥文件名", "priv file name"),
                            &format!("priv-{slug}.key"),
                        )?,
                        "key",
                    ))
                } else {
                    None
                };
                let (show_qr, out) = match prompt(
                    lang.t(
                        "私钥二维码（扫码导入钱包）：1=终端显示 2=存 PNG 0=跳过",
                        "private-key QR (scan to import): 1=terminal 2=save PNG 0=skip",
                    ),
                    "1",
                )?
                .as_str()
                {
                    "0" | "n" | "N" | "no" => (false, None),
                    "2" => (
                        true,
                        Some(resolve_ext(
                            prompt_path(
                                lang.t("QR 图片文件", "QR image file"),
                                &format!("priv-{slug}.png"),
                            )?,
                            "png",
                        )),
                    ),
                    _ => (true, None),
                };
                cmd_redeem(&package, &key, &expect, export, 60, out, show_qr).map(|_| "q")
            }
            "4" | "sign" => {
                let key = prompt_path(
                    lang.t("密钥文件 (b 或 priv)", "key file (b or priv)"),
                    "priv.key",
                )?;
                let message = prompt(lang.t("声明文本 message", "message"), "")?;
                cmd_sign(&key, &message).map(|_| "q")
            }
            "5" | "verify" => {
                let address = prompt(lang.t("地址 address", "address"), "")?;
                let message = prompt(lang.t("声明文本 message", "message"), "")?;
                let signature = prompt(
                    lang.t("签名 signature (0x+130hex)", "signature (0x+130hex)"),
                    "",
                )?;
                cmd_verify(&address, &message, &signature).map(|_| "q")
            }
            "6" | "inspect" => {
                let file = match pick_file(lang, &dir_files("tronorder"), false)? {
                    Some(p) => p,
                    None => resolve_ext(
                        prompt_path(lang.t("订单文件", "order file"), "order.tronorder")?,
                        "tronorder",
                    ),
                };
                cmd_inspect(&file).map(|_| "1")
            }
            "q" | "quit" | "exit" => return Ok(true),
            _ => {
                eprintln!(
                    "{}",
                    lang.t("  无效选择 — 输入 1-6 或 q", "  unknown choice — 1-6 or q")
                );
                continue;
            }
        };
        match next {
            Ok(s) => {
                suggest = s;
                did_something = true;
            }
            Err(e) => eprintln!("error: {e}"),
        }
        eprintln!();
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
            "warning: {} expects a very large search ({:.2e} iterations) — \
             §3.1 reachability; sellers may decline or require confirmation",
            pat.canonical(),
            pat.expected_iterations()
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
    show_qr: bool,
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
    if show_qr {
        qr::render(&priv_hex, out.as_deref(), timeout)
    } else {
        Ok(())
    }
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

fn cmd_inspect(path: &std::path::Path) -> Result<bool, String> {
    let data = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let of = order::parse_order_file(&data)?;
    println!("pattern   : {}", of.pattern.canonical());
    println!("B         : {}", of.b_hex);
    println!(
        "H         : {}",
        tron_tool::hex_encode(&order::order_fingerprint(&of.order_text))
    );
    let ok = order::order_signature_ok(&of);
    println!(
        "signature : {}",
        if ok {
            "OK — recovers to B 签名有效"
        } else {
            "MISMATCH — 签名无效，文件被改或损坏"
        }
    );
    Ok(ok)
}

// qr.rs — secret-material QR rendering, ported from /opt/tron-legacy/qr.
//
// EcLevel::H (30% recovery). Terminal: unicode dense render + optional
// countdown self-destruct (clear screen + scrollback). File: PNG/SVG at
// 0600 + optional countdown overwrite-and-delete. Plaintext and bitmap
// are wiped from memory afterwards.

use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::time::Duration;

use qrcode::{EcLevel, QrCode};
use zeroize::{Zeroize, Zeroizing};

const IMAGE_SIZE: u32 = 480;

/// Render `payload` as a QR code to the terminal (`out == None`) or to a
/// PNG/SVG file at 0600. `timeout` > 0 arms the self-destruct countdown
/// (0 = keep). Returns after the countdown/destroy completes.
pub fn render(payload: &str, out: Option<&Path>, timeout: u64) -> Result<(), String> {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::H)
        .map_err(|e| format!("payload exceeds QR capacity: {e}"))?;

    match out {
        None => {
            let mut s = Zeroizing::new(
                code.render::<qrcode::render::unicode::Dense1x2>()
                    .quiet_zone(true)
                    .build(),
            );
            println!("{}", s.as_str());
            if io::stdout().is_terminal() {
                if timeout > 0 {
                    countdown(timeout, "QR code");
                    // 2J clear screen, 3J clear scrollback, H cursor home.
                    print!("\x1b[2J\x1b[3J\x1b[H");
                    io::stdout().flush().ok();
                    eprintln!("expired — QR code destroyed");
                } else {
                    eprintln!("note: QR stays in terminal scrollback; -o file output is safer");
                }
            }
            s.zeroize();
        }
        Some(path) => {
            write_image(&code, path).map_err(|e| format!("write {}: {e}", path.display()))?;
            if timeout > 0 {
                eprintln!(
                    "written {} (mode 0600) — self-destructs in {timeout}s; \
                     import it now or re-run with --timeout 0 to keep",
                    path.display()
                );
                countdown(timeout, &path.display().to_string());
                destroy_file(path).map_err(|e| format!("destroy {}: {e}", path.display()))?;
                eprintln!("expired — {} destroyed", path.display());
            } else {
                eprintln!(
                    "written {} (mode 0600, --timeout 0 keeps it)",
                    path.display()
                );
            }
        }
    }
    wipe_code(code);
    Ok(())
}

fn countdown(secs: u64, what: &str) {
    for remaining in (1..=secs).rev() {
        eprint!("\r\x1b[2K{what} self-destructs in {remaining:2}s (Ctrl-C to abort)");
        io::stderr().flush().ok();
        std::thread::sleep(Duration::from_secs(1));
    }
    eprint!("\r\x1b[2K");
}

/// Overwrite every QR module with Light, erasing the encoded information.
fn wipe_code(code: QrCode) {
    let mut modules = code.into_colors();
    modules.iter_mut().for_each(|m| *m = qrcode::Color::Light);
}

/// Overwrite with zero bytes, then delete.
fn destroy_file(path: &Path) -> io::Result<()> {
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        io::copy(&mut io::repeat(0).take(len), &mut f).ok();
        f.sync_all().ok();
    }
    std::fs::remove_file(path)
}

fn write_image(code: &QrCode, path: &Path) -> io::Result<()> {
    let mut data = if path.extension().is_some_and(|e| e == "svg") {
        code.render()
            .min_dimensions(IMAGE_SIZE, IMAGE_SIZE)
            .dark_color(qrcode::render::svg::Color("#000000"))
            .light_color(qrcode::render::svg::Color("#ffffff"))
            .build()
            .into_bytes()
    } else {
        let img = code
            .render::<image::Luma<u8>>()
            .min_dimensions(IMAGE_SIZE, IMAGE_SIZE)
            .build();
        let mut buf = io::Cursor::new(Vec::new());
        image::DynamicImage::ImageLuma8(img)
            .write_to(&mut buf, image::ImageFormat::Png)
            .map_err(io::Error::other)?;
        buf.into_inner()
    };
    let r = crate::write_secret_file(path, &data);
    data.zeroize();
    r
}

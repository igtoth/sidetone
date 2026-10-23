// Sidetone desktop: starts the embedded local server (analysis, AI proxy,
// softphone engine) on a random loopback port and opens it in a native window.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use tauri::{LogicalSize, Manager, WebviewUrl, WebviewWindowBuilder};

const FULL: (f64, f64) = (1400.0, 880.0);
const FULL_MIN: (f64, f64) = (900.0, 600.0);
const PHONE_W: f64 = 400.0;
const PHONE_MIN: (f64, f64) = (340.0, 560.0);

/// Remembers the layout so the next start opens in the same size.
fn mode_file() -> Option<std::path::PathBuf> {
    sidetone_cli::phone::config_dir().map(|d| d.join("window-mode"))
}

fn saved_phone_mode() -> bool {
    mode_file()
        .and_then(|f| std::fs::read_to_string(f).ok())
        .is_some_and(|s| s.trim() == "phone")
}

/// Phone height: tall enough for the keypad and lines, but inside the screen.
fn phone_height(w: &tauri::WebviewWindow) -> f64 {
    let screen = w
        .current_monitor()
        .ok()
        .flatten()
        .map(|m| m.size().to_logical::<f64>(m.scale_factor()).height)
        .unwrap_or(1000.0);
    (screen - 90.0).clamp(PHONE_MIN.1, 1000.0)
}

fn apply_mode(w: &tauri::WebviewWindow, phone: bool) {
    let _ = w.set_fullscreen(false);
    let _ = w.unmaximize();
    if phone {
        let _ = w.set_min_size(Some(LogicalSize::new(PHONE_MIN.0, PHONE_MIN.1)));
        let _ = w.set_size(LogicalSize::new(PHONE_W, phone_height(w)));
    } else {
        let _ = w.set_size(LogicalSize::new(FULL.0, FULL.1));
        let _ = w.set_min_size(Some(LogicalSize::new(FULL_MIN.0, FULL_MIN.1)));
        let _ = w.center();
    }
}

fn main() {
    let save: sidetone_cli::serve::SaveHook = Arc::new(|name: &str, data: &[u8]| {
        let path = rfd::FileDialog::new().set_file_name(name).save_file();
        match path {
            Some(p) => {
                std::fs::write(&p, data)?;
                Ok(Some(p))
            }
            None => Ok(None),
        }
    });
    // Native file picker for certificate paths (mutual TLS). Filters nudge the
    // user toward the right file but always allow "All files".
    let _ = sidetone_cli::serve::OPEN_HOOK.set(Box::new(|kind: &str| {
        let dialog = match kind {
            "ca-bundle" => rfd::FileDialog::new()
                .add_filter("CA certificates (PEM)", &["pem", "crt", "cer"])
                .add_filter("All files", &["*"]),
            _ => rfd::FileDialog::new()
                .add_filter("Client certificate (PKCS#12 or PEM)", &["p12", "pfx", "pem", "crt"])
                .add_filter("All files", &["*"]),
        };
        dialog.pick_file()
    }));
    let (url, _server) = sidetone_cli::serve::spawn("127.0.0.1:0", None, true, Some(save))
        .expect("start local server");

    tauri::Builder::default()
        .setup(move |app| {
            let target: tauri::Url = url.parse()?;
            let phone = saved_phone_mode();
            let (size, min) = if phone {
                ((PHONE_W, 1000.0), PHONE_MIN)
            } else {
                (FULL, FULL_MIN)
            };
            let w = WebviewWindowBuilder::new(app, "main", WebviewUrl::External(target))
                .title("Sidetone")
                .inner_size(size.0, size.1)
                .min_inner_size(min.0, min.1)
                .maximized(false)
                .build()?;
            if phone {
                let _ = w.set_size(LogicalSize::new(PHONE_W, phone_height(&w)));
            }
            let handle = app.handle().clone();
            let _ = sidetone_cli::serve::WINDOW_HOOK.set(Box::new(move |mode: &str| {
                let phone = mode == "phone";
                let was = saved_phone_mode();
                if let Some(f) = mode_file() {
                    if let Some(d) = f.parent() {
                        let _ = std::fs::create_dir_all(d);
                    }
                    let _ = std::fs::write(f, if phone { "phone" } else { "full" });
                }
                // The page reports its mode on every load; resize only on a change.
                if phone != was {
                    if let Some(w) = handle.get_webview_window("main") {
                        apply_mode(&w, phone);
                    }
                }
            }));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Sidetone")
        .run(|_app, event| {
            // Hang up and unregister before the process goes away.
            if let tauri::RunEvent::Exit = event {
                sidetone_cli::phone::shutdown();
            }
        });
}

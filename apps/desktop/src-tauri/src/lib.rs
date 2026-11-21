//! VoidWire desktop shell.
//!
//! The app is unprivileged. Everything that touches the network stack is done
//! by the `voidwired` service; this process only speaks VWIPC to it
//! (ARCHITECTURE.md §1, §5), forwards its event stream to the webview,
//! owns the tray icon and the global panic shortcut.

mod bridge;
mod commands;
mod events;
mod service;
mod tray;

use tauri::{Manager, WindowEvent};
use tauri_plugin_global_shortcut::{Code, Modifiers, Shortcut, ShortcutState};

/// CmdOrCtrl+Shift+X → `Panic`.
fn panic_shortcut() -> Shortcut {
    #[cfg(target_os = "macos")]
    let primary = Modifiers::SUPER;
    #[cfg(not(target_os = "macos"))]
    let primary = Modifiers::CONTROL;
    Shortcut::new(Some(primary | Modifiers::SHIFT), Code::KeyX)
}

pub fn run() {
    let panic_key = panic_shortcut();
    let shortcut_plugin = tauri_plugin_global_shortcut::Builder::new()
        .with_handler(move |app, shortcut, event| {
            if shortcut == &panic_key && event.state() == ShortcutState::Pressed {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = events::trigger_panic(&app, "shortcut").await;
                });
            }
        })
        .build();

    tauri::Builder::default()
        .plugin(shortcut_plugin)
        .manage(events::Link::default())
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::up,
            commands::down,
            commands::disarm,
            commands::panic,
            commands::audit,
            commands::optimize,
            commands::get_settings,
            commands::set_settings,
            commands::list_nodes,
            commands::import_node,
            commands::remove_node,
            commands::redeem_invite,
            commands::register_warp,
            commands::telemetry,
            commands::daemon_installed,
            commands::install_service,
            commands::link_status,
            commands::app_info,
        ])
        .setup(move |app| {
            use tauri_plugin_global_shortcut::GlobalShortcutExt;
            // Another app may own the chord; the UI button and tray still work.
            let shortcut_error = app
                .global_shortcut()
                .register(panic_key)
                .err()
                .map(|e| e.to_string());
            app.manage(commands::ShortcutStatus(shortcut_error));
            tray::build(app)?;
            events::spawn(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps the tray (and the panic shortcut)
            // alive; "Quit" in the tray exits.
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to build the VoidWire desktop app")
        .run(|app, event| {
            // macOS: clicking the Dock icon re-opens the hidden window.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = event {
                tray::show_main(app);
            }
            #[cfg(not(target_os = "macos"))]
            let _ = (app, event);
        });
}

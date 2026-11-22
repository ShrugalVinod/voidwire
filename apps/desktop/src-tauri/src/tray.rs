//! System tray: Connect (Auto) / Disconnect / Panic / Show / Quit, with a
//! tooltip that mirrors the Iron Dome state.

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{App, AppHandle, Manager};
use vw_core::config::Profile;
use vw_core::ipc::Request;
use vw_core::state::DomeState;

use crate::bridge;
use crate::events::{self, LinkStatus};

const TRAY_ID: &str = "voidwire-tray";

pub fn state_label(s: DomeState) -> &'static str {
    match s {
        DomeState::Disarmed => "Disarmed",
        DomeState::ArmingBootLock => "Arming",
        DomeState::Handshaking => "Handshaking",
        DomeState::CanaryAuditing => "Canary audit",
        DomeState::TunnelActive => "PROTECTED",
        DomeState::KeyRotating => "Rotating keys",
        DomeState::FailsafeLockdown => "LOCKDOWN",
        DomeState::Disarming => "Disarming",
    }
}

fn tooltip_for(link: &LinkStatus) -> String {
    if !link.connected {
        return "VoidWire: service not reachable".into();
    }
    match link.state {
        Some(s) => format!("VoidWire: {}", state_label(s)),
        None => "VoidWire: connected to service".into(),
    }
}

pub fn set_tooltip(app: &AppHandle, link: &LinkStatus) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_tooltip(Some(tooltip_for(link)));
    }
}

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn run_action(app: &AppHandle, req: Request, ok_msg: &'static str) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        match bridge::call(req).await {
            Ok(_) => events::notice(&app, "info", ok_msg),
            Err(e) => events::notice(&app, "error", e),
        }
    });
}

pub fn build(app: &App) -> tauri::Result<()> {
    let connect = MenuItem::with_id(app, "connect", "Connect (Auto)", true, None::<&str>)?;
    let disconnect = MenuItem::with_id(app, "disconnect", "Disconnect", true, None::<&str>)?;
    let panic = MenuItem::with_id(
        app,
        "panic",
        "Panic: rotate keys & exit",
        true,
        Some("CmdOrCtrl+Shift+X"),
    )?;
    let show = MenuItem::with_id(app, "show", "Show VoidWire", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(
        app,
        &[&connect, &disconnect, &panic, &sep1, &show, &sep2, &quit],
    )?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("VoidWire: starting")
        .menu(&menu)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "connect" => run_action(
                app,
                Request::Up {
                    profile: Profile::Auto,
                    country: None,
                    transport: None,
                    gateway: None,
                },
                "Connect requested (Auto)",
            ),
            "disconnect" => run_action(
                app,
                Request::Down {
                    keep_lockdown: false,
                },
                "Disconnected",
            ),
            "panic" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = events::trigger_panic(&app, "tray").await;
                });
            }
            "show" => show_main(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            // Windows convention: left click opens the window, right click
            // opens the menu. macOS shows the menu on any click.
            if cfg!(not(target_os = "macos")) {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    show_main(tray.app_handle());
                }
            }
        });

    #[cfg(target_os = "macos")]
    {
        let icon = tauri::image::Image::from_bytes(include_bytes!("../icons/tray-template.png"))?;
        builder = builder
            .icon(icon)
            .icon_as_template(true)
            .show_menu_on_left_click(true);
    }
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(icon) = app.default_window_icon() {
            builder = builder.icon(icon.clone());
        }
        builder = builder.show_menu_on_left_click(false);
    }

    builder.build(app)?;
    Ok(())
}

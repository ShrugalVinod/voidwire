//! Pure rendering: `draw(frame, &App)` turns state into widgets.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::canvas::{Canvas, Line as CanvasLine, Map, MapResolution, Points};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Sparkline, Wrap};
use ratatui::Frame;
use vw_core::config::{NodeKind, NodeRole};
use vw_core::ipc::{HopInfo, StatusReport};
use vw_core::state::DomeState;

use crate::app::{App, Focus, Link, RateSeries, Tone};
use crate::format;

/// Neon-on-black palette.
pub mod palette {
    use ratatui::style::Color;

    pub const BG: Color = Color::Rgb(7, 9, 14);
    pub const CYAN: Color = Color::Rgb(0, 240, 255);
    pub const EMERALD: Color = Color::Rgb(16, 185, 129);
    pub const CRIMSON: Color = Color::Rgb(239, 68, 68);
    pub const AMBER: Color = Color::Rgb(245, 166, 35);
    pub const MAGENTA: Color = Color::Rgb(255, 46, 170);
    pub const TEXT: Color = Color::Rgb(205, 214, 224);
    pub const MUTED: Color = Color::Rgb(110, 120, 135);
    pub const CHROME: Color = Color::Rgb(58, 66, 80);
    pub const MAP: Color = Color::Rgb(38, 70, 82);
}

use palette::*;

/// Below this size the world map is collapsed into a one-line route.
pub const MAP_MIN_WIDTH: u16 = 110;
pub const MAP_MIN_HEIGHT: u16 = 34;

/// Fixed, neutral canvas position for the client marker. The user's
/// location is never inferred; the label says so.
pub const YOU_LON: f64 = -160.0;
pub const YOU_LAT: f64 = -52.0;

/// Text and colour of the Iron Dome state badge.
pub fn state_badge(state: DomeState) -> (&'static str, Color) {
    match state {
        DomeState::TunnelActive => ("PROTECTED", EMERALD),
        DomeState::KeyRotating => ("PROTECTED · ROTATING KEYS", EMERALD),
        DomeState::FailsafeLockdown => ("LOCKDOWN", CRIMSON),
        DomeState::ArmingBootLock => ("ARMING BOOT LOCK", AMBER),
        DomeState::Handshaking => ("HANDSHAKING", AMBER),
        DomeState::CanaryAuditing => ("CANARY AUDIT", AMBER),
        DomeState::Disarming => ("DISARMING", AMBER),
        DomeState::Disarmed => ("DISARMED · TRAFFIC EXPOSED", MUTED),
    }
}

fn tone_color(t: Tone) -> Color {
    match t {
        Tone::Info => CYAN,
        Tone::Success => EMERALD,
        Tone::Warning => AMBER,
        Tone::Danger => CRIMSON,
    }
}

fn panel(title: &str, focused: bool) -> Block<'static> {
    Block::bordered()
        .border_style(Style::default().fg(if focused { CYAN } else { CHROME }))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(BG).fg(TEXT))
}

fn check(ok: bool) -> Span<'static> {
    if ok {
        Span::styled(
            "✔ ",
            Style::default().fg(EMERALD).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "✖ ",
            Style::default().fg(CRIMSON).add_modifier(Modifier::BOLD),
        )
    }
}

fn muted(s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), Style::default().fg(MUTED))
}

fn bold(s: impl Into<String>, c: Color) -> Span<'static> {
    Span::styled(
        s.into(),
        Style::default().fg(c).add_modifier(Modifier::BOLD),
    )
}

// ───────────────────────────── entry point ─────────────────────────────

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    f.render_widget(
        Block::default().style(Style::default().bg(BG).fg(TEXT)),
        area,
    );

    let Some(status) = app.status.as_ref().filter(|_| app.is_online()) else {
        draw_offline(f, area, app);
        return;
    };

    let banner_h = u16::from(app.banner.is_some());
    let [header, banner, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(banner_h),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);

    draw_header(f, header, app, status);
    if let Some(b) = &app.banner {
        f.render_widget(
            Paragraph::new(Line::from(bold(format!(" {} ", b.text), BG)))
                .style(Style::default().bg(tone_color(b.tone))),
            banner,
        );
    }
    match app.focus {
        Focus::Overview => draw_overview(f, body, app, status),
        focus => draw_panel(f, body, app, status, focus, true, false),
    }
    draw_footer(f, footer, app);
    if app.confirm_disarm {
        draw_confirm(f, area);
    }
}

fn draw_overview(f: &mut Frame, area: Rect, app: &App, status: &StatusReport) {
    let show_map = area.width >= MAP_MIN_WIDTH && area.height + 4 >= MAP_MIN_HEIGHT;
    let [top, bottom] = if show_map {
        Layout::vertical([Constraint::Percentage(56), Constraint::Percentage(44)]).areas(area)
    } else {
        Layout::vertical([Constraint::Length(9), Constraint::Min(0)]).areas(area)
    };
    if show_map {
        let [map, right] =
            Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(top);
        let [traffic, crypto] =
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(right);
        draw_panel(f, map, app, status, Focus::Map, false, false);
        draw_panel(f, traffic, app, status, Focus::Traffic, false, false);
        draw_panel(f, crypto, app, status, Focus::Crypto, false, false);
    } else {
        let [traffic, crypto] =
            Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(top);
        draw_panel(f, traffic, app, status, Focus::Traffic, false, true);
        draw_panel(f, crypto, app, status, Focus::Crypto, false, true);
    }
    let [fw, shield, opt] = Layout::horizontal([
        Constraint::Percentage(38),
        Constraint::Percentage(27),
        Constraint::Percentage(35),
    ])
    .areas(bottom);
    draw_panel(f, fw, app, status, Focus::Firewall, false, !show_map);
    draw_panel(f, shield, app, status, Focus::Shield, false, !show_map);
    draw_panel(f, opt, app, status, Focus::Optimizer, false, !show_map);
}

fn draw_panel(
    f: &mut Frame,
    area: Rect,
    app: &App,
    status: &StatusReport,
    which: Focus,
    focused: bool,
    compact: bool,
) {
    match which {
        Focus::Overview => draw_overview(f, area, app, status),
        Focus::Map => draw_map(f, area, status, focused),
        Focus::Traffic => draw_traffic(f, area, app, status, focused),
        Focus::Crypto => draw_crypto(f, area, status, focused, compact),
        Focus::Firewall => draw_firewall(f, area, app, status, focused),
        Focus::Shield => draw_shield(f, area, status, focused),
        Focus::Optimizer => draw_optimizer(f, area, app, focused),
        Focus::Log => draw_log(f, area, app),
    }
}

// ───────────────────────────── offline ─────────────────────────────────

fn draw_offline(f: &mut Frame, area: Rect, app: &App) {
    let mut lines = vec![
        Line::from(bold(" VOIDWIRE ", BG)).style(Style::default().bg(CYAN)),
        Line::from(""),
    ];
    match &app.link {
        Link::Offline { error, attempts } => {
            lines.push(Line::from(bold("DAEMON UNREACHABLE", CRIMSON)));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                error.clone(),
                Style::default().fg(TEXT),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(muted(format!(
                "Retrying every 2 s (attempt {attempts}). Is voidwired installed and running?"
            ))));
            lines.push(Line::from(muted(
                "Iron Dome state is unknown while the daemon cannot be reached.",
            )));
        }
        Link::Connecting => {
            lines.push(Line::from(bold("CONNECTING TO VOIDWIRED…", AMBER)));
        }
        Link::Online { daemon_version } => {
            lines.push(Line::from(bold(
                format!("Authenticated to voidwired {daemon_version}"),
                EMERALD,
            )));
            lines.push(Line::from(muted("Waiting for the first status report…")));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(muted("q / Esc quit")));
    let h = (lines.len() as u16 + 4).min(area.height);
    let [_, mid, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(h),
        Constraint::Fill(1),
    ])
    .areas(area);
    let block = Block::bordered()
        .border_style(Style::default().fg(match app.link {
            Link::Offline { .. } => CRIMSON,
            _ => CHROME,
        }))
        .style(Style::default().bg(BG));
    f.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(block),
        mid,
    );
}

// ───────────────────────────── header / footer ─────────────────────────

fn draw_header(f: &mut Frame, area: Rect, app: &App, s: &StatusReport) {
    let (badge, badge_color) = state_badge(s.state);
    let profile = s.profile.map(|p| p.label()).unwrap_or("none");
    let transport = s.transport.map(|t| t.label()).unwrap_or("none");
    let line1 = Line::from(vec![
        Span::styled(
            " VOIDWIRE ",
            Style::default()
                .fg(BG)
                .bg(CYAN)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" {badge} "),
            Style::default()
                .fg(BG)
                .bg(badge_color)
                .add_modifier(Modifier::BOLD),
        ),
        muted("  profile "),
        bold(profile, TEXT),
        muted("  transport "),
        bold(transport, TEXT),
    ]);
    let events = if app.events_online {
        Span::styled("events live", Style::default().fg(EMERALD))
    } else {
        Span::styled("events reconnecting", Style::default().fg(AMBER))
    };
    let line2 = Line::from(vec![
        muted("uptime "),
        Span::raw(format::uptime(s.uptime_secs)),
        muted("  daemon "),
        Span::raw(s.daemon_version.clone()),
        muted("  platform "),
        Span::raw(s.platform.clone()),
        muted("  "),
        events,
    ]);
    f.render_widget(
        Paragraph::new(vec![line1, line2]).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(CHROME)),
        ),
        area,
    );
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let key = |k: &'static str| Span::styled(k, Style::default().fg(BG).bg(CYAN));
    let mut spans = vec![
        key("P"),
        muted(" panic "),
        key("c"),
        muted(" connect "),
        key("d"),
        muted(" down "),
        key("D"),
        muted(" disarm "),
        key("a"),
        muted(" audit "),
        key("o"),
        muted(" optimize "),
        key("Tab"),
        muted(format!(" {} ", app.focus.next().title().to_lowercase())),
        key("q"),
        muted(" quit"),
    ];
    for cmd in &app.in_flight {
        spans.push(Span::styled(
            format!("  ⟳ {}…", cmd.label()),
            Style::default().fg(AMBER),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_confirm(f: &mut Frame, area: Rect) {
    let w = area.width.min(64);
    let h = 7.min(area.height);
    let rect = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let lines = vec![
        Line::from(bold("DISCONNECT + DISARM IRON DOME?", CRIMSON)),
        Line::from("The firewall lockdown will be removed and traffic"),
        Line::from("will leave this device unprotected."),
        Line::from(vec![
            bold("y", CRIMSON),
            muted(" confirm   any other key cancels"),
        ]),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(
                Block::bordered()
                    .border_style(Style::default().fg(CRIMSON))
                    .style(Style::default().bg(BG).fg(TEXT)),
            ),
        rect,
    );
}

// ───────────────────────────── map ─────────────────────────────────────

fn role_label(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Entry => "ENTRY",
        NodeRole::Exit => "EXIT",
        NodeRole::Both => "ENTRY+EXIT",
    }
}

fn hop_tag(i: usize, h: &HopInfo) -> String {
    let mut s = format!("{} {}", i + 1, h.name);
    if let Some(cc) = &h.country {
        s.push_str(&format!(" {cc}"));
    }
    s
}

/// One-line textual route, used when the map is collapsed.
pub fn route_line(hops: &[HopInfo]) -> Line<'static> {
    let mut spans = vec![bold("YOU", CYAN)];
    if hops.is_empty() {
        spans.push(muted(" ─╳ no active route"));
    }
    for (i, h) in hops.iter().enumerate() {
        spans.push(muted(" ─▶ "));
        spans.push(Span::raw(hop_tag(i, h)));
        if let Some(rtt) = h.rtt_ms {
            spans.push(muted(format!(" {rtt:.0}ms")));
        }
        spans.push(if h.post_quantum {
            Span::styled(" PQ", Style::default().fg(EMERALD))
        } else {
            Span::styled(" non-PQ", Style::default().fg(AMBER))
        });
    }
    Line::from(spans)
}

fn draw_map(f: &mut Frame, area: Rect, s: &StatusReport, focused: bool) {
    let placed: Vec<(usize, &HopInfo, f64, f64)> = s
        .hops
        .iter()
        .enumerate()
        .filter_map(|(i, h)| h.coords.map(|(lat, lon)| (i, h, lon, lat)))
        .collect();
    let unplaced: Vec<String> = s
        .hops
        .iter()
        .enumerate()
        .filter(|(_, h)| h.coords.is_none())
        .map(|(i, h)| hop_tag(i, h))
        .collect();
    let mut block = panel(Focus::Map.title(), focused);
    if !unplaced.is_empty() {
        block = block.title_bottom(muted(format!(" no coordinates: {} ", unplaced.join(", "))));
    }
    let canvas = Canvas::default()
        .block(block)
        .background_color(BG)
        .marker(Marker::Braille)
        .x_bounds([-180.0, 180.0])
        .y_bounds([-90.0, 90.0])
        .paint(move |ctx| {
            ctx.draw(&Map {
                resolution: MapResolution::High,
                color: MAP,
            });
            ctx.layer();
            let mut prev = (YOU_LON, YOU_LAT);
            for (_, h, lon, lat) in &placed {
                let color = if h.post_quantum { CYAN } else { AMBER };
                ctx.draw(&CanvasLine::new(prev.0, prev.1, *lon, *lat, color));
                prev = (*lon, *lat);
            }
            ctx.layer();
            ctx.draw(&Points {
                coords: &[(YOU_LON, YOU_LAT)],
                color: CYAN,
            });
            let pts: Vec<(f64, f64)> = placed.iter().map(|(_, _, x, y)| (*x, *y)).collect();
            ctx.draw(&Points {
                coords: &pts,
                color: MAGENTA,
            });
            ctx.print(
                YOU_LON,
                YOU_LAT,
                Line::from(vec![bold("◎ YOU", CYAN), muted(" (not geolocated)")]),
            );
            for (i, h, lon, lat) in &placed {
                let mut spans = vec![bold(format!("◉ {}", hop_tag(*i, h)), TEXT)];
                if let Some(rtt) = h.rtt_ms {
                    spans.push(muted(format!(" {rtt:.0}ms")));
                }
                spans.push(if h.post_quantum {
                    bold(" PQ", EMERALD)
                } else {
                    bold(" non-PQ", AMBER)
                });
                ctx.print(*lon, *lat, Line::from(spans));
            }
        });
    f.render_widget(canvas, area);
}

// ───────────────────────────── traffic ─────────────────────────────────

fn draw_traffic(f: &mut Frame, area: Rect, app: &App, s: &StatusReport, focused: bool) {
    let block = panel(Focus::Traffic.title(), focused);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [rx_area, tx_area] =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(inner);
    let t = &s.telemetry;
    sparkline(f, rx_area, "▼ RX", &app.rx, t.rx_bytes, t.rx_packets, CYAN);
    sparkline(
        f,
        tx_area,
        "▲ TX",
        &app.tx,
        t.tx_bytes,
        t.tx_packets,
        MAGENTA,
    );
}

fn sparkline(
    f: &mut Frame,
    area: Rect,
    label: &str,
    series: &RateSeries,
    total: u64,
    packets: u64,
    color: Color,
) {
    if area.height == 0 {
        return;
    }
    let [head, graph] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    let current = series
        .current()
        .map(format::rate)
        .unwrap_or_else(|| "measuring…".into());
    f.render_widget(
        Paragraph::new(Line::from(vec![
            bold(format!("{label} {current}"), color),
            muted(format!(
                "  peak {}  total {}  {} pkts",
                format::rate(series.peak()),
                format::bytes(total),
                format::count(packets)
            )),
        ])),
        head,
    );
    let data = series.tail(graph.width as usize);
    f.render_widget(
        Sparkline::default()
            .data(&data)
            .style(Style::default().fg(color).bg(BG)),
        graph,
    );
}

// ───────────────────────────── crypto ──────────────────────────────────

/// The honest warning shown when a hop has no post-quantum protection.
pub fn non_pq_warning(index: usize, hop: &HopInfo) -> String {
    let what = if hop.kind == NodeKind::Warp {
        "classical WireGuard (WARP)"
    } else {
        "classical WireGuard"
    };
    format!(
        "⚠ Hop {} ({}) is {what}: no post-quantum protection on that hop",
        index + 1,
        hop.name
    )
}

fn draw_crypto(f: &mut Frame, area: Rect, s: &StatusReport, focused: bool, compact: bool) {
    let mut lines = Vec::new();
    if compact {
        lines.push(route_line(&s.hops));
    }
    // The honesty warning goes first so it survives small terminals.
    for (i, h) in s.hops.iter().enumerate().filter(|(_, h)| !h.post_quantum) {
        lines.push(Line::from(Span::styled(
            non_pq_warning(i, h),
            Style::default().fg(AMBER),
        )));
    }
    lines.push(Line::from(vec![
        muted("suite "),
        bold(
            if s.crypto_suite.is_empty() {
                "none (no tunnel)".to_string()
            } else {
                s.crypto_suite.clone()
            },
            CYAN,
        ),
    ]));
    if s.hops.is_empty() {
        lines.push(Line::from(muted("No active hops.")));
    }
    for (i, h) in s.hops.iter().enumerate() {
        lines.push(Line::from(vec![
            bold(format!("{} ", i + 1), TEXT),
            muted(format!("{:<5} ", role_label(h.role))),
            Span::raw(h.name.clone()),
            muted(format!(" · {} ", h.transport.label())),
            if h.post_quantum {
                Span::styled(
                    " PQ ML-KEM ",
                    Style::default()
                        .fg(BG)
                        .bg(EMERALD)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(
                    " CLASSICAL ",
                    Style::default()
                        .fg(BG)
                        .bg(AMBER)
                        .add_modifier(Modifier::BOLD),
                )
            },
        ]));
    }
    let rotation = s
        .last_rotation_secs_ago
        .map(|n| format!("{n}s ago"))
        .unwrap_or_else(|| "never".into());
    lines.push(Line::from(vec![
        muted("PQ rotation "),
        Span::raw(rotation),
        muted(format!(
            " ({} total)  DAITA ",
            format::count(s.telemetry.pq_rotations)
        )),
        if s.daita {
            bold("on", EMERALD)
        } else {
            bold("off", MUTED)
        },
        muted("  MTU "),
        Span::raw(s.mtu.map(|m| m.to_string()).unwrap_or_else(|| "–".into())),
    ]));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(panel(Focus::Crypto.title(), focused)),
        area,
    );
}

// ───────────────────────────── firewall ────────────────────────────────

fn draw_firewall(f: &mut Frame, area: Rect, app: &App, s: &StatusReport, focused: bool) {
    let fw = &s.firewall;
    let row = |ok: bool, label: &'static str| Line::from(vec![check(ok), Span::raw(label)]);
    let mut lines = vec![
        row(fw.ipv4_locked, "IPv4 lock"),
        row(fw.ipv6_locked, "IPv6 lock"),
        row(fw.dns_vault, "DNS vault"),
        row(fw.stun_filter, "WebRTC STUN filter"),
        row(fw.tunnelvision_guard, "Tunnelvision CVE-2024-3661 guard"),
        row(fw.boot_lock, "Boot lock"),
        Line::from(vec![muted("backend "), bold(fw.backend.clone(), TEXT)]),
    ];
    match &app.last_audit {
        None => lines.push(Line::from(muted("audit: none this session (press a)"))),
        Some(a) => {
            let passed = a.checks.iter().filter(|c| c.passed).count();
            lines.push(Line::from(vec![
                muted("audit "),
                if a.passed {
                    bold("PASSED", EMERALD)
                } else {
                    bold("FAILED", CRIMSON)
                },
                muted(format!(
                    " {}/{} · {}",
                    passed,
                    a.checks.len(),
                    format::utc_clock(a.unix_time)
                )),
            ]));
            for c in &a.checks {
                let mut spans = vec![
                    Span::raw(" "),
                    check(c.passed),
                    Span::raw(c.name.clone()),
                    muted(format!(" {}", format::short_proof(&c.proof))),
                ];
                if focused || !c.passed {
                    spans.push(muted(format!(" {}", c.detail)));
                }
                lines.push(Line::from(spans));
            }
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel(Focus::Firewall.title(), focused)),
        area,
    );
}

// ───────────────────────────── shield ──────────────────────────────────

fn draw_shield(f: &mut Frame, area: Rect, s: &StatusReport, focused: bool) {
    let t = &s.telemetry;
    let sh = &t.shield;
    let block = panel(Focus::Shield.title(), focused);
    let width = block.inner(area).width as usize;
    let kv = |label: &str, v: u64, c: Color| {
        let value = format::count(v);
        let pad = width.saturating_sub(label.chars().count() + value.len());
        Line::from(vec![
            muted(label.to_string()),
            Span::raw(" ".repeat(pad)),
            Span::styled(value, Style::default().fg(c)),
        ])
    };
    let lines = vec![
        Line::from(vec![
            bold("TOTAL ", CYAN),
            bold(format::count(sh.total()), CYAN),
        ]),
        kv("ads", sh.ads, TEXT),
        kv("trackers", sh.trackers, TEXT),
        kv("telemetry", sh.telemetry, TEXT),
        kv("malware", sh.malware, TEXT),
        kv("custom", sh.custom, TEXT),
        kv("CNAME-uncloaked", sh.cname_uncloaked, TEXT),
        Line::from(muted("── leak drops ──")),
        kv("STUN", t.stun_blocked, AMBER),
        kv("IPv6", t.ipv6_dropped, AMBER),
        kv("DoT", t.dot_blocked, AMBER),
        kv("pre-canary", t.pre_canary_dropped, AMBER),
        kv("DNS intercepted", t.dns_intercepted, TEXT),
    ];
    f.render_widget(Paragraph::new(lines).block(block), area);
}

// ───────────────────────────── optimizer ───────────────────────────────

fn draw_optimizer(f: &mut Frame, area: Rect, app: &App, focused: bool) {
    let mut lines = Vec::new();
    match &app.decision {
        None => lines.push(Line::from(muted("No optimizer decision yet (press o)."))),
        Some(d) => {
            lines.push(Line::from(vec![
                muted("hops "),
                bold(
                    if d.hops.is_empty() {
                        "–".to_string()
                    } else {
                        d.hops.join(" → ")
                    },
                    TEXT,
                ),
            ]));
            lines.push(Line::from(vec![
                muted("via "),
                bold(d.transport.label(), CYAN),
                muted(format!("  MTU {}  MSS {}", d.mtu, d.mss_v4)),
                muted("  DAITA "),
                Span::raw(if d.daita { "on" } else { "off" }),
            ]));
            let v = d.verdict;
            let mut net = Vec::new();
            if v.udp_hostile {
                net.push("UDP-hostile");
            }
            if v.quic_blocked {
                net.push("QUIC blocked");
            }
            if v.wg_signature_filtered {
                net.push("WG signature filtered");
            }
            lines.push(Line::from(vec![
                muted("network "),
                if net.is_empty() {
                    Span::styled("clean", Style::default().fg(EMERALD))
                } else {
                    Span::styled(net.join(", "), Style::default().fg(AMBER))
                },
            ]));
            lines.push(Line::from(vec![
                muted("reason "),
                Span::raw(d.reason.clone()),
            ]));
            let mut cands: Vec<_> = d.candidates.iter().collect();
            cands.sort_by(|a, b| b.score.total_cmp(&a.score));
            let n = if focused { cands.len() } else { 3 };
            if !cands.is_empty() {
                lines.push(Line::from(muted("top candidates")));
            }
            for (i, c) in cands.into_iter().take(n).enumerate() {
                let rtt = c
                    .rtt_ms
                    .map(|r| format!("{r:.0}ms"))
                    .unwrap_or_else(|| "–".into());
                let mut spans = vec![
                    bold(format!("{} ", i + 1), TEXT),
                    Span::raw(format!("{} ", c.node_name)),
                    muted(format!("{} ", c.transport.label())),
                    bold(format!("{:.1}", c.score), CYAN),
                    muted(format!(" {rtt} loss {:.1}%", c.loss * 100.0)),
                ];
                if let Some(t) = c.throughput_mbps {
                    spans.push(muted(format!(" {t:.0}Mb/s")));
                }
                if !c.reachable {
                    spans.push(Span::styled(" unreachable", Style::default().fg(CRIMSON)));
                } else if !c.post_quantum {
                    spans.push(Span::styled(" non-PQ", Style::default().fg(AMBER)));
                }
                lines.push(Line::from(spans));
            }
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(panel(Focus::Optimizer.title(), focused)),
        area,
    );
}

// ───────────────────────────── log ─────────────────────────────────────

fn draw_log(f: &mut Frame, area: Rect, app: &App) {
    let block = panel(Focus::Log.title(), true);
    let rows = block.inner(area).height as usize;
    let skip = app.logs.len().saturating_sub(rows);
    let mut lines: Vec<Line> = app
        .logs
        .iter()
        .skip(skip)
        .map(|l| {
            let c = match l.level.as_str() {
                "error" => CRIMSON,
                "warn" => AMBER,
                "state" => CYAN,
                _ => MUTED,
            };
            Line::from(vec![
                Span::styled(format!("{:<6}", l.level), Style::default().fg(c)),
                Span::raw(l.message.clone()),
            ])
        })
        .collect();
    if lines.is_empty() {
        lines.push(Line::from(muted("No daemon log lines received yet.")));
    }
    if let Some(e) = &app.events_error {
        if !app.events_online {
            lines.push(Line::from(Span::styled(
                format!("event stream reconnecting: {e}"),
                Style::default().fg(AMBER),
            )));
        }
    }
    f.render_widget(Paragraph::new(lines).block(block), area);
}

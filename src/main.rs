#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod native_chrome;
mod config;
mod setup;
mod delete_job;
mod delete_ui;
mod install;
mod recent;
mod theme;
mod windows;
use eframe::egui::{self, Color32, RichText};
use egui_phosphor::light as icons;
use theme::ThemeMode;

use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};
use windows::{Disk, ProcessInfo};

enum Event {
    Disks(Result<Vec<Disk>, String>),
    Directory(u64, String, Result<windows::DirectoryListing, String>),
    Processes(u64, Result<windows::VisibleScan, String>),
    Recent(Result<Vec<String>, String>),
    Mounted(String, Result<String, String>),
    Action(Result<String, String>),
    Detached(Result<String, String>),
    Log(String),
    Finished(Result<(), String>),
    Installed(Result<String, String>),
    SystemTheme(bool),
    Deleted(u64, delete_ui::DeleteTarget, Result<String, String>),
    DeleteLog(String),
    HostSetup(u64, Result<String, String>),
    GuardInstalled(u64, Result<String, String>),
    GuardChecked(u64, u64, String, Result<(), String>),
}
struct App {
    tx: Sender<Event>,
    rx: Receiver<Event>,
    disks: Vec<Disk>,
    selected: Option<usize>,
    tree: std::collections::HashMap<String, Vec<windows::Entry>>,
    expanded: std::collections::HashSet<String>,
    loading: std::collections::HashSet<String>,
    generation: u64,
    skipped: u64,
    processes: Vec<ProcessInfo>,
    scan_warning: String,
    rows: Vec<(String, bool, usize)>,
    tree_dirty: bool,
    last_filter: String,
    busy: bool,
    scan_busy: bool,
    last_scan: Instant,
    detached: bool,
    source: String,
    source_selected: bool,
    search: String,
    destination: String,
    config: config::Config,
    copy_ready: bool,
    setup_busy: bool,
    setup_generation: u64,
    setup_message: String,
    guard_message: String,
    guard_verified: Option<String>,
    guard_install_confirm: bool,
    status: String,
    logs: Vec<String>,
    force_confirm: Option<ProcessInfo>,
    delete_dialog: Option<delete_ui::DeleteDialog>,
    delete_running: bool,
    run_confirm: bool,
    running: bool,
    installing: bool,
    install_confirm: bool,
    show_settings: bool,
    theme_mode: ThemeMode,
    motion_enabled: bool,
    system_light: bool,
    system_checked: Instant,
    last_visual: Option<bool>,
    last_blend: Option<f32>,
    brand: Option<egui::TextureHandle>,
    recent_images: Vec<String>,
    pending_select: Option<String>,
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
static MAPPINGS: std::sync::OnceLock<std::sync::Mutex<Vec<(String, String)>>> =
    std::sync::OnceLock::new();
fn refresh_mappings() {
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoProfile","-NonInteractive","-Command", "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-SmbMapping | Select-Object LocalPath,RemotePath | ConvertTo-Json -Compress"]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    let out = cmd.output();
    if let Ok(out) = out {
        if out.status.success() {
            let v: serde_json::Value =
                serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
            let items: Vec<&serde_json::Value> = match &v {
                serde_json::Value::Array(a) => a.iter().collect(),
                serde_json::Value::Object(_) => vec![&v],
                _ => vec![],
            };
            let found = items
                .iter()
                .filter_map(|x| {
                    Some((
                        x["LocalPath"].as_str()?.to_string(),
                        x["RemotePath"].as_str()?.to_string(),
                    ))
                })
                .collect();
            if let Ok(mut m) = MAPPINGS.get_or_init(Default::default).lock() {
                *m = found;
            }
        }
    }
}
fn mapped_unc(path: &str) -> Result<String, String> {
    let p = path.replace('/', "\\");
    if p.starts_with("\\\\") {
        return Ok(p);
    }
    if p.len() < 3 || p.get(1..3) != Some(":\\") {
        return Err("Choose a UNC path or mapped network drive.".into());
    }
    let drive = &p[..2];
    if let Ok(m) = MAPPINGS.get_or_init(Default::default).lock() {
        for (local, remote) in m.iter() {
            if local.eq_ignore_ascii_case(drive) {
                return Ok(format!("{}{}", remote.trim_end_matches('\\'), &p[2..]));
            }
        }
    }
    Err(format!(
        "{drive} is not an active SMB mapping; refresh mappings or choose a network folder."
    ))
}
fn translate(path: &str, share: &str, root: &str) -> Result<String, String> {
    let p = mapped_unc(path)?;
    let s = mapped_unc(share)?;
    let s = s.trim_end_matches('\\');
    if p.len() < s.len()
        || !p
            .get(..s.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(s))
        || (p.len() > s.len() && p.as_bytes()[s.len()] != b'\\')
    {
        return Err(format!("{p} is not inside the configured share {s}"));
    }
    let rel = &p[s.len()..];
    let mut out = root.trim_end_matches('/').to_string();
    for component in rel.split('\\').filter(|x| !x.is_empty()) {
        if component == "." || component == ".." {
            return Err("Relative path components are not allowed.".into());
        }
        out.push('/');
        out.push_str(component);
    }
    Ok(if out.is_empty() { "/".into() } else { out })
}
fn command(
    host: &str,
    share: &str,
    root: &str,
    d: &Disk,
    source: &str,
    destination: &str,
) -> Result<(String, String), String> {
    if host.is_empty()
        || host.starts_with('-')
        || !host
            .bytes()
            .all(|x| x.is_ascii_alphanumeric() || b"@._-".contains(&x))
    {
        return Err("SSH host must be an ordinary user@host name or IP address.".into());
    }
    let image = translate(&d.image_path, share, root)?;
    let dest = translate(destination, share, root)?;
    let src = if source.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", source.replace('\\', "/"))
    };
    if src.split('/').any(|x| x == ".." || x == ".") {
        return Err("Invalid source path.".into());
    }
    let remote = format!(
        "\"$HOME/.local/share/vhdx-handoff/bin/vhdx-copy\" {} {} {} {}",
        quote(&image),
        d.partition,
        quote(&src),
        quote(&dest)
    );
    Ok((remote.clone(), remote))
}
#[derive(Clone, Copy)]
struct Palette {
    transition: f32,
    card: Color32,
    border: Color32,
    muted: Color32,
    accent: Color32,
    accent_fill: Color32,
    inner: Color32,
}
fn palette(light: bool) -> Palette {
    if light {
        Palette {
            transition: 1.0,
            card: Color32::from_rgb(250, 249, 247),
            border: Color32::from_rgb(170, 170, 166),
            muted: Color32::from_rgb(87, 90, 89),
            accent: Color32::from_rgb(103, 137, 0),
            accent_fill: Color32::from_rgb(195, 237, 41),
            inner: Color32::from_rgb(245, 244, 242),
        }
    } else {
        Palette {
            transition: 0.0,
            card: Color32::from_rgb(27, 29, 29),
            border: Color32::from_rgb(80, 83, 82),
            muted: Color32::from_rgb(174, 178, 175),
            accent: Color32::from_rgb(201, 241, 28),
            accent_fill: Color32::from_rgb(195, 237, 41),
            inner: Color32::from_rgb(20, 22, 22),
        }
    }
}
// The two color endpoints are blended over the same duration as the indicator.
// Roughly six display intervals at 60 Hz: fast, but enough frames to see motion.
const THEME_TRANSITION_SECONDS: f32 = 0.10;
fn mix_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let blend = |x: u8, y: u8| ((x as f32 + (y as f32 - x as f32) * t).round()).clamp(0.0, 255.0) as u8;
    Color32::from_rgba_unmultiplied(blend(a.r(), b.r()), blend(a.g(), b.g()), blend(a.b(), b.b()), blend(a.a(), b.a()))
}
fn color_contrast(a: Color32, b: Color32) -> f32 {
    fn luminance(c: Color32) -> f32 {
        let linear = |v: u8| { let x = v as f32 / 255.0; if x <= 0.04045 { x / 12.92 } else { ((x + 0.055) / 1.055).powf(2.4) } };
        0.2126 * linear(c.r()) + 0.7152 * linear(c.g()) + 0.0722 * linear(c.b())
    }
    let (a, b) = (luminance(a), luminance(b));
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}
fn readable_during_transition(preferred: Color32, background: Color32, t: f32) -> Color32 {
    if t <= 0.0 || t >= 1.0 || color_contrast(preferred, background) >= 4.5 { return preferred; }
    if color_contrast(Color32::BLACK, background) >= color_contrast(Color32::WHITE, background) { Color32::BLACK } else { Color32::WHITE }
}
fn blended_palette(t: f32) -> Palette {
    let (a, b) = (palette(false), palette(true));
    let card = mix_color(a.card, b.card, t);
    Palette {
        transition: t,
        card,
        border: mix_color(a.border, b.border, t),
        muted: readable_during_transition(mix_color(a.muted, b.muted, t), card, t),
        accent: readable_during_transition(mix_color(a.accent, b.accent, t), card, t),
        accent_fill: mix_color(a.accent_fill, b.accent_fill, t),
        inner: mix_color(a.inner, b.inner, t),
    }
}
fn card(ui: &mut egui::Ui, p: Palette, inner: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(p.card)
        .stroke(egui::Stroke::new(1.0_f32, p.border))
        .corner_radius(8.0)
        .inner_margin(11.0)
        .show(ui, inner);
}
fn section_title(ui: &mut egui::Ui, p: Palette, number: &str, title: &str, detail: &str) {
    ui.horizontal(|ui| {
        ui.label(heading(number).color(p.accent).size(17.0));
        ui.label(heading(title).size(18.0));
    });
    ui.label(RichText::new(detail).color(p.muted).size(13.0));
    ui.add_space(4.0);
}
fn inset(ui: &mut egui::Ui, p: Palette, inner: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new().fill(p.inner).stroke(egui::Stroke::new(1.0_f32, p.border))
        .corner_radius(6.0).inner_margin(10.0).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            inner(ui);
        });
}
fn dialog_label(ui: &mut egui::Ui, p: Palette, label: &str, value: &str) {
    ui.label(RichText::new(label).color(p.muted).size(12.0));
    egui::ScrollArea::horizontal().id_salt(("dialog-value", label))
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
        .max_height(30.0).show(ui, |ui| {
            ui.add(egui::Label::new(RichText::new(value).size(13.0)).wrap_mode(egui::TextWrapMode::Extend));
        });
}
fn primary_action(label: &str, p: Palette) -> egui::Button<'_> {
    egui::Button::new(heading(label).color(Color32::BLACK)).fill(p.accent_fill)
        .min_size(egui::vec2(105.0, 31.0))
}
// Installation is only redundant after an image-specific verification, never
// merely because the host reports that an installation path exists.
fn guard_verified_for_image(detached: bool, verified: Option<&str>, image: Option<&str>) -> bool {
    detached && verified.zip(image).is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
}
fn guard_install_result(result: Result<String, String>) -> String {
    match result {
        Ok(message) => message,
        Err(error) if error.starts_with("VHDX_HANDOFF_GUARD_ERROR: Existing helper/configuration not overwritten; inspect it before any upgrade") =>
            "A guard installation already exists. Its readiness has not been checked. Select and detach an image, then choose Verify detached image. If verification fails, inspect the existing installation before upgrading.".into(),
        Err(error) => format!("Guard install failed: {error}"),
    }
}
fn initialize_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    ouroboros_ui::theme::typography::register(&mut fonts);
    // The reference uses medium-weight line icons. Keep the existing font
    // family mappings and replace the fallback face with the regular variant.
    fonts.font_data.insert("phosphor".into(), egui_phosphor::Variant::Regular.font_data().into());
    if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\segoeui.ttf") {
        fonts.font_data.insert(
            "windows-segoe".into(),
            egui::FontData::from_owned(bytes).into(),
        );
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "windows-segoe".into());
    }
    if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\seguisb.ttf") {
        fonts.font_data.insert(
            "windows-segoe-semibold".into(),
            egui::FontData::from_owned(bytes).into(),
        );
        let mut heading = fonts
            .families
            .get(&egui::FontFamily::Proportional)
            .cloned()
            .unwrap_or_default();
        heading.insert(0, "windows-segoe-semibold".into());
        fonts
            .families
            .insert(egui::FontFamily::Name("heading".into()), heading);
    }
    ctx.set_fonts(fonts);
}
/// Respect the Windows "animation effects" accessibility setting.
#[cfg(windows)]
fn animations_enabled() -> bool {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn SystemParametersInfoW(action: u32, param: u32, value: *mut core::ffi::c_void, flags: u32) -> i32;
    }
    let mut enabled: i32 = 1;
    // SPI_GETCLIENTAREAANIMATION: output is a Windows BOOL.
    let ok = unsafe { SystemParametersInfoW(4162, 0, (&mut enabled as *mut i32).cast(), 0) };
    ok == 0 || enabled != 0
}
#[cfg(not(windows))]
fn animations_enabled() -> bool { true }

fn heading(text: impl Into<String>) -> RichText {
    RichText::new(text).family(egui::FontFamily::Name("heading".into()))
}
fn apply_palette(ctx: &egui::Context, t: f32) {
    let p = blended_palette(t);
    let lighter = t >= 0.45;
    let mut v = if lighter { egui::Visuals::light() } else { egui::Visuals::dark() };
    v.panel_fill = mix_color(Color32::from_rgb(20,22,22), Color32::from_rgb(245,243,240), t);
    v.window_fill = p.card;
    v.window_stroke = egui::Stroke::new(1.0_f32, p.border);
    v.window_corner_radius = egui::CornerRadius::same(8);
    v.menu_corner_radius = egui::CornerRadius::same(6);
    v.extreme_bg_color = p.inner;
    v.faint_bg_color = p.card;
    v.widgets.noninteractive.bg_fill = p.card;
    v.widgets.inactive.bg_fill = mix_color(Color32::from_rgb(42,44,44), Color32::from_rgb(246,245,243), t);
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, p.border);
    v.widgets.hovered.bg_fill = mix_color(Color32::from_rgb(57,62,51), Color32::from_rgb(229,234,216), t);
    v.widgets.active.bg_fill = v.widgets.hovered.bg_fill;
    let preferred_ink = mix_color(Color32::from_rgb(232,234,231), Color32::from_rgb(28,30,28), t);
    let ink = readable_during_transition(preferred_ink, p.card, t);
    v.override_text_color = Some(ink);
    for widget in [&mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active, &mut v.widgets.open] {
        widget.corner_radius = egui::CornerRadius::same(5);
        widget.weak_bg_fill = widget.bg_fill;
        widget.fg_stroke = egui::Stroke::new(1.0_f32, ink);
    }
    v.selection.bg_fill = mix_color(Color32::from_rgb(61,73,23), Color32::from_rgb(224,236,156), t);
    v.selection.stroke = egui::Stroke::new(1.0_f32, p.accent);
    ctx.set_visuals(v);
    ctx.global_style_mut(|s| {
        s.spacing.item_spacing = egui::vec2(6.0, 5.0);
        s.spacing.button_padding = egui::vec2(10.0, 5.0);
        s.spacing.interact_size.y = 29.0;
        s.text_styles.insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
        s.text_styles.insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
    });
}

impl Default for App {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        let (config, config_message)=match config::Config::load() {
            Ok(Some(c)) => (c, "Check the host helper before use.".to_string()),
            Ok(None) => (config::Config::default(), "Enter your host and share to begin.".to_string()),
            Err(e) => (config::Config::default(), format!("Settings could not be loaded: {e}. Existing settings will not be replaced unless you save.")),
        };
        let needs_setup=!config.copy_configured();
        let mut a = Self {
            tx,
            rx,
            disks: vec![],
            selected: None,
            tree: Default::default(),
            expanded: Default::default(),
            loading: Default::default(),
            generation: 0,
            skipped: 0,
            processes: vec![],
            scan_warning: String::new(),
            rows: vec![],
            tree_dirty: true,
            last_filter: "\0".into(),
            busy: false,
            scan_busy: false,
            last_scan: Instant::now(),
            detached: false,
            source: String::new(),
            source_selected: false,
            search: String::new(),
            destination: String::new(),
            config,
            copy_ready: false,
            setup_busy: false,
            setup_generation: 0,
            setup_message: config_message,
            guard_message: "Guard not yet checked for this image.".into(),
            guard_verified: None,
            guard_install_confirm: false,
            status: "Find or attach a VHDX to begin.".into(),
            logs: vec![],
            force_confirm: None,
            delete_dialog: None,
            delete_running: false,
            run_confirm: false,
            running: false,
            installing: false,
            install_confirm: false,
            show_settings: needs_setup,
            theme_mode: theme::load(),
            motion_enabled: animations_enabled(),
            system_light: false,
            system_checked: Instant::now(),
            last_visual: None,
            last_blend: None,
            brand: None,
            recent_images: vec![],
            pending_select: None,
        };
        a.find_disks();
        thread::spawn(refresh_mappings);
        let tx = a.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Recent(recent::load()));
        });
        let tx = a.tx.clone();
        thread::spawn(move || {
            if let Some(v) = theme::system_light() {
                let _ = tx.send(Event::SystemTheme(v));
            }
        });
        a
    }
}
impl App {
    fn disk(&self) -> Option<&Disk> {
        self.selected.and_then(|i| self.disks.get(i))
    }
    fn find_disks(&mut self) {
        self.busy = true;
        let t = self.tx.clone();
        thread::spawn(move || {
            let _ = t.send(Event::Disks(windows::discover_disks()));
        });
    }
    fn clear_selection(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.guard_verified = None;
        self.guard_message = "Guard not yet checked for this image.".into();
        self.selected = None;
        self.tree.clear();
        self.expanded.clear();
        self.loading.clear();
        self.rows.clear();
        self.tree_dirty = true;
        self.last_filter = "\0".into();
        self.skipped = 0;
        self.processes.clear();
        self.scan_warning.clear();
        self.scan_busy = false;
        self.detached = false;
        self.source.clear();
        self.source_selected = false;
        self.search.clear();
    }
    fn select_disk(&mut self, index: usize) {
        self.clear_selection();
        self.selected = Some(index);
        self.expanded.insert(String::new());
        if let Some(d) = self.disk() {
            let path = d.image_path.clone();
            let tx = self.tx.clone();
            thread::spawn(move || {
                let _ = tx.send(Event::Recent(recent::remember(&path)));
            });
        }
        self.load_dir(String::new());
    }
    fn load_dir(&mut self, path: String) {
        if self.detached {
            self.status =
                "Open folders before detaching; only previously loaded folders remain available."
                    .into();
            return;
        }
        if self.loading.contains(&path) || self.tree.contains_key(&path) {
            return;
        }
        if let Some(d) = self.disk() {
            let drive = d.drive.clone();
            let generation = self.generation;
            let tx = self.tx.clone();
            self.loading.insert(path.clone());
            self.status = if path.is_empty() {
                "Loading the top level…".into()
            } else {
                format!("Loading {path}…")
            };
            thread::spawn(move || {
                let result = windows::list_directory(&drive, &path);
                let _ = tx.send(Event::Directory(generation, path, result));
            });
        }
    }
    fn refresh_processes(&mut self) {
        if let Some(d) = self.disk() {
            let drive = d.drive.clone();
            let generation = self.generation;
            let entries = self
                .tree
                .values()
                .flatten()
                .filter(|e| !e.is_dir)
                .take(257)
                .cloned()
                .collect::<Vec<_>>();
            self.scan_busy = true;
            self.last_scan = Instant::now();
            let tx = self.tx.clone();
            thread::spawn(move || {
                let _ = tx.send(Event::Processes(
                    generation,
                    windows::scan_visible_processes(&drive, &entries),
                ));
            });
        }
    }
    fn action(&mut self, p: ProcessInfo, force: bool) {
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Action(windows::close_process(
                p.pid, p.started, force,
            )));
        });
    }
    fn detach(&mut self) {
        if let Some(d) = self.disk() {
            let image = d.image_path.clone();
            self.busy = true;
            let tx = self.tx.clone();
            thread::spawn(move || {
                let _ = tx.send(Event::Detached(windows::detach(&image)));
            });
        }
    }
    fn mount(&mut self, path: String) {
        self.clear_selection();
        self.busy = true;
        self.status = "Attaching the selected image…".into();
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = recent::mount(&path);
            let _ = tx.send(Event::Mounted(path, result));
        });
    }

    fn rebuild_rows(&mut self) {
        fn walk(
            tree: &std::collections::HashMap<String, Vec<windows::Entry>>,
            expanded: &std::collections::HashSet<String>,
            parent: &str,
            depth: usize,
            out: &mut Vec<(String, bool, usize)>,
        ) {
            if let Some(entries) = tree.get(parent) {
                for entry in entries {
                    out.push((entry.path.clone(), entry.is_dir, depth));
                    if entry.is_dir && expanded.contains(&entry.path) {
                        walk(tree, expanded, &entry.path, depth + 1, out);
                    }
                }
            }
        }
        self.rows.clear();
        if self.search.is_empty() {
            walk(&self.tree, &self.expanded, "", 0, &mut self.rows);
        } else {
            let needle = self.search.to_lowercase();
            for entries in self.tree.values() {
                for e in entries {
                    if e.path.to_lowercase().contains(&needle) {
                        self.rows.push((e.path.clone(), e.is_dir, 0));
                    }
                }
            }
            self.rows
                .sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
        }
        self.last_filter = self.search.clone();
        self.tree_dirty = false;
    }
    fn set_theme(&mut self, mode: ThemeMode) {
        self.motion_enabled = animations_enabled();
        self.theme_mode = mode;
        if let Err(e) = theme::save(mode) {
            self.status = format!("Could not save theme preference: {e}");
        }
    }
    fn show_tree(&mut self, ui: &mut egui::Ui, p: Palette) {
        ui.spacing_mut().interact_size.y = 22.0;
        ui.spacing_mut().item_spacing.y = 0.0;
        ui.spacing_mut().button_padding = egui::vec2(2.0, 0.0);
        ui.horizontal(|ui| {
            ui.add_space(4.0);
            ui.label(RichText::new(icons::CARET_DOWN).size(15.0));
            ui.add_space(3.0);
            ui.label(RichText::new(icons::FOLDER_SIMPLE).color(p.accent).size(18.0));
            let label = self.disk().map(|d| d.drive.clone()).unwrap_or_default();
            if ui.selectable_label(self.source_selected && self.source.is_empty(), label)
                .on_hover_text("Select the entire drive")
                .clicked()
            {
                self.source.clear();
                self.source_selected = true;
            }
        });
        let total = self.rows.len();
        // Keep the transfer actions visible in a short window; the tree remains
        // independently scrollable when it has more rows than this viewport.
        let tree_height = (ui.ctx().content_rect().height() - 449.0).clamp(96.0, 150.0);
        ui.spacing_mut().interact_size.y = 22.0;
        ui.spacing_mut().item_spacing.y = 0.0;
        ui.spacing_mut().button_padding = egui::vec2(2.0, 0.0);
        egui::ScrollArea::vertical()
            .id_salt("source-tree")
            .max_height(tree_height)
            .min_scrolled_height(tree_height)
            .show_rows(ui, 24.0, total, |ui, range| {
                let rows = self.rows[range].to_vec();
                for (path, is_dir, depth) in rows {
                    let row_rect = egui::Rect::from_min_size(
                        ui.cursor().min, egui::vec2(ui.available_width(), 24.0));
                    let row_response = ui.interact(row_rect, ui.id().with(("tree-row", &path)), egui::Sense::click());
                    if self.source_selected && self.source == path {
                        ui.painter().rect_filled(row_rect, 4.0, ui.visuals().selection.bg_fill);
                    }
                    ui.horizontal(|ui| {
                        let selected = self.source_selected && self.source == path;
                        if selected {
                            let bg = ui.visuals().selection.bg_fill;
                            let ink = readable_during_transition(ui.visuals().text_color(), bg, p.transition);
                            ui.visuals_mut().override_text_color = Some(ink);
                        }
                        ui.spacing_mut().button_padding = egui::vec2(2.0, 1.0);
                        ui.spacing_mut().interact_size.y = 20.0;
                        ui.add_space(24.0 + (depth.min(12) as f32) * 15.0);
                        if is_dir {
                            let opened = self.expanded.contains(&path);
                            let glyph = if opened {
                                icons::CARET_DOWN
                            } else {
                                icons::CARET_RIGHT
                            };
                            let available = !self.detached || self.tree.contains_key(&path);
                            if ui
                                .add_enabled(available, egui::Button::new(RichText::new(glyph).size(15.0)).frame(false))
                                .on_disabled_hover_text(
                                    "Open this folder before detaching to browse its contents.",
                                )
                                .clicked()
                            {
                                if opened {
                                    self.expanded.remove(&path);
                                } else {
                                    self.expanded.insert(path.clone());
                                    self.load_dir(path.clone());
                                }
                                self.tree_dirty = true;
                            }
                        } else {
                            ui.add_space(20.0);
                        }
                        ui.label(
                            RichText::new(if is_dir {
                                icons::FOLDER_SIMPLE
                            } else {
                                icons::FILE
                            })
                            .color(if selected { readable_during_transition(p.accent, ui.visuals().selection.bg_fill, p.transition) } else { p.accent }).size(18.0),
                        );
                        ui.add_space(4.0);
                        let label = if self.search.is_empty() {
                            std::path::Path::new(&path)
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_else(|| path.clone())
                        } else {
                            path.clone()
                        };
                        let label_response = ui.add(egui::Button::new(label).frame(false));
                        let response = row_response.union(label_response);
                        if response.clicked() {
                            self.source = path.clone();
                            self.source_selected = true;
                        }
                        response.context_menu(|ui| {
                            ui.set_max_width(280.0);
                            ui.label(heading("Image item").size(14.0));
                            ui.separator();
                            let allowed = self.detached
                                && self.guard_verified.as_deref().zip(self.disk().map(|d|d.image_path.as_str())).is_some_and(|(a,b)|a.eq_ignore_ascii_case(b))
                                && !self.setup_busy
                                && !self.busy
                                && !self.running
                                && !self.scan_busy
                                && self.loading.is_empty();
                            if ui
                                .add_enabled(allowed, egui::Button::new("Delete from VHDX…"))
                                .clicked()
                            {
                                if let Some(d) = self.disk() {
                                    match delete_ui::DeleteTarget::new(
                                        d.image_path.clone(),
                                        path.clone(),
                                        is_dir,
                                    ) {
                                        Ok(target) => {
                                            self.delete_dialog =
                                                Some(delete_ui::DeleteDialog::new(target))
                                        }
                                        Err(e) => self.status = e,
                                    }
                                }
                                ui.close();
                            }
                            if !allowed {
                                ui.weak("Detach the image and verify its host guard in Host setup before deleting.");
                            }
                        });
                        if self.loading.contains(&path) {
                            ui.spinner();
                        }
                    });
                }
            });
    }

    fn begin_delete(&mut self, target: delete_ui::DeleteTarget) {
        if !self.guard_verified.as_deref().is_some_and(|p|p.eq_ignore_ascii_case(&target.image_path)) {
            self.status="Verify the host guard for this detached image before deleting.".into();
            return;
        }
        self.guard_verified=None; // Require a fresh verification after each operation.
        let Some(partition) = self.disk().map(|d| d.partition) else {
            self.status = "No selected partition.".into();
            return;
        };
        let generation = self.generation;
        let cfg = self.config.clone();
        let tx = self.tx.clone();
        self.busy = true;
        self.delete_running = true;
        self.logs.clear();
        self.status =
            "Deleting on the host; keep the image detached until cleanup completes…".into();
        thread::spawn(move || {
            let (log_tx, log_rx) = std::sync::mpsc::channel();
            let relay = tx.clone();
            let relay_task = std::thread::spawn(move || {
                for line in log_rx {
                    let _ = relay.send(Event::DeleteLog(line));
                }
            });
            let result = delete_job::run(&cfg, &target, partition, log_tx);
            let _ = relay_task.join();
            let _ = tx.send(Event::Deleted(generation, target, result));
        });
    }
    fn start_host_setup(&mut self, install: bool) {
        if self.setup_busy { return; }
        self.copy_ready=false;
        if let Err(e)=setup::validate(&self.config).and_then(|_|self.config.save()) {
            self.setup_message=e;
            return;
        }
        self.setup_generation=self.setup_generation.wrapping_add(1);
        let generation=self.setup_generation;
        let config=self.config.clone();
        let tx=self.tx.clone();
        self.setup_busy=true;
        self.setup_message=if install { "Installing the copy helper on the SSH host…".into() } else { "Checking the copy helper on the SSH host…".into() };
        thread::spawn(move || { let result=setup::copy_helper(&config,install);let _=tx.send(Event::HostSetup(generation,result)); });
    }
    fn start_guard_install(&mut self) {
        if self.setup_busy {return;}
        self.guard_verified=None;
        if let Err(e)=setup::validate(&self.config).and_then(|_|self.config.save()) {self.guard_message=e;return;}
        self.setup_generation=self.setup_generation.wrapping_add(1);
        let seq=self.setup_generation; let cfg=self.config.clone();let tx=self.tx.clone();
        self.setup_busy=true;self.guard_message="Installing the bundled guard on the host…".into();
        thread::spawn(move || {let result=setup::install_guard(&cfg);let _=tx.send(Event::GuardInstalled(seq,result));});
    }
    fn start_guard_check(&mut self) {
        if self.setup_busy {return;}
        self.guard_verified=None;
        if !self.detached {self.guard_message="Detach the selected image before verifying its host guard.".into();return;}
        let Some(image)=self.disk().map(|d|d.image_path.clone()) else {self.guard_message="Select an image first.".into();return;};
        if let Err(e)=setup::validate(&self.config).and_then(|_|self.config.save()) {self.guard_message=e;return;}
        self.setup_generation=self.setup_generation.wrapping_add(1);
        let seq=self.setup_generation;let disk_generation=self.generation;let cfg=self.config.clone();let tx=self.tx.clone();
        self.setup_busy=true;self.guard_message="Verifying this image and host guard…".into();
        thread::spawn(move || {let result=delete_job::check_guard(&cfg,&image);let _=tx.send(Event::GuardChecked(seq,disk_generation,image,result));});
    }
    fn run(&mut self, remote: String) {
        let t = self.tx.clone();
        let host = self.config.copy_ssh.clone();
        let config = self.config.clone();
        let destination = self.destination.clone();
        let image = self.disk().unwrap().image_path.clone();
        self.running = true;
        self.logs.clear();
        thread::spawn(move || {
            let result = (|| -> Result<(), String> {
                if windows::image_attached(&image)? {
                    return Err(
                        "The image was reattached in Windows; detach it again before copying."
                            .into(),
                    );
                }
                let _ = t.send(Event::Log("Verifying the image and destination share mappings…".into()));
                setup::verify_copy_mapping(&config, &image, &destination)?;
                if windows::image_attached(&image)? {
                    return Err("The image was reattached during mapping checks; copy did not start.".into());
                }
                let mut cmd = Command::new("ssh.exe");
                cmd.args([
                    "-T",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "StrictHostKeyChecking=yes",
                    "-o",
                    "ConnectTimeout=8",
                    "-a",
                    &host,
                    &remote,
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
                #[cfg(windows)]
                {
                    use std::os::windows::process::CommandExt;
                    cmd.creation_flags(0x08000000);
                }
                let mut child = cmd
                    .spawn()
                    .map_err(|e| format!("Could not start SSH: {e}"))?;
                let stderr = child.stderr.take().unwrap();
                let t2 = t.clone();
                let err_thread = thread::spawn(move || {
                    for l in BufReader::new(stderr).lines().map_while(Result::ok) {
                        let _ = t2.send(Event::Log(l));
                    }
                });
                for l in BufReader::new(child.stdout.take().unwrap())
                    .lines()
                    .map_while(Result::ok)
                {
                    let _ = t.send(Event::Log(l));
                }
                let status = child.wait().map_err(|e| e.to_string())?;
                let _ = err_thread.join();
                if status.success() {
                    Ok(())
                } else {
                    Err(format!("SSH/helper exited with {status}; the destination may be partially updated."))
                }
            })();
            let _ = t.send(Event::Finished(result));
        });
    }
    fn events(&mut self) {
        while let Ok(e) = self.rx.try_recv() {
            match e {
                Event::Disks(result) => {
                    self.busy = false;
                    match result {
                        Ok(disks) => {
                            let wanted = self.pending_select.take().or_else(|| {
                                if !self.detached {
                                    self.disk().map(|d| d.image_path.clone())
                                } else {
                                    None
                                }
                            });
                            self.clear_selection();
                            self.disks = disks;
                            if let Some(path) = wanted {
                                if let Some(index) = self
                                    .disks
                                    .iter()
                                    .position(|d| d.image_path.eq_ignore_ascii_case(&path))
                                {
                                    self.select_disk(index);
                                } else {
                                    self.status="Image attached, but Windows has not assigned a drive letter yet. Refresh shortly.".into();
                                }
                            } else {
                                self.status =
                                    format!("Found {} attached VHDX volumes.", self.disks.len());
                            }
                        }
                        Err(e) => self.status = e,
                    }
                }
                Event::Directory(g, path, result) => {
                    if g != self.generation {
                        continue;
                    }
                    self.loading.remove(&path);
                    match result {
                        Ok(list) => {
                            self.skipped += list.skipped;
                            let n = list.entries.len();
                            self.tree.insert(path.clone(), list.entries);
                            self.tree_dirty = true;
                            self.status = if path.is_empty() {
                                format!("Top level ready · {n} items. Open a folder to load it.")
                            } else {
                                format!("Loaded {n} items in {path}.")
                            };
                            if path.is_empty() && !self.scan_busy {
                                self.refresh_processes();
                            }
                        }
                        Err(e) => {
                            self.expanded.remove(&path);
                            self.status = format!("Could not load folder: {e}");
                        }
                    }
                }
                Event::Processes(g, result) => {
                    if g != self.generation {
                        continue;
                    }
                    self.scan_busy = false;
                    self.last_scan = Instant::now();
                    match result {
                        Ok(scan) => {
                            self.processes = scan.processes;
                            self.scan_warning=format!("Partial check: {} loaded files checked; at least {} skipped or omitted; {} scan errors; {} processes inaccessible. Other handles can be missed.",scan.files_considered,scan.skipped,scan.scan_errors,scan.inaccessible_processes);
                        }
                        Err(e) => {
                            self.scan_warning = format!("Process check failed: {e}");
                            self.status = self.scan_warning.clone();
                        }
                    }
                }
                Event::Recent(result) => match result {
                    Ok(list) => self.recent_images = list,
                    Err(e) => self.status = format!("Recent images unavailable: {e}"),
                },
                Event::Mounted(path, result) => {
                    self.busy = false;
                    match result {
                        Ok(msg) => {
                            self.status = msg;
                            self.pending_select = Some(path);
                            let tx = self.tx.clone();
                            thread::spawn(move || {
                                let _ = tx.send(Event::Recent(recent::load()));
                            });
                            self.find_disks();
                        }
                        Err(e) => self.status = e,
                    }
                }
                Event::Action(result) => self.status = result.unwrap_or_else(|e| e),
                Event::Detached(result) => {
                    self.busy = false;
                    match result {
                        Ok(s) => {
                            self.detached = true;
                            self.processes.clear();
                            self.status = s;
                        }
                        Err(e) => self.status = e,
                    }
                }
                Event::Log(s) => {
                    self.logs.push(s);
                    if self.logs.len() > 300 {
                        self.logs.remove(0);
                    }
                }
                Event::Deleted(generation, target, result) => {
                    self.busy = false;
                    self.delete_running = false;
                    if generation != self.generation {
                        self.status =
                            "Delete finished for a previous image; inspect it before use.".into();
                        continue;
                    }
                    let path = target.relative_path.clone();
                    let prefix = format!("{}\\", path);
                    self.tree
                        .retain(|parent, _| parent != &path && !parent.starts_with(&prefix));
                    for entries in self.tree.values_mut() {
                        entries.retain(|e| e.path != path && !e.path.starts_with(&prefix));
                    }
                    self.expanded
                        .retain(|parent| parent != &path && !parent.starts_with(&prefix));
                    if self.source == path || self.source.starts_with(&prefix) {
                        self.source.clear();
                        self.source_selected = false;
                    }
                    self.tree_dirty = true;
                    match result {
                        Ok(message) => self.status = message,
                        Err(error) => {
                            self.tree.clear();
                            self.rows.clear();
                            self.expanded.clear();
                            self.source_selected = false;
                            self.status = error;
                        }
                    }
                }
                Event::DeleteLog(line) => {
                    if line.contains("SAFE HOLD") {
                        self.status = line.clone();
                    }
                    self.logs.push(line);
                    if self.logs.len() > 300 {
                        self.logs.remove(0);
                    }
                }
                Event::SystemTheme(v) => {
                    if self.system_light != v { self.motion_enabled = animations_enabled(); }
                    self.system_light = v;
                },
                Event::HostSetup(generation, result) => {
                    self.setup_busy=false;
                    if generation == self.setup_generation {
                        self.copy_ready=result.is_ok();
                        self.setup_message=result.unwrap_or_else(|e| format!("Host setup not ready: {e}"));
                    }
                }
                Event::GuardInstalled(seq, result) => {
                    self.setup_busy=false;
                    if seq==self.setup_generation { self.guard_message=guard_install_result(result); }
                }
                Event::GuardChecked(seq, disk_generation, image, result) => {
                    self.setup_busy=false;
                    if seq==self.setup_generation && disk_generation==self.generation && self.detached && self.disk().is_some_and(|d|d.image_path.eq_ignore_ascii_case(&image)) {
                        match result {Ok(())=>{self.guard_verified=Some(image);self.guard_message="Guard verified for this detached image. It will be checked again before deletion.".into();},Err(e)=>{self.guard_verified=None;self.guard_message=format!("Guard is not ready: {e}");}}
                    }
                }
                Event::Installed(result) => {
                    self.installing = false;
                    self.status = result.unwrap_or_else(|e| format!("Installation failed: {e}"));
                }
                Event::Finished(result) => {
                    self.running = false;
                    self.status = match result {
                        Ok(()) => "Copy complete. The image can be reattached.".into(),
                        Err(e) => e,
                    };
                }
            }
        }
    }
}
impl eframe::App for App {
    fn ui(&mut self, root: &mut egui::Ui, _: &mut eframe::Frame) {
        let ctx = root.ctx().clone();
        self.events();
        ctx.request_repaint_after(Duration::from_millis(250));
        if self.theme_mode == ThemeMode::System
            && self.system_checked.elapsed() > Duration::from_secs(10)
        {
            self.system_checked = Instant::now();
            let tx = self.tx.clone();
            thread::spawn(move || {
                if let Some(v) = theme::system_light() {
                    let _ = tx.send(Event::SystemTheme(v));
                }
            });
        }
        let light = self.theme_mode.light(self.system_light);
        let target = if light { 1.0 } else { 0.0 };
        let animated = ctx.animate_value_with_time(
            egui::Id::new("theme-palette"), target,
            if self.motion_enabled { THEME_TRANSITION_SECONDS } else { 0.0 },
        );
        let blend = if self.motion_enabled { animated } else { target };
        if self.last_blend != Some(blend) {
            apply_palette(&ctx, blend);
            // Root was created before set_visuals; update its cached style so all
            // child widgets paint this same animation frame, not the previous one.
            root.set_style(ctx.global_style());
            self.last_blend = Some(blend);
        }
        // Native Windows title bars do not expose an interpolated appearance.
        // Switch the system chrome once the blended surface crosses midpoint.
        let chrome_light = blend >= 0.5;
        if self.last_visual != Some(chrome_light) {
            ctx.send_viewport_cmd(egui::ViewportCommand::SetTheme(if chrome_light {
                egui::SystemTheme::Light
            } else {
                egui::SystemTheme::Dark
            }));
            self.last_visual = Some(chrome_light);
        }
        let p = blended_palette(blend);
        if self.selected.is_some()
            && !self.detached
            && !self.scan_busy
            && !self.busy
            && self.last_scan.elapsed() > Duration::from_secs(20)
        {
            self.refresh_processes();
        }
        if self.tree_dirty || self.last_filter != self.search {
            self.rebuild_rows();
        }
        if self.brand.is_none() {
            let image =
                egui::ColorImage::from_rgba_unmultiplied([57, 45], include_bytes!("brand.rgba"));
            self.brand =
                Some(ctx.load_texture("handoff-brand", image, egui::TextureOptions::LINEAR));
        }
        egui::Panel::bottom("status-bar")
            .frame(
                egui::Frame::new()
                    .fill(ctx.global_style().visuals.panel_fill)
                    .stroke(egui::Stroke::new(1.0_f32, p.border))
                    .inner_margin(egui::Margin::symmetric(20, 8)),
            )
            .show_inside(root, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(if self.running || self.delete_running {
                            icons::CIRCLE_NOTCH
                        } else {
                            icons::CHECK_CIRCLE
                        })
                        .color(p.accent)
                        .size(21.0),
                    );
                    if self.running || self.delete_running {
                        ui.spinner();
                    }
                    let heading = if self.delete_running {
                        "Deleting"
                    } else if self.running {
                        "Copying"
                    } else if self.detached {
                        "Image is detached"
                    } else if self.selected.is_some() {
                        "Image is attached"
                    } else {
                        "Ready"
                    };
                    ui.label(
                        RichText::new(heading)
                            .family(egui::FontFamily::Name("heading".into()))
                            .size(14.0),
                    );
                    ui.label(RichText::new("│").color(p.border).size(18.0));
                    let message = self
                        .status
                        .strip_prefix("Image is attached. ")
                        .unwrap_or(&self.status);
                    ui.label(RichText::new(message).size(13.0));
                });
                if let Some(last) = self
                    .logs
                    .last()
                    .filter(|_| self.running || self.delete_running)
                {
                    ui.label(RichText::new(last).color(p.muted).size(11.0));
                }
            });
        egui::Panel::top("header")
            .frame(
                egui::Frame::new()
                    .fill(ctx.global_style().visuals.panel_fill)
                    .stroke(egui::Stroke::new(1.0_f32, p.border))
                    .inner_margin(egui::Margin::symmetric(19, 6)),
            )
            .show_inside(root, |ui| {
                if self.run_confirm
                    || self.install_confirm
                    || self.force_confirm.is_some()
                    || self.delete_dialog.is_some()
                    || self.show_settings
                {
                    ui.disable();
                }
                ui.horizontal(|ui| {
                    if let Some(brand) = &self.brand {
                        ui.add(egui::Image::new(brand).fit_to_exact_size(egui::vec2(32.0, 25.0)));
                    }
                    ui.add_space(4.0);
                    ui.label(heading("VHDrop").size(20.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.scope(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            ui.spacing_mut().button_padding.x = 0.0;
                            ui.allocate_ui_with_layout(
                                egui::vec2(108.0, 29.0),
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                let target = match self.theme_mode {
                                    ThemeMode::Light => 0.0,
                                    ThemeMode::Dark => 1.0,
                                    ThemeMode::System => 2.0,
                                };
                                // egui retargets an in-flight animation from its current
                                // position, so quick repeated changes stay continuous.
                                let animated = ui.ctx().animate_value_with_time(
                                    ui.id().with("theme-indicator"), target,
                                    if self.motion_enabled { THEME_TRANSITION_SECONDS } else { 0.0 },
                                );
                                let position = if self.motion_enabled { animated } else { target };
                                // Reserve shapes before the buttons so they stay behind
                                // the icons. Their bounds come from the actual first button,
                                // not the nested UI's cursor/min rectangle (which is affected
                                // by vertical alignment).
                                let painter = ui.painter().clone();
                                let track_shape = painter.add(egui::Shape::Noop);
                                let indicator_shape = painter.add(egui::Shape::Noop);
                                let border_shape = painter.add(egui::Shape::Noop);
                                let mut indicator = egui::Rect::NOTHING;
                                for (mode, icon, label) in [
                                    (ThemeMode::Light, icons::SUN, "Light"),
                                    (ThemeMode::Dark, icons::MOON, "Dark"),
                                    (ThemeMode::System, icons::MONITOR, "System"),
                                ] {
                                    let selected = self.theme_mode == mode;
                                    // Retain egui buttons for their keyboard interaction and
                                    // accessible radio metadata, but paint the track ourselves.
                                    let response = ui.add(
                                        egui::Button::new(RichText::new(icon).size(17.0))
                                            .min_size(egui::vec2(36.0, 29.0))
                                            .frame(false),
                                    );
                                    if !indicator.is_positive() {
                                        let track = egui::Rect::from_min_size(
                                            response.rect.min, egui::vec2(108.0, response.rect.height()),
                                        );
                                        indicator = egui::Rect::from_min_size(
                                            track.min + egui::vec2(position * 36.0, 0.0),
                                            egui::vec2(36.0, track.height()),
                                        );
                                        painter.set(track_shape, egui::Shape::rect_filled(
                                            track, 5, ui.visuals().widgets.inactive.bg_fill,
                                        ));
                                        painter.set(indicator_shape, egui::Shape::rect_filled(
                                            indicator.shrink(1.0), 4, p.accent_fill,
                                        ));
                                        painter.set(border_shape, egui::Shape::rect_stroke(
                                            track, 5, egui::Stroke::new(1.0_f32, p.border),
                                            egui::StrokeKind::Inside,
                                        ));
                                    }
                                    // Repaint the part of each icon above the lime indicator
                                    // in dark ink, including while it crosses a segment.
                                    painter.with_clip_rect(indicator.shrink(1.0)).text(
                                        response.rect.center(), egui::Align2::CENTER_CENTER,
                                        icon, egui::FontId::proportional(17.0), Color32::BLACK,
                                    );
                                    if response.has_focus() {
                                        // A two-tone focus ring is visible over either the
                                        // light indicator or the surrounding theme surface.
                                        painter.rect_stroke(
                                            response.rect.shrink(1.5), 4,
                                            egui::Stroke::new(2.0_f32, Color32::BLACK),
                                            egui::StrokeKind::Inside,
                                        );
                                        painter.rect_stroke(
                                            response.rect.shrink(3.5), 3,
                                            egui::Stroke::new(1.0_f32, Color32::WHITE),
                                            egui::StrokeKind::Inside,
                                        );
                                    }
                                    response.widget_info(|| egui::WidgetInfo::selected(
                                        egui::WidgetType::RadioButton, ui.is_enabled(), selected,
                                        format!("{label} appearance"),
                                    ));
                                    let response = response.on_hover_text(format!("{label} appearance"));
                                    if response.clicked() && !selected {
                                        self.set_theme(mode);
                                    }
                                }
                            });
                        });
                        ui.add_space(10.0);
                        ui.label(RichText::new("│").color(p.border).size(21.0));
                        ui.add_space(10.0);
                        if ui
                            .add_enabled(
                                !self.installing,
                                egui::Button::new(format!("{}  Install…", icons::DOWNLOAD_SIMPLE)),
                            )
                            .clicked()
                        {
                            self.install_confirm = true;
                        }
                        if ui.button(format!("{}  Connection", icons::LINK)).clicked() {
                            self.show_settings = true;
                        }
                    });
                });
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(ctx.global_style().visuals.panel_fill)
                .inner_margin(egui::Margin::symmetric(14, 0)))
            .show_inside(root,|ui|{
   if self.run_confirm||self.install_confirm||self.force_confirm.is_some()||self.delete_dialog.is_some()||self.show_settings{ui.disable();}
   ui.add_space(11.0);
   egui::ScrollArea::vertical().id_salt("main-scroll").show(ui,|ui|{
    let left_width=((ui.available_width()-14.0)*0.424).clamp(280.0,520.0);
    ui.horizontal_top(|ui|{
     ui.allocate_ui_with_layout(egui::vec2(left_width,0.0),egui::Layout::top_down(egui::Align::Min),|ui|{
      card(ui,p,|ui|{
       ui.set_min_width(ui.available_width());
       section_title(ui,p,"01","Select a drive","Choose an attached image or attach a recent one.");
       let selected_label=self.disk().map(|d|format!("{}  —  {}", std::path::Path::new(&d.image_path).file_name().unwrap_or_default().to_string_lossy(), d.drive)).unwrap_or_else(||"Choose an attached VHDX".to_owned());
       let mut selected_text=egui::text::LayoutJob::default();
       let color=ui.visuals().text_color();
       selected_text.append(icons::HARD_DRIVE,0.0,egui::TextFormat{font_id:egui::FontId::proportional(20.0),color,valign:egui::Align::Center,..Default::default()});
       selected_text.append(&format!("  {selected_label}"),0.0,egui::TextFormat{font_id:egui::FontId::proportional(14.0),color,valign:egui::Align::Center,..Default::default()});
       let labels:Vec<(usize,String)>=self.disks.iter().enumerate().map(|(i,d)|(i,format!("{}  —  {}",std::path::Path::new(&d.image_path).file_name().unwrap_or_default().to_string_lossy(),d.drive))).collect();let mut selection=None;
       ui.add_enabled_ui(!self.busy&&!self.running,|ui|{
        egui::ComboBox::from_id_salt("attached-vhdx").width(ui.available_width().max(180.0)).selected_text(selected_text).show_ui(ui,|ui|{for (i,label) in &labels{if ui.selectable_label(self.selected==Some(*i),label).clicked(){selection=Some(*i);}}});
       });
       if let Some(i)=selection {if self.selected!=Some(i){self.select_disk(i);}}
       ui.horizontal_wrapped(|ui|{
        if ui.add_enabled(!self.busy&&!self.running,egui::Button::new(icons::ARROWS_CLOCKWISE)).on_hover_text("Refresh attached VHDX drives").clicked(){self.find_disks();}
        if ui.add_enabled(self.selected.is_some()&&!self.busy&&!self.detached&&!self.running,egui::Button::new("Reload top level")).on_hover_text("Reload only the drive's immediate entries").clicked(){if let Some(i)=self.selected{self.select_disk(i);}}
        ui.add_enabled_ui(!self.busy&&!self.running,|ui|{ui.menu_button("Recent / attach",|ui|{
         ui.set_max_width(360.0);
         ui.label(heading("Recent images").size(14.0));
         ui.label(RichText::new("Network images use the configured share.").color(p.muted).size(12.0));
         if self.recent_images.is_empty(){ui.weak("No images recorded by this app yet.");}
         for path in self.recent_images.clone(){if ui.add(egui::Button::new(format!("Attach {path}")).truncate()).on_hover_text(&path).clicked(){ui.close();self.mount(path);}}
         ui.separator();if ui.button("Browse for VHDX…").clicked(){ui.close();if let Some(path)=rfd::FileDialog::new().add_filter("Disk image",&["vhdx","vhd"]).pick_file(){self.mount(path.to_string_lossy().into_owned());}}
        });});
        if self.busy{ui.spinner();}
       });
       if self.selected.is_some() && !self.tree.contains_key(""){ui.label(RichText::new(if self.loading.contains(""){"Loading top-level items…"}else{"Top level unavailable; use Reload to retry."}).color(p.muted).size(11.5));}
      });
      ui.add_space(12.0);
      card(ui,p,|ui|{
       ui.set_min_width(ui.available_width());
       ui.horizontal(|ui| {
        ui.label(heading("02").color(p.accent).size(17.0)); ui.label(heading("Close & detach").size(18.0));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
         if ui.add_enabled(self.selected.is_some()&&!self.detached&&!self.scan_busy&&!self.busy,egui::Button::new(icons::ARROWS_CLOCKWISE)).on_hover_text("Refresh the partial process check").clicked(){self.refresh_processes();}
         if self.scan_busy {ui.spinner();} if self.detached {ui.colored_label(p.accent,"Detached");}
        });
       });
       ui.label(RichText::new("Review programs using the drive before detaching.").color(p.muted).size(13.0));
       egui::ScrollArea::vertical().id_salt("processes").max_height(74.0).show(ui,|ui|{
        if self.processes.is_empty(){ui.weak(if self.selected.is_none(){"Select a drive to check for programs."}else if self.scan_busy{"Checking running programs…"}else{"No programs found by the partial check."});}
        for process in self.processes.clone(){
         egui::Frame::new().fill(ui.visuals().widgets.inactive.bg_fill).stroke(egui::Stroke::new(1.0_f32,p.border)).corner_radius(6.0).inner_margin(egui::Margin::symmetric(8,4)).show(ui,|ui|{
          let process_bg = ui.visuals().widgets.inactive.bg_fill;
          let process_ink = readable_during_transition(ui.visuals().text_color(), process_bg, blend);
          ui.visuals_mut().override_text_color = Some(process_ink);
          ui.set_min_width(ui.available_width());
          ui.horizontal(|ui| {
           ui.label(RichText::new(icons::ARTICLE).size(20.0));
           let name_width = (ui.available_width() - 154.0).max(40.0);
           ui.vertical(|ui| {
            ui.set_width(name_width);
            ui.add(egui::Label::new(&process.name).truncate()).on_hover_text(&process.name);
            ui.label(RichText::new(format!("PID {}",process.pid)).color(readable_during_transition(p.muted, process_bg, blend)).size(11.5));
           });
           ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui| {
            if ui.button(RichText::new(format!("{} Force", icons::LIGHTNING)).color(if blend >= 1.0 {Color32::from_rgb(83,111,0)} else {readable_during_transition(p.accent, process_bg, blend)})).clicked(){self.force_confirm=Some(process.clone());}
            if ui.button(format!("{} Close", icons::X)).on_hover_text("Ask the program's windows to close").clicked(){self.action(process.clone(),false);}
           });
          });
         });
        }
       });
       ui.add_space(4.0);
       ui.horizontal(|ui| { ui.label(RichText::new(icons::INFO).color(p.muted).size(17.0)); ui.add(egui::Label::new(RichText::new("Process checks are partial and can miss handles, especially in unopened folders.").color(p.muted).size(12.0)).wrap()); });
       ui.separator();
       if !self.scan_warning.is_empty(){egui::CollapsingHeader::new("Check coverage").show(ui,|ui|{ui.weak(&self.scan_warning);});}
       ui.add_space(6.0);
       let can_detach=self.selected.is_some()&&self.tree.contains_key("")&&!self.busy&&!self.scan_busy&&self.loading.is_empty()&&!self.detached&&!self.running;
       if ui.add_enabled(can_detach,egui::Button::new(format!("{}  Detach VHDX",icons::EJECT))).clicked(){self.detach();}
       ui.label(RichText::new("Detaching does not close programs. Administrator access required.").color(p.muted).size(11.0));
       ui.add_space(2.0);
      });
     });
     ui.add_space(10.0);
     ui.vertical(|ui|{card(ui,p,|ui|{
      ui.set_min_width(ui.available_width());section_title(ui,p,"03","Choose what to copy","Open folders to load them. Select a file or folder before detaching.");
      let mut search_hint=egui::text::LayoutJob::default();
      search_hint.append(icons::MAGNIFYING_GLASS,0.0,egui::TextFormat{font_id:egui::FontId::proportional(17.0),color:p.muted,valign:egui::Align::Center,..Default::default()});
      search_hint.append("  Search loaded items",0.0,egui::TextFormat{font_id:egui::FontId::proportional(14.0),color:p.muted,valign:egui::Align::Center,..Default::default()});
      ui.add(egui::TextEdit::singleline(&mut self.search).hint_text(search_hint).desired_width(ui.available_width()));
      egui::Frame::new().fill(p.inner).stroke(egui::Stroke::new(1.0_f32,p.border)).corner_radius(5.0).inner_margin(6.0).show(ui,|ui|{
       ui.set_min_width(ui.available_width());if self.tree.contains_key(""){ui.add_enabled_ui(!self.busy&&!self.running,|ui|{self.show_tree(ui,p);});}else{let empty_height=(ui.ctx().content_rect().height()-470.0).clamp(95.0,130.0);ui.set_min_height(empty_height);ui.weak(if self.loading.contains(""){"Loading the top level…"}else if self.selected.is_some(){"Could not load. Use Reload top level to retry."}else{"Select a drive to see its top-level items."});}
      });
      if !self.search.is_empty(){ui.label(RichText::new("Filter searches only folders you have opened.").color(p.muted).size(11.0));}
      if self.detached{ui.label(RichText::new("Detached: previously opened folders remain available.").color(p.muted).size(11.0));}
      ui.add_space(4.0);ui.label(heading("Destination (server share)"));
      ui.horizontal(|ui| {
       let field_width=(ui.available_width()-88.0).max(90.0);
       egui::Frame::new().fill(p.inner).stroke(egui::Stroke::new(1.0_f32,p.border)).corner_radius(5.0)
        .inner_margin(egui::Margin::symmetric(8,0)).show(ui,|ui| {
         ui.set_width((field_width-16.0).max(70.0));
         ui.horizontal(|ui| {
          ui.label(RichText::new(icons::HARD_DRIVES).size(16.0));
          ui.add(egui::TextEdit::singleline(&mut self.destination).frame(egui::Frame::new())
           .desired_width(ui.available_width()).hint_text("Choose an SMB folder…"));
         });
        });
       if ui.button("Browse…").clicked(){if let Some(path)=rfd::FileDialog::new().pick_folder(){self.destination=path.display().to_string();}}
      });
      let command_result=self.disk().map(|d|command(&self.config.copy_ssh,&self.config.share,&self.config.guest_root,d,&self.source,&self.destination));
      // The next step remains visible at all times, including to keyboard and touch users.
      // Never place an arbitrary path or backend error in this compact button.
      let (short_blocker, detail)=if self.disk().is_none(){(Some("Choose a drive"),None)}
       else if self.running||self.busy||self.scan_busy||self.setup_busy||!self.loading.is_empty(){(Some("Wait for the current operation"),None)}
       else if !self.copy_ready{(Some("Complete host setup"),None)}
       else if !self.tree.contains_key(""){(Some("Load the top level"),None)}
       else if !self.source_selected{(Some("Select a source"),None)}
       else if self.destination.is_empty(){(Some("Choose a destination"),None)}
       else if !self.detached{(Some("Detach the VHDX first"),None)}
       else if let Some(Err(e))=&command_result{(Some("Check connection or paths"),Some(e.clone()))}
       else{(None,None)};
      let enabled=short_blocker.is_none();let fill=if enabled{p.accent_fill}else{ui.visuals().widgets.inactive.bg_fill};
      let text=if enabled{RichText::new(format!("{}  Review copy",icons::PLAY)).strong().color(Color32::BLACK)}
       else{RichText::new(format!("{}  Review copy   ·   {}",icons::PLAY,short_blocker.unwrap_or("Unavailable"))).color(p.muted).size(12.0)};
      let review=ui.scope(|ui| {ui.visuals_mut().disabled_alpha=1.0;ui.add_enabled(enabled,egui::Button::new(text).fill(fill).min_size(egui::vec2(ui.available_width(),36.0)))}).inner;
      if review.clicked(){self.run_confirm=true;}
      if let Some(error)=detail {egui::CollapsingHeader::new("Connection or path details").show(ui,|ui| {ui.label(error);});}
      ui.horizontal_wrapped(|ui| { ui.label(RichText::new(icons::LOCK_SIMPLE).color(p.accent).size(16.0)); ui.label(RichText::new("Matching files are replaced; the original remains inside the VHDX image.").size(12.0)); });
      ui.label(RichText::new("To delete from the image after detaching, first verify its host guard in Host setup.").color(p.muted).size(11.0));
      if !self.logs.is_empty(){egui::CollapsingHeader::new("Copy log").show(ui,|ui|{egui::ScrollArea::vertical().max_height(80.0).show(ui,|ui|{for line in &self.logs{ui.monospace(line);}});});}
     });});
    });
   });
  });
        if self.show_settings {
            egui::Window::new("Host setup")
                .collapsible(false).default_width(540.0)
                .show(&ctx, |ui| {
                    if self.guard_install_confirm { ui.disable(); }
                    ui.set_max_width(560.0);
                    egui::ScrollArea::vertical()
                        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                        .max_height((ctx.content_rect().height() - 150.0).max(220.0))
                        .show(ui, |ui| {
                            section_title(ui, p, "01", "Server-side copy", "Connect your Windows share to its Linux host.");
                            ui.label(RichText::new("Use an existing SSH key and trusted host key. Passwords and private keys are never stored here.").color(p.muted).size(13.0));
                            ui.add_space(4.0);
                            let old = self.config.clone();
                            inset(ui, p, |ui| {
                                ui.add_enabled_ui(!self.setup_busy, |ui| {
                                    egui::Grid::new("connection-grid").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                                        ui.label("SSH user@host"); ui.text_edit_singleline(&mut self.config.copy_ssh); ui.end_row();
                                        ui.label("Windows UNC share"); ui.text_edit_singleline(&mut self.config.share); ui.end_row();
                                        ui.label("Linux share directory"); ui.text_edit_singleline(&mut self.config.guest_root); ui.end_row();
                                    });
                                });
                            });
                            if self.config != old { self.copy_ready=false; self.guard_verified=None; self.setup_generation=self.setup_generation.wrapping_add(1); }
                            let old_guard = self.config.clone();
                            ui.add_space(8.0);
                            ui.label(heading("Copy helper").size(15.0));
                            ui.label(RichText::new("Install the bundled helper, then check the connection. Installation may download Python packages and will not run sudo.").color(p.muted).size(13.0));
                            ui.horizontal_wrapped(|ui| {
                                if ui.add_enabled(!self.setup_busy, primary_action("Install copy helper", p)).clicked() { self.start_host_setup(true); }
                                if ui.add_enabled(!self.setup_busy, egui::Button::new("Check copy helper")).clicked() { self.start_host_setup(false); }
                                if self.setup_busy { ui.spinner(); }
                            });
                            ui.label(RichText::new(&self.setup_message).color(if self.copy_ready { p.accent } else { p.muted }).size(13.0));
                            egui::CollapsingHeader::new("Root preparation, if needed").show(ui, |ui| {
                                ui.label("If the coordination directory is missing, run this command on the host as an administrator, then install again.");
                                let root_command=setup::root_command(&self.config);
                                if ui.button("Copy root preparation command").clicked() { ctx.copy_text(root_command.clone()); }
                                egui::CollapsingHeader::new("Inspect command").show(ui, |ui| {
                                    egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| { ui.monospace(&root_command); });
                                });
                            });
                            ui.add_space(12.0);
                            section_title(ui, p, "02", "Guarded operations", "Optional setup for deletion and network mounting.");
                            egui::CollapsingHeader::new("Configure host write guard").show(ui, |ui| {
                                ui.label(RichText::new("Samba may run on the Linux host or in a Proxmox LXC guest. Both modes require guest SMB with an empty password on a trusted network; authenticated SMB is not yet supported.").color(p.muted).size(13.0));
                                inset(ui, p, |ui| {
                                    ui.add_enabled_ui(!self.setup_busy, |ui| {
                                        egui::Grid::new("guard-settings").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                                            ui.label("Host SSH user@host"); ui.text_edit_singleline(&mut self.config.delete_ssh); ui.end_row();
                                            ui.label("Host share directory"); ui.text_edit_singleline(&mut self.config.host_root); ui.end_row();
                                            ui.label("LXC ID (blank for local)"); ui.text_edit_singleline(&mut self.config.guard_container_id); ui.end_row();
                                            ui.label("Guest SMB username"); ui.text_edit_singleline(&mut self.config.guard_guest_username); ui.end_row();
                                            ui.label("Host guard helper"); ui.monospace("/opt/vhdx-handoff-v1/vhdx_delete.py"); ui.end_row();
                                        });
                                        ui.checkbox(&mut self.config.guard_guest_smb_acknowledged, "I understand guest SMB uses an empty password and must be restricted to a trusted network.");
                                    });
                                });
                                let verified_for_image = self.config == old_guard && guard_verified_for_image(
                                    self.detached, self.guard_verified.as_deref(), self.disk().map(|d|d.image_path.as_str()));
                                ui.horizontal_wrapped(|ui| {
                                    let install=ui.add_enabled(!self.setup_busy && !verified_for_image, egui::Button::new("Install bundled guard…"));
                                    let install=if verified_for_image { install.on_disabled_hover_text("The guard is already verified for this image; no reinstall is needed.") } else { install };
                                    if install.clicked() { self.guard_install_confirm=true; }
                                    if ui.add_enabled(!self.setup_busy && self.detached && self.selected.is_some(), egui::Button::new("Verify detached image")).clicked() { self.start_guard_check(); }
                                    if self.setup_busy { ui.spinner(); }
                                });
                                if verified_for_image { ui.label(RichText::new("Guard verified for this image; no reinstall is needed.").color(p.accent).size(13.0)); }
                                else { ui.label(RichText::new(&self.guard_message).color(p.muted).size(13.0)); }
                                ui.weak("Other network locations remain blocked. External mount tools can bypass this app's checks.");
                            });
                            if self.config != old_guard { self.copy_ready=false; self.guard_verified=None; self.setup_generation=self.setup_generation.wrapping_add(1); }
                            ui.add_space(4.0);
                            ui.label(RichText::new("Local image mounting remains available. Connection settings are stored per-user; SSH keys and passwords are not stored here.").color(p.muted).size(12.0));
                        });
                    ui.separator();
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Refresh mapped drives").clicked() { thread::spawn(refresh_mappings); }
                        if ui.add(primary_action("Save settings", p)).clicked() { match self.config.save() { Ok(()) => self.setup_message="Settings saved. Check the helper before copying.".into(), Err(e) => self.setup_message=e } }
                        if ui.button("Close").clicked() { self.show_settings=false; }
                    });
                });
        }
        if self.guard_install_confirm {
            egui::Window::new("Install host write guard?").collapsible(false).resizable(false).default_width(480.0).show(&ctx, |ui| {
                ui.set_max_width(500.0);
                egui::ScrollArea::vertical().max_height((ctx.content_rect().height() - 140.0).max(180.0)).show(ui, |ui| {
                section_title(ui, p, "01", "Review host setup", "Confirm the connection before installing the guard.");
                inset(ui, p, |ui| {
                    dialog_label(ui,p,"Host SSH",&self.config.delete_ssh);
                    dialog_label(ui,p,"Host share",&self.config.host_root);
                    dialog_label(ui,p,"Guest share",&self.config.guest_root);
                    dialog_label(ui,p,"Windows share",&self.config.share);
                    dialog_label(ui,p,"Samba location",&format!("{} · {}", if self.config.guard_container_id.is_empty() { "On host".to_owned() } else { format!("LXC {}",self.config.guard_container_id) },self.config.guard_guest_username));
                });
                ui.label(RichText::new("Scroll paths horizontally to see the full value.").color(p.muted).size(12.0));
                ui.add_space(6.0);
                ui.label("Installs hash-verified files as root into /opt/vhdx-handoff-v1 and /etc/vhdx-handoff-v1. Existing installations are never overwritten.");
                ui.label(RichText::new("Requires root SSH or noninteractive sudo, and guest SMB on a trusted network. No password is requested or stored.").color(p.muted).size(13.0));
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() { self.guard_install_confirm=false; }
                    if ui.add(primary_action("Install guard",p)).clicked() { self.guard_install_confirm=false; self.start_guard_install(); }
                });
            });
        }
        if let Some(dialog) = self.delete_dialog.as_mut() {
            match dialog.show(&ctx, p) {
                delete_ui::DeleteOutcome::Pending => {}
                delete_ui::DeleteOutcome::Cancelled => self.delete_dialog = None,
                delete_ui::DeleteOutcome::Confirmed(target) => {
                    self.delete_dialog = None;
                    if self.detached
                        && !self.busy
                        && !self.running
                        && !self.scan_busy
                        && self.loading.is_empty()
                        && self
                            .disk()
                            .is_some_and(|d| d.image_path.eq_ignore_ascii_case(&target.image_path))
                    {
                        self.begin_delete(target);
                    } else {
                        self.status = "Disk state changed; select the item again.".into();
                    }
                }
            }
        }
        if self.install_confirm {
            egui::Window::new("Install for this user?").collapsible(false).resizable(false).default_width(430.0).show(&ctx, |ui| {
                ui.set_max_width(460.0);
                section_title(ui,p,"01","Install VHDrop","Add the app to your Windows account.");
                inset(ui,p,|ui| {
                    ui.label("Install the app in your user Programs folder.");
                    ui.label("Add a Start menu shortcut and per-user VHD/VHDX Explorer actions.");
                });
                ui.add_space(6.0);
                ui.label(RichText::new("Existing copies or shortcuts with the same name will be replaced.").color(p.muted).size(13.0));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() { self.install_confirm=false; }
                    if ui.add(primary_action("Install",p)).clicked() { self.install_confirm=false; self.installing=true; let tx=self.tx.clone(); thread::spawn(move||{let _=tx.send(Event::Installed(install::install()));}); }
                });
            });
        }
        if let Some(process) = self.force_confirm.clone() {
            egui::Window::new("Force quit program?").collapsible(false).resizable(false).default_width(430.0).show(&ctx, |ui| {
                ui.set_max_width(460.0);
                section_title(ui,p,"!","Force quit", "This program may have unsaved work.");
                inset(ui,p,|ui| {
                    dialog_label(ui,p,"Program",&process.name);
                    dialog_label(ui,p,"Process ID",&process.pid.to_string());
                });
                ui.add_space(8.0);
                ui.label("Force quitting can cause unsaved changes to be lost.");
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() { self.force_confirm=None; }
                    if ui.add(egui::Button::new(heading("Force quit").color(Color32::WHITE)).fill(Color32::from_rgb(170,48,43)).min_size(egui::vec2(105.0,31.0))).clicked() {
                        self.action(process.clone(),true); self.force_confirm=None;
                    }
                });
            });
        }
        if self.run_confirm {
            egui::Window::new("Review copy").collapsible(false).resizable(false).default_width(500.0).show(&ctx, |ui| {
                ui.set_max_width(520.0);
                egui::ScrollArea::vertical().max_height((ctx.content_rect().height()-140.0).max(180.0)).show(ui, |ui| {
                    section_title(ui,p,"01","Review your copy", "Confirm the image, source, and destination.");
                    inset(ui,p,|ui| {
                        if let Some(d)=self.disk() { dialog_label(ui,p,"Image",&d.image_path); }
                        dialog_label(ui,p,"Source",if self.source.is_empty(){"Entire drive"}else{&self.source});
                        dialog_label(ui,p,"Destination",&self.destination);
                        if let Some(d)=self.disk() {
                            if let Ok(image)=translate(&d.image_path,&self.config.share,&self.config.guest_root) { dialog_label(ui,p,"Host image",&image); }
                            if let Ok(dest)=translate(&self.destination,&self.config.share,&self.config.guest_root) { dialog_label(ui,p,"Host destination",&dest); }
                        }
                    });
                    ui.label(RichText::new("Scroll paths horizontally to see the full value.").color(p.muted).size(12.0));
                    ui.add_space(8.0);
                    ui.label("Matching files will be replaced. Keep the VHDX detached on every computer until the copy finishes.");
                    ui.label(RichText::new("Temporary probes check both server mappings. Both directories need write and delete access; a network failure could leave a probe behind.").color(p.muted).size(13.0));
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() { self.run_confirm=false; }
                    let can_start = self.copy_ready && !self.busy && !self.scan_busy && self.loading.is_empty() && self.detached && !self.running
                        && self.disk().is_some_and(|d| command(&self.config.copy_ssh,&self.config.share,&self.config.guest_root,d,&self.source,&self.destination).is_ok());
                    let start = ui.add_enabled(can_start, primary_action("Start copy",p));
                    let start = if can_start { start } else { start.on_disabled_hover_text("Check the connection, paths, and detached image before copying.") };
                    if start.clicked() {
                        if let Some(d)=self.disk() { if let Ok((remote,_))=command(&self.config.copy_ssh,&self.config.share,&self.config.guest_root,d,&self.source,&self.destination) { self.run(remote); } }
                        self.run_confirm=false;
                    }
                });
            });
        }

    }
}

fn main() -> eframe::Result {
    let mut args = std::env::args_os();
    let _ = args.next();
    if args.next().as_deref() == Some(std::ffi::OsStr::new("--check-before-mount")) {
        let result = args
            .next()
            .ok_or_else(|| "Missing image path.".to_string())
            .and_then(|path| delete_job::check_before_mount(&path.to_string_lossy()));
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }
    eframe::run_native(
        "VHDrop",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([900.0, 600.0])
                .with_icon(egui::IconData { rgba: include_bytes!("../assets/app.rgba").to_vec(), width: 256, height: 256 })
                .with_min_inner_size([720.0, 560.0]),
            ..Default::default()
        },
        Box::new(|cc| {
            let _ = native_chrome::simplify_caption(cc);
            initialize_fonts(&cc.egui_ctx);
            Ok(Box::new(App::default()))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transition_has_intermediate_steps_at_sixty_hz() {
        let ctx = egui::Context::default();
        let mut values = Vec::new();
        for frame in 0..=10 {
            let time = frame as f64 / 60.0;
            let target = if frame == 0 { 0.0 } else { 1.0 };
            let _ = ctx.run_ui(egui::RawInput { time: Some(time), ..Default::default() }, |ui| {
                values.push(ui.ctx().animate_value_with_time(
                    egui::Id::new("sixty-hz-theme"), target, THEME_TRANSITION_SECONDS,
                ));
            });
        }
        assert!(values.iter().filter(|&&v| v > 0.0 && v < 1.0).count() >= 4);
        assert_eq!(values.last(), Some(&1.0));
    }
    #[test]
    fn blended_palette_keeps_endpoints_and_intermediate_contrast() {
        assert_eq!(blended_palette(0.0).card, palette(false).card);
        assert_eq!(blended_palette(1.0).card, palette(true).card);
        assert_eq!(blended_palette(0.0).accent, palette(false).accent);
        assert_eq!(blended_palette(1.0).accent, palette(true).accent);
        for i in 1..100 {
            let t = i as f32 / 100.0;
            let p = blended_palette(t);
            assert!(color_contrast(p.muted, p.card) >= 4.5);
            assert!(color_contrast(p.accent, p.card) >= 4.5);
            let selection = mix_color(Color32::from_rgb(61,73,23), Color32::from_rgb(224,236,156), t);
            let preferred = mix_color(Color32::from_rgb(232,234,231), Color32::from_rgb(28,30,28), t);
            let ink = readable_during_transition(preferred, selection, t);
            assert!(color_contrast(ink, selection) >= 4.5);
            let process = mix_color(Color32::from_rgb(42,44,44), Color32::from_rgb(246,245,243), t);
            assert!(color_contrast(readable_during_transition(preferred, process, t), process) >= 4.5);
        }
    }
    #[test]
    fn palette_and_slider_retarget_at_same_speed() {
        let ctx = egui::Context::default();
        let mut values = Vec::new();
        for (time, palette_target, slider_target) in [(0.0,0.0,0.0), (0.016,1.0,2.0), (0.048,1.0,2.0), (0.052,0.0,0.0), (0.08,0.0,0.0)] {
            let _ = ctx.run_ui(egui::RawInput { time: Some(time), ..Default::default() }, |ui| {
                let ctx = ui.ctx();
                values.push((ctx.animate_value_with_time(egui::Id::new("test-palette"),palette_target,THEME_TRANSITION_SECONDS),
                             ctx.animate_value_with_time(egui::Id::new("test-slider"),slider_target,THEME_TRANSITION_SECONDS)));
            });
        }
        assert!(values[2].0 > 0.0 && values[2].0 < 1.0);
        for (palette, slider) in values { assert!((slider - 2.0 * palette).abs() < 0.001); }
    }
    #[test]
    fn guard_install_guidance_never_treats_existence_as_verified() {
        let error="VHDX_HANDOFF_GUARD_ERROR: Existing helper/configuration not overwritten; inspect it before any upgrade (SSH exit: exit code: 1)";
        let message=guard_install_result(Err(error.into()));
        assert!(message.contains("has not been checked"));
        assert!(message.contains("Verify detached image"));
        assert_eq!(guard_install_result(Err("network error".into())),"Guard install failed: network error");
        assert_eq!(guard_install_result(Ok("installed".into())),"installed");
    }
    #[test]
    fn guard_install_disabled_only_for_the_verified_detached_image() {
        assert!(guard_verified_for_image(true,Some(r"C:\DISK.VHDX"),Some(r"c:\disk.vhdx")));
        assert!(!guard_verified_for_image(false,Some("disk"),Some("disk")));
        assert!(!guard_verified_for_image(true,Some("disk"),Some("other")));
        assert!(!guard_verified_for_image(true,None,Some("disk")));
        assert!(!guard_verified_for_image(true,Some("disk"),None));
    }
    #[test]
    fn shell_quote() {
        assert_eq!(quote("a'b"), "'a'\\''b'");
    }
    #[test]
    fn share_boundary() {
        assert_eq!(
            translate(r"\\server\Media\Projects\A", r"\\server\Media", "/mnt/media").unwrap(),
            "/mnt/media/Projects/A"
        );
        assert!(translate(r"\\server\Media2\x", r"\\server\Media", "/mnt/media").is_err());
    }
}

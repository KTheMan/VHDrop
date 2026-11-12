//! Explicit two-step confirmation for an item inside a detached VHDX.
//!
//! This module only produces an intent. It performs no filesystem, disk-image,
//! network, process, or server operations. The caller must independently check
//! attachment state and validate the target again before executing the intent.
use eframe::egui::{self, RichText};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteTarget {
    pub image_path: String,
    /// Exact path relative to the VHDX volume root; never the root itself.
    pub relative_path: String,
    pub is_dir: bool,
}

impl DeleteTarget {
    /// Reject root, absolute, ADS, control-character and traversal targets.
    pub fn new(image_path: String, relative_path: String, is_dir: bool) -> Result<Self, String> {
        let image = std::path::Path::new(&image_path);
        let extension = image.extension().and_then(|s| s.to_str()).unwrap_or("");
        if !image.is_absolute()
            || image_path.chars().any(char::is_control)
            || !extension.eq_ignore_ascii_case("vhdx")
        {
            return Err("Host deletion requires an absolute .vhdx image path.".into());
        }
        if relative_path.is_empty()
            || relative_path.starts_with(['\\', '/'])
            || relative_path.chars().any(char::is_control)
            || relative_path.contains(':')
        {
            return Err("Choose a file or folder inside the drive, not the drive root.".into());
        }
        for component in relative_path.split(['\\', '/']) {
            if component.is_empty()
                || component == "."
                || component == ".."
                || component.ends_with([' ', '.'])
                || component
                    .chars()
                    .any(|c| matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
            {
                return Err("The selected item has an unsafe or unsupported path.".into());
            }
        }
        Ok(Self {
            image_path,
            relative_path,
            is_dir,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Review,
    TypeDelete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteOutcome {
    Pending,
    Cancelled,
    /// User completed both gates; caller still must recheck safety.
    Confirmed(DeleteTarget),
}

pub struct DeleteDialog {
    target: DeleteTarget,
    stage: Stage,
    typed: String,
}

impl DeleteDialog {
    pub fn new(target: DeleteTarget) -> Self {
        Self {
            target,
            stage: Stage::Review,
            typed: String::new(),
        }
    }

    /// Show the current gate and return a user intent, never perform deletion.
    /// Keep the caller's underlying window disabled while this dialog is present.
    pub fn show(&mut self, ctx: &egui::Context, p: crate::Palette) -> DeleteOutcome {
        let mut outcome = DeleteOutcome::Pending;
        let (title, step, heading) = match self.stage {
            Stage::Review => ("Delete from VHDX?", "01", "Review target"),
            Stage::TypeDelete => ("Confirm permanent deletion", "02", "Final confirmation"),
        };
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .default_width(460.0)
            .show(ctx, |ui| {
                // Keep the content compact on small screens and cap path width so a
                // very long filename cannot expand the confirmation off-screen.
                let width = (ctx.content_rect().width() - 64.0).clamp(240.0, 460.0);
                ui.set_max_width(width);
                egui::ScrollArea::vertical()
                    .max_height((ctx.content_rect().height() - 150.0).max(180.0))
                    .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(crate::heading(step).size(17.0).color(p.accent));
                    ui.label(crate::heading(heading).size(18.0));
                });
                let summary = if self.target.is_dir {
                    "The folder and everything inside it will be permanently deleted."
                } else {
                    "The selected file will be permanently deleted."
                };
                ui.label(RichText::new(summary).color(p.muted).size(13.0));
                ui.add_space(8.0);
                egui::Frame::new()
                    .fill(p.inner)
                    .stroke(egui::Stroke::new(1.0_f32, p.border))
                    .corner_radius(6.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.set_min_width((width - 22.0).max(0.0));
                        ui.label(RichText::new("IMAGE").color(p.muted).size(11.0));
                        egui::ScrollArea::horizontal()
                            .id_salt("delete_image_path")
                            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                            .max_height(30.0)
                            .show(ui, |ui| { ui.add(egui::Label::new(&self.target.image_path).wrap_mode(egui::TextWrapMode::Extend)); });
                        ui.add_space(5.0);
                        ui.label(RichText::new(if self.target.is_dir { "FOLDER" } else { "FILE" }).color(p.muted).size(11.0));
                        egui::ScrollArea::horizontal()
                            .id_salt("delete_item_path")
                            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                            .max_height(30.0)
                            .show(ui, |ui| { ui.add(egui::Label::new(&self.target.relative_path).wrap_mode(egui::TextWrapMode::Extend)); });
                    });
                ui.label(RichText::new("Scroll paths horizontally to see the full value.").color(p.muted).size(12.0));
                ui.add_space(5.0);
                ui.label(RichText::new("No Recycle Bin").strong());
                ui.label(RichText::new("Keep the image detached on every computer, and stop any local host process using it, until deletion completes.").color(p.muted).size(13.0));
                    });
                if self.stage == Stage::TypeDelete {
                    ui.add_space(8.0);
                    ui.label("Type DELETE to confirm:");
                    ui.add(egui::TextEdit::singleline(&mut self.typed).desired_width(200.0));
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() { outcome = DeleteOutcome::Cancelled; }
                    match self.stage {
                        Stage::Review => {
                            let button = egui::Button::new(RichText::new("Continue…").color(egui::Color32::from_rgb(25, 30, 14)).strong()).fill(p.accent_fill);
                            if ui.add(button).clicked() { self.stage = Stage::TypeDelete; }
                        }
                        Stage::TypeDelete => {
                            let confirmed = self.typed == "DELETE";
                            let label = RichText::new("Delete permanently").strong();
                            let button = if confirmed {
                                egui::Button::new(label.color(egui::Color32::WHITE))
                                    .fill(egui::Color32::from_rgb(160, 42, 47))
                            } else { egui::Button::new(label) };
                            if ui.add_enabled(confirmed, button).clicked() {
                                outcome = DeleteOutcome::Confirmed(self.target.clone());
                            }
                        }
                    }
                });
            });
        outcome
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    const IMAGE: &str = r"\\server\share\disk.vhdx";

    #[test]
    fn accepts_exact_file_and_folder_paths() {
        let file = DeleteTarget::new(IMAGE.into(), r"Example\bin\app.exe".into(), false).unwrap();
        assert_eq!(file.relative_path, r"Example\bin\app.exe");
        assert!(!file.is_dir);
        assert!(
            DeleteTarget::new(IMAGE.into(), "Example".into(), true)
                .unwrap()
                .is_dir
        );
    }

    #[test]
    fn rejects_root_absolute_traversal_and_ads_paths() {
        for path in [
            "",
            "\\",
            "/",
            r"\Windows",
            r"C:\Windows",
            "../outside",
            r"..\outside",
            r"a\..\outside",
            r"a\.\b",
            r"a\\b",
            "a/",
            "a:secret",
            "a\nother",
            "trailing.",
        ] {
            assert!(
                DeleteTarget::new(IMAGE.into(), path.into(), false).is_err(),
                "accepted {path:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_image_paths() {
        for image in [
            "",
            "relative.vhdx",
            r"C:\path\file.txt",
            r"C:\path\legacy.vhd",
            "bad\n.vhdx",
        ] {
            assert!(
                DeleteTarget::new(image.into(), "file".into(), false).is_err(),
                "accepted {image:?}"
            );
        }
    }
}


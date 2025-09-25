#[cfg(feature = "gui")]
use crate::database::{open_database, ComponentQueries};
#[cfg(feature = "gui")]
use crate::types::{Component, ComponentType};
#[cfg(feature = "gui")]
use egui::{Context, Ui};
#[cfg(feature = "gui")]
use std::path::{Path, PathBuf};

#[cfg(feature = "gui")]
pub struct AnalyzerApp {
    db_path: PathBuf,
    components: Vec<Component>,
    selected_component: Option<String>,
    filter_text: String,
    selected_type: Option<ComponentType>,
    error_message: Option<String>,
}

#[cfg(feature = "gui")]
impl AnalyzerApp {
    pub fn new(db_path: &Path) -> Self {
        let mut app = Self {
            db_path: db_path.to_path_buf(),
            components: Vec::new(),
            selected_component: None,
            filter_text: String::new(),
            selected_type: None,
            error_message: None,
        };
        
        // Load initial data
        if let Err(e) = app.load_components() {
            app.error_message = Some(format!("Failed to load components: {}", e));
        }
        
        app
    }

    fn load_components(&mut self) -> anyhow::Result<()> {
        let db = open_database(&self.db_path)?;
        let conn = db.connection();
        
        self.components = if let Some(component_type) = &self.selected_type {
            ComponentQueries::get_by_type(conn, component_type.clone())?
        } else if !self.filter_text.is_empty() {
            ComponentQueries::get_by_name_pattern(conn, &self.filter_text)?
        } else {
            ComponentQueries::get_all(conn)?
        };
        
        Ok(())
    }

    fn show_component_list(&mut self, ui: &mut Ui) {
        ui.heading("Components");
        
        ui.horizontal(|ui| {
            ui.label("Filter:");
            if ui.text_edit_singleline(&mut self.filter_text).changed() {
                if let Err(e) = self.load_components() {
                    self.error_message = Some(format!("Failed to filter components: {}", e));
                }
            }
        });

        ui.horizontal(|ui| {
            ui.label("Type:");
            egui::ComboBox::from_label("Component Type")
                .selected_text(match &self.selected_type {
                    Some(t) => t.to_string(),
                    None => "All".to_string(),
                })
                .show_ui(ui, |ui| {
                    if ui.selectable_value(&mut self.selected_type, None, "All").changed() {
                        if let Err(e) = self.load_components() {
                            self.error_message = Some(format!("Failed to load components: {}", e));
                        }
                    }
                    for component_type in &[
                        ComponentType::Binary,
                        ComponentType::Function,
                        ComponentType::Instruction,
                        ComponentType::Process,
                        ComponentType::Host,
                        ComponentType::Network,
                    ] {
                        if ui.selectable_value(&mut self.selected_type, Some(component_type.clone()), component_type.to_string()).changed() {
                            if let Err(e) = self.load_components() {
                                self.error_message = Some(format!("Failed to load components: {}", e));
                            }
                        }
                    }
                });
        });

        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            for component in &self.components {
                let response = ui.selectable_label(
                    self.selected_component.as_ref() == Some(&component.id),
                    format!("{} ({})", component.name, component.component_type)
                );
                
                if response.clicked() {
                    self.selected_component = Some(component.id.clone());
                }
            }
        });
    }

    fn show_component_details(&self, ui: &mut Ui) {
        ui.heading("Component Details");
        
        if let Some(selected_id) = &self.selected_component {
            if let Some(component) = self.components.iter().find(|c| &c.id == selected_id) {
                ui.label(format!("Name: {}", component.name));
                ui.label(format!("Type: {}", component.component_type));
                ui.label(format!("ID: {}", component.id));
                
                if let Some(path) = &component.path {
                    ui.label(format!("Path: {}", path));
                }
                
                if let Some(hash) = &component.hash {
                    ui.label(format!("Hash: {}", hash));
                }
                
                ui.label(format!("Created: {}", component.created_at.format("%Y-%m-%d %H:%M:%S UTC")));
                ui.label(format!("Updated: {}", component.updated_at.format("%Y-%m-%d %H:%M:%S UTC")));
                
                if !component.metadata.is_empty() {
                    ui.separator();
                    ui.heading("Metadata");
                    for (key, value) in &component.metadata {
                        ui.label(format!("{}: {}", key, value));
                    }
                }
            }
        } else {
            ui.label("Select a component to view details");
        }
    }
}

#[cfg(feature = "gui")]
impl eframe::App for AnalyzerApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        let mut clear_error = false;
        if let Some(error) = &self.error_message {
            let error_msg = error.clone();
            egui::Window::new("Error")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(&error_msg);
                    if ui.button("OK").clicked() {
                        clear_error = true;
                    }
                });
        }
        if clear_error {
            self.error_message = None;
        }

        egui::SidePanel::left("component_list")
            .default_width(400.0)
            .show(ctx, |ui| {
                self.show_component_list(ui);
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            self.show_component_details(ui);
        });

        egui::TopBottomPanel::bottom("status")
            .default_height(30.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(format!("Components: {}", self.components.len()));
                    ui.separator();
                    ui.label(format!("Database: {}", self.db_path.display()));
                });
            });
    }
}
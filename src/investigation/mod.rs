#[cfg(feature = "gui")]
use crate::types::{Investigation, Component};
#[cfg(feature = "gui")]
use crate::database::{open_database};
#[cfg(feature = "gui")]
use egui::{Ui, TextEdit, ComboBox, ScrollArea, CollapsingHeader, RichText};
#[cfg(feature = "gui")]
use chrono::{DateTime, Utc};
#[cfg(feature = "gui")]
use std::path::Path;

#[cfg(feature = "gui")]
pub struct InvestigationManager {
    pub investigations: Vec<Investigation>,
    pub selected_investigation: Option<String>,
    pub new_investigation: NewInvestigationForm,
    pub show_new_form: bool,
    pub component_notes: std::collections::HashMap<String, ComponentNote>,
}

#[cfg(feature = "gui")]
#[derive(Default)]
pub struct NewInvestigationForm {
    pub title: String,
    pub description: String,
    pub investigator: String,
    pub priority: InvestigationPriority,
    pub component_id: Option<String>,
}

#[cfg(feature = "gui")]
#[derive(Debug, Clone, Default, PartialEq)]
pub enum InvestigationPriority {
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

#[cfg(feature = "gui")]
impl std::fmt::Display for InvestigationPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvestigationPriority::Low => write!(f, "Low"),
            InvestigationPriority::Medium => write!(f, "Medium"),
            InvestigationPriority::High => write!(f, "High"),
            InvestigationPriority::Critical => write!(f, "Critical"),
        }
    }
}

#[cfg(feature = "gui")]
#[derive(Debug, Clone)]
pub struct ComponentNote {
    pub component_id: String,
    pub note: String,
    pub investigator: String,
    pub created_at: DateTime<Utc>,
    pub tags: Vec<String>,
    pub suspicion_level: SuspicionLevel,
}

#[cfg(feature = "gui")]
#[derive(Debug, Clone, Default, PartialEq)]
pub enum SuspicionLevel {
    #[default]
    None,
    Low,
    Medium,
    High,
    Malicious,
}

#[cfg(feature = "gui")]
impl std::fmt::Display for SuspicionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SuspicionLevel::None => write!(f, "None"),
            SuspicionLevel::Low => write!(f, "Low"),
            SuspicionLevel::Medium => write!(f, "Medium"),
            SuspicionLevel::High => write!(f, "High"),
            SuspicionLevel::Malicious => write!(f, "Malicious"),
        }
    }
}

#[cfg(feature = "gui")]
impl InvestigationManager {
    pub fn new() -> Self {
        Self {
            investigations: Vec::new(),
            selected_investigation: None,
            new_investigation: NewInvestigationForm::default(),
            show_new_form: false,
            component_notes: std::collections::HashMap::new(),
        }
    }

    pub fn load_investigations(&mut self, db_path: &Path) -> anyhow::Result<()> {
        let db = open_database(db_path)?;
        let conn = db.connection();
        
        // Load investigations from database
        // Note: Using simplified query for now - would need proper implementation
        self.investigations.clear();
        
        // Add sample investigations for testing
        self.investigations.push(Investigation {
            id: "inv_001".to_string(),
            title: "Suspicious Network Activity".to_string(),
            description: "Binary shows unusual network connection patterns".to_string(),
            component_id: "comp_001".to_string(),
            investigator: Some("Security Analyst".to_string()),
            status: "Open".to_string(),
            findings: serde_json::json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        
        Ok(())
    }

    pub fn render(&mut self, ui: &mut Ui, selected_component: Option<&Component>) -> bool {
        let mut investigation_changed = false;

        ui.heading("Investigation Console");
        ui.separator();

        // Investigation controls
        ui.horizontal(|ui| {
            if ui.button("New Investigation").clicked() {
                self.show_new_form = !self.show_new_form;
                if let Some(comp) = selected_component {
                    self.new_investigation.component_id = Some(comp.id.clone());
                }
            }
            
            if ui.button("Refresh").clicked() {
                // Refresh investigations from database
                investigation_changed = true;
            }
        });

        ui.separator();

        // New investigation form
        if self.show_new_form {
            ui.group(|ui| {
                ui.heading("New Investigation");
                
                ui.horizontal(|ui| {
                    ui.label("Title:");
                    ui.text_edit_singleline(&mut self.new_investigation.title);
                });

                ui.horizontal(|ui| {
                    ui.label("Investigator:");
                    ui.text_edit_singleline(&mut self.new_investigation.investigator);
                });

                ui.horizontal(|ui| {
                    ui.label("Priority:");
                    ComboBox::from_label("")
                        .selected_text(self.new_investigation.priority.to_string())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.new_investigation.priority, InvestigationPriority::Low, "Low");
                            ui.selectable_value(&mut self.new_investigation.priority, InvestigationPriority::Medium, "Medium");
                            ui.selectable_value(&mut self.new_investigation.priority, InvestigationPriority::High, "High");
                            ui.selectable_value(&mut self.new_investigation.priority, InvestigationPriority::Critical, "Critical");
                        });
                });

                ui.label("Description:");
                ui.add(TextEdit::multiline(&mut self.new_investigation.description)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY));

                ui.horizontal(|ui| {
                    if ui.button("Create Investigation").clicked() {
                        self.create_investigation();
                        self.show_new_form = false;
                        investigation_changed = true;
                    }
                    
                    if ui.button("Cancel").clicked() {
                        self.show_new_form = false;
                        self.new_investigation = NewInvestigationForm::default();
                    }
                });
            });
            
            ui.separator();
        }

        // Current investigations list
        ui.heading("Active Investigations");
        ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
            for investigation in &self.investigations {
                let selected = self.selected_investigation.as_ref() == Some(&investigation.id);
                let response = ui.selectable_label(selected, &investigation.title);
                
                if response.clicked() {
                    self.selected_investigation = Some(investigation.id.clone());
                }
                
                ui.label(format!("Status: {} | Investigator: {}", 
                    investigation.status, 
                    investigation.investigator.as_deref().unwrap_or("Unknown")));
                ui.separator();
            }
        });

        // Investigation details
        if let Some(selected_id) = &self.selected_investigation {
            if let Some(investigation) = self.investigations.iter().find(|i| &i.id == selected_id) {
                ui.separator();
                self.render_investigation_details(ui, investigation);
            }
        }

        // Component notes section
        if let Some(component) = selected_component {
            ui.separator();
            self.render_component_notes(ui, component);
        }

        investigation_changed
    }

    fn render_investigation_details(&mut self, ui: &mut Ui, investigation: &Investigation) {
        CollapsingHeader::new("Investigation Details")
            .default_open(true)
            .show(ui, |ui| {
                ui.label(format!("ID: {}", investigation.id));
                ui.label(format!("Title: {}", investigation.title));
                ui.label(format!("Description: {}", investigation.description));
                ui.label(format!("Status: {}", investigation.status));
                ui.label(format!("Component: {}", investigation.component_id));
                
                if let Some(investigator) = &investigation.investigator {
                    ui.label(format!("Investigator: {}", investigator));
                }
                
                ui.label(format!("Created: {}", investigation.created_at.format("%Y-%m-%d %H:%M:%S UTC")));
                ui.label(format!("Updated: {}", investigation.updated_at.format("%Y-%m-%d %H:%M:%S UTC")));

                ui.separator();
                ui.label("Findings:");
                ui.add(TextEdit::multiline(&mut investigation.findings.to_string())
                    .desired_rows(5)
                    .desired_width(f32::INFINITY));

                ui.horizontal(|ui| {
                    if ui.button("Update Status").clicked() {
                        // Update investigation status
                    }
                    
                    if ui.button("Add Finding").clicked() {
                        // Add new finding
                    }
                    
                    if ui.button("Export Report").clicked() {
                        // Export investigation report
                    }
                });
            });
    }

    fn render_component_notes(&mut self, ui: &mut Ui, component: &Component) {
        CollapsingHeader::new("Component Notes")
            .default_open(false)
            .show(ui, |ui| {
                // Show existing notes
                if let Some(note) = self.component_notes.get(&component.id) {
                    ui.group(|ui| {
                        ui.label(format!("Note by {}", note.investigator));
                        ui.label(format!("Suspicion Level: {}", note.suspicion_level));
                        ui.label(format!("Created: {}", note.created_at.format("%Y-%m-%d %H:%M")));
                        
                        ui.separator();
                        ui.label(&note.note);
                        
                        if !note.tags.is_empty() {
                            ui.horizontal(|ui| {
                                ui.label("Tags:");
                                for tag in &note.tags {
                                    ui.label(RichText::new(tag).color(egui::Color32::BLUE));
                                }
                            });
                        }
                    });
                } else {
                    ui.label("No notes for this component");
                }

                ui.separator();
                
                // Add new note form
                ui.heading("Add Note");
                
                let mut new_note = String::new();
                let mut new_investigator = String::new();
                let mut suspicion_level = SuspicionLevel::None;
                
                ui.horizontal(|ui| {
                    ui.label("Investigator:");
                    ui.text_edit_singleline(&mut new_investigator);
                });
                
                ui.horizontal(|ui| {
                    ui.label("Suspicion Level:");
                    ComboBox::from_label("")
                        .selected_text(suspicion_level.to_string())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut suspicion_level, SuspicionLevel::None, "None");
                            ui.selectable_value(&mut suspicion_level, SuspicionLevel::Low, "Low");
                            ui.selectable_value(&mut suspicion_level, SuspicionLevel::Medium, "Medium");
                            ui.selectable_value(&mut suspicion_level, SuspicionLevel::High, "High");
                            ui.selectable_value(&mut suspicion_level, SuspicionLevel::Malicious, "Malicious");
                        });
                });
                
                ui.label("Note:");
                ui.add(TextEdit::multiline(&mut new_note)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY));

                if ui.button("Add Note").clicked() && !new_note.is_empty() && !new_investigator.is_empty() {
                    let note = ComponentNote {
                        component_id: component.id.clone(),
                        note: new_note,
                        investigator: new_investigator,
                        created_at: Utc::now(),
                        tags: Vec::new(),
                        suspicion_level,
                    };
                    
                    self.component_notes.insert(component.id.clone(), note);
                }
            });
    }

    fn create_investigation(&mut self) {
        let investigation = Investigation {
            id: format!("inv_{}", Utc::now().timestamp()),
            title: self.new_investigation.title.clone(),
            description: self.new_investigation.description.clone(),
            component_id: self.new_investigation.component_id.clone().unwrap_or_else(|| "unknown".to_string()),
            investigator: if self.new_investigation.investigator.is_empty() {
                None
            } else {
                Some(self.new_investigation.investigator.clone())
            },
            status: "Open".to_string(),
            findings: serde_json::json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        self.investigations.push(investigation);
        self.new_investigation = NewInvestigationForm::default();
    }
}

#[cfg(feature = "gui")]
impl Default for InvestigationManager {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "gui")]
use crate::types::{Component, Relationship, AnalysisResult, AnalysisType};
#[cfg(feature = "gui")]
use crate::database::{ComponentQueries, RelationshipQueries, AnalysisQueries};
#[cfg(feature = "gui")]
use egui::{Ui, TextEdit, ComboBox, ScrollArea, CollapsingHeader};

#[cfg(feature = "gui")]
pub struct ComponentDetailView {
    pub component: Option<Component>,
    pub relationships: Vec<Relationship>,
    pub analysis_results: Vec<AnalysisResult>,
}

#[cfg(feature = "gui")]
impl ComponentDetailView {
    pub fn new() -> Self {
        Self {
            component: None,
            relationships: Vec::new(),
            analysis_results: Vec::new(),
        }
    }

    pub fn set_component(
        &mut self, 
        component: Component, 
        conn: &rusqlite::Connection
    ) -> anyhow::Result<()> {
        // Load relationships
        self.relationships = RelationshipQueries::get_by_source(conn, &component.id)?;
        let mut incoming_rels = RelationshipQueries::get_by_target(conn, &component.id)?;
        self.relationships.append(&mut incoming_rels);

        // Load analysis results
        self.analysis_results = AnalysisQueries::get_by_component(conn, &component.id)?;

        self.component = Some(component);
        Ok(())
    }

    pub fn render(&mut self, ui: &mut Ui) {
        if let Some(component) = &self.component {
            ui.heading(&component.name);
            ui.separator();

            // Basic information
            CollapsingHeader::new("Basic Information")
                .default_open(true)
                .show(ui, |ui| {
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
                });

            // Metadata
            if !component.metadata.is_empty() {
                CollapsingHeader::new("Metadata").show(ui, |ui| {
                    for (key, value) in &component.metadata {
                        ui.horizontal(|ui| {
                            ui.label(format!("{}:", key));
                            ui.label(value.to_string());
                        });
                    }
                });
            }

            // Relationships
            if !self.relationships.is_empty() {
                CollapsingHeader::new("Relationships").show(ui, |ui| {
                    for relationship in &self.relationships {
                        ui.horizontal(|ui| {
                            let direction = if relationship.source_id == component.id {
                                "→"
                            } else {
                                "←"
                            };
                            ui.label(format!("{} {} ({})", 
                                direction,
                                relationship.relationship_type,
                                if relationship.source_id == component.id {
                                    &relationship.target_id
                                } else {
                                    &relationship.source_id
                                }
                            ));
                        });
                    }
                });
            }

            // Analysis Results
            if !self.analysis_results.is_empty() {
                CollapsingHeader::new("Analysis Results").show(ui, |ui| {
                    for result in &self.analysis_results {
                        CollapsingHeader::new(format!("{:?}", result.analysis_type)).show(ui, |ui| {
                            ui.label(format!("Confidence: {:.2}%", 
                                result.confidence_score.unwrap_or(0.0) * 100.0));
                            ui.label(format!("Created: {}", result.created_at.format("%Y-%m-%d %H:%M:%S UTC")));
                            
                            ui.separator();
                            ui.label("Results:");
                            
                            ScrollArea::vertical()
                                .max_height(200.0)
                                .show(ui, |ui| {
                                    ui.add(
                                        TextEdit::multiline(&mut result.results.to_string())
                                            .desired_width(f32::INFINITY)
                                            .desired_rows(5)
                                    );
                                });
                        });
                    }
                });
            }
        } else {
            ui.label("No component selected");
        }
    }
}

#[cfg(feature = "gui")]
impl Default for ComponentDetailView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "gui")]
pub struct FilterPanel {
    pub component_type_filter: Option<crate::types::ComponentType>,
    pub name_filter: String,
    pub analysis_type_filter: Option<AnalysisType>,
    pub has_relationships_filter: Option<bool>,
}

#[cfg(feature = "gui")]
impl FilterPanel {
    pub fn new() -> Self {
        Self {
            component_type_filter: None,
            name_filter: String::new(),
            analysis_type_filter: None,
            has_relationships_filter: None,
        }
    }

    pub fn render(&mut self, ui: &mut Ui) -> bool {
        let mut changed = false;

        ui.heading("Filters");
        ui.separator();

        // Component Type Filter
        ui.horizontal(|ui| {
            ui.label("Type:");
            ComboBox::from_label("")
                .selected_text(match &self.component_type_filter {
                    Some(t) => t.to_string(),
                    None => "All".to_string(),
                })
                .show_ui(ui, |ui| {
                    if ui.selectable_value(&mut self.component_type_filter, None, "All").changed() {
                        changed = true;
                    }
                    for component_type in &[
                        crate::types::ComponentType::Binary,
                        crate::types::ComponentType::Function,
                        crate::types::ComponentType::Instruction,
                        crate::types::ComponentType::Process,
                        crate::types::ComponentType::Host,
                        crate::types::ComponentType::Network,
                    ] {
                        if ui.selectable_value(
                            &mut self.component_type_filter, 
                            Some(component_type.clone()), 
                            component_type.to_string()
                        ).changed() {
                            changed = true;
                        }
                    }
                });
        });

        // Name Filter
        ui.horizontal(|ui| {
            ui.label("Name:");
            if ui.text_edit_singleline(&mut self.name_filter).changed() {
                changed = true;
            }
        });

        // Analysis Type Filter
        ui.horizontal(|ui| {
            ui.label("Analysis:");
            ComboBox::from_label("")
                .selected_text(match &self.analysis_type_filter {
                    Some(t) => format!("{:?}", t),
                    None => "All".to_string(),
                })
                .show_ui(ui, |ui| {
                    if ui.selectable_value(&mut self.analysis_type_filter, None, "All").changed() {
                        changed = true;
                    }
                    for analysis_type in &[
                        AnalysisType::StaticAnalysis,
                        AnalysisType::CallGraph,
                        AnalysisType::Syscalls,
                        AnalysisType::Capabilities,
                        AnalysisType::DataFlow,
                        AnalysisType::TaintAnalysis,
                        AnalysisType::NetworkAnalysis,
                    ] {
                        if ui.selectable_value(
                            &mut self.analysis_type_filter, 
                            Some(analysis_type.clone()), 
                            format!("{:?}", analysis_type)
                        ).changed() {
                            changed = true;
                        }
                    }
                });
        });

        // Relationships Filter
        ui.horizontal(|ui| {
            ui.label("Has relationships:");
            ComboBox::from_label("")
                .selected_text(match &self.has_relationships_filter {
                    Some(true) => "Yes",
                    Some(false) => "No",
                    None => "Any",
                })
                .show_ui(ui, |ui| {
                    if ui.selectable_value(&mut self.has_relationships_filter, None, "Any").changed() {
                        changed = true;
                    }
                    if ui.selectable_value(&mut self.has_relationships_filter, Some(true), "Yes").changed() {
                        changed = true;
                    }
                    if ui.selectable_value(&mut self.has_relationships_filter, Some(false), "No").changed() {
                        changed = true;
                    }
                });
        });

        changed
    }

    pub fn matches_component(&self, component: &Component) -> bool {
        // Component type filter
        if let Some(filter_type) = &self.component_type_filter {
            if &component.component_type != filter_type {
                return false;
            }
        }

        // Name filter
        if !self.name_filter.is_empty() {
            if !component.name.to_lowercase().contains(&self.name_filter.to_lowercase()) {
                return false;
            }
        }

        true
    }
}

#[cfg(feature = "gui")]
impl Default for FilterPanel {
    fn default() -> Self {
        Self::new()
    }
}
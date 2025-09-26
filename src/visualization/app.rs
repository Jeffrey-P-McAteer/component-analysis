#[cfg(feature = "gui")]
use crate::database::{open_database, ComponentQueries, RelationshipQueries};
#[cfg(feature = "gui")]
use crate::types::{Component, ComponentType};
#[cfg(feature = "gui")]
use crate::visualization::{ComponentGraph, ComponentDetailView, FilterPanel, GraphLayout};
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
    
    // Graph visualization
    graph: ComponentGraph,
    detail_view: ComponentDetailView,
    filter_panel: FilterPanel,
    view_mode: ViewMode,
    show_filters: bool,
}

#[cfg(feature = "gui")]
#[derive(Debug, Clone, PartialEq)]
enum ViewMode {
    List,
    Graph,
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
            graph: ComponentGraph::new(),
            detail_view: ComponentDetailView::new(),
            filter_panel: FilterPanel::new(),
            view_mode: ViewMode::List,
            show_filters: false,
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
        
        // Apply filters from filter panel
        if self.view_mode == ViewMode::Graph {
            self.components.retain(|c| self.filter_panel.matches_component(c));
        }
        
        self.load_graph()?;
        Ok(())
    }

    fn load_graph(&mut self) -> anyhow::Result<()> {
        self.graph = ComponentGraph::new();
        
        // Add components to graph
        for component in &self.components {
            self.graph.add_component(component.clone());
        }
        
        // Add relationships
        let db = open_database(&self.db_path)?;
        let conn = db.connection();
        
        for component in &self.components {
            let relationships = RelationshipQueries::get_by_source(conn, &component.id)?;
            for relationship in relationships {
                // Only add relationship if target is also in our component list
                if self.components.iter().any(|c| c.id == relationship.target_id) {
                    self.graph.add_relationship(relationship);
                }
            }
        }
        
        // Apply layout
        self.graph.apply_layout();
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

    fn show_component_details(&mut self, ui: &mut Ui) {
        if let Some(selected_id) = &self.selected_component {
            if let Some(component) = self.components.iter().find(|c| &c.id == selected_id).cloned() {
                let db_result = open_database(&self.db_path);
                if let Ok(db) = db_result {
                    if let Err(e) = self.detail_view.set_component(component, db.connection()) {
                        self.error_message = Some(format!("Failed to load component details: {}", e));
                    }
                }
            }
        }
        
        self.detail_view.render(ui);
    }

    fn show_graph_view(&mut self, ui: &mut Ui) {
        // Graph controls
        ui.horizontal(|ui| {
            ui.label("Layout:");
            if ui.button("Force").clicked() {
                self.graph.set_layout(GraphLayout::Force);
            }
            if ui.button("Hierarchical").clicked() {
                self.graph.set_layout(GraphLayout::Hierarchical);
            }
            if ui.button("Circular").clicked() {
                self.graph.set_layout(GraphLayout::Circular);
            }
            if ui.button("Grid").clicked() {
                self.graph.set_layout(GraphLayout::Grid);
            }
            
            ui.separator();
            
            if ui.button("Clear Selection").clicked() {
                self.graph.clear_selection();
                self.selected_component = None;
            }
        });

        ui.separator();
        
        // Render graph
        self.graph.render(ui);
        
        // Update selection from graph
        let selected_components = self.graph.get_selected_components();
        if let Some(first_selected) = selected_components.first() {
            if self.selected_component.as_ref() != Some(&first_selected.id) {
                self.selected_component = Some(first_selected.id.clone());
            }
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

        // Top menu bar
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                // View mode selection
                ui.label("View:");
                if ui.selectable_value(&mut self.view_mode, ViewMode::List, "List").clicked() {
                    if let Err(e) = self.load_components() {
                        self.error_message = Some(format!("Failed to refresh components: {}", e));
                    }
                }
                if ui.selectable_value(&mut self.view_mode, ViewMode::Graph, "Graph").clicked() {
                    if let Err(e) = self.load_components() {
                        self.error_message = Some(format!("Failed to load graph: {}", e));
                    }
                }

                ui.separator();

                // Filter toggle
                if ui.button(if self.show_filters { "Hide Filters" } else { "Show Filters" }).clicked() {
                    self.show_filters = !self.show_filters;
                }

                ui.separator();

                // Refresh button
                if ui.button("Refresh").clicked() {
                    if let Err(e) = self.load_components() {
                        self.error_message = Some(format!("Failed to refresh: {}", e));
                    }
                }
            });
        });

        // Left panel - either component list or filters
        if self.view_mode == ViewMode::List || self.show_filters {
            egui::SidePanel::left("left_panel")
                .default_width(400.0)
                .show(ctx, |ui| {
                    if self.view_mode == ViewMode::List {
                        self.show_component_list(ui);
                    } else if self.show_filters {
                        if self.filter_panel.render(ui) {
                            // Filters changed, reload components
                            if let Err(e) = self.load_components() {
                                self.error_message = Some(format!("Failed to apply filters: {}", e));
                            }
                        }
                    }
                });
        }

        // Right panel for details
        egui::SidePanel::right("details_panel")
            .default_width(350.0)
            .show(ctx, |ui| {
                self.show_component_details(ui);
            });

        // Central panel - main content
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.view_mode {
                ViewMode::List => {
                    ui.heading("Component Analysis Results");
                    ui.label("Select components from the left panel to view details.");
                    
                    if !self.components.is_empty() {
                        ui.separator();
                        ui.label(format!("Total components loaded: {}", self.components.len()));
                        
                        // Component type breakdown
                        let mut type_counts = std::collections::HashMap::new();
                        for component in &self.components {
                            *type_counts.entry(&component.component_type).or_insert(0) += 1;
                        }
                        
                        for (comp_type, count) in type_counts {
                            ui.label(format!("{}: {}", comp_type, count));
                        }
                    }
                }
                ViewMode::Graph => {
                    self.show_graph_view(ui);
                }
            }
        });

        egui::TopBottomPanel::bottom("status")
            .default_height(30.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(format!("Components: {}", self.components.len()));
                    ui.separator();
                    ui.label(format!("View: {:?}", self.view_mode));
                    ui.separator();
                    ui.label(format!("Database: {}", self.db_path.display()));
                });
            });
    }
}
#[cfg(feature = "gui")]
use crate::database::{open_database, ComponentQueries, RelationshipQueries};
#[cfg(feature = "gui")]
use crate::types::{Component, ComponentType};
#[cfg(feature = "gui")]
use crate::visualization::{ComponentGraph, ComponentDetailView, FilterPanel, GraphLayout};
#[cfg(feature = "gui")]
use crate::investigation::InvestigationManager;
#[cfg(feature = "gui")]
use crate::performance::PerformanceManager;
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
    
    // Investigation support
    investigation_manager: InvestigationManager,
    show_investigation_panel: bool,
    
    // Performance monitoring
    performance_manager: PerformanceManager,
    show_performance_panel: bool,
}

#[cfg(feature = "gui")]
#[derive(Debug, Clone, PartialEq)]
enum ViewMode {
    List,
    Graph,
    Investigation,
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
            investigation_manager: InvestigationManager::new(),
            show_investigation_panel: false,
            performance_manager: PerformanceManager::new(),
            show_performance_panel: false,
        };
        
        // Load initial data
        if let Err(e) = app.load_components() {
            app.error_message = Some(format!("Failed to load components: {}", e));
        }

        // Load investigations
        if let Err(e) = app.investigation_manager.load_investigations(&app.db_path) {
            app.error_message = Some(format!("Failed to load investigations: {}", e));
        }
        
        app
    }

    fn load_components(&mut self) -> anyhow::Result<()> {
        let timer = self.performance_manager.start_timer("load_components");
        
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
        
        // Update performance metrics
        self.performance_manager.update_component_count("loaded", self.components.len());
        self.performance_manager.record_timer(timer);
        self.performance_manager.update_memory_usage();
        
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

    fn show_component_paths(&mut self, component_id: &str) -> anyhow::Result<()> {
        // Load relationships for path analysis
        let db = open_database(&self.db_path)?;
        let conn = db.connection();
        
        // Get all relationships (both incoming and outgoing) for the component
        let mut all_relationships = RelationshipQueries::get_by_source(conn, component_id)?;
        let incoming_relationships = RelationshipQueries::get_by_target(conn, component_id)?;
        all_relationships.extend(incoming_relationships);
        
        // Also get relationships for other components to build complete paths
        for component in &self.components {
            if component.id != component_id {
                let component_relationships = RelationshipQueries::get_by_source(conn, &component.id)?;
                all_relationships.extend(component_relationships);
            }
        }
        
        // Remove duplicates
        all_relationships.sort_by(|a, b| a.id.cmp(&b.id));
        all_relationships.dedup_by(|a, b| a.id == b.id);
        
        // Highlight paths in the graph
        self.graph.highlight_component_paths(component_id, &all_relationships);
        
        Ok(())
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
            
            ui.separator();
            
            // Path visualization controls
            if let Some(selected_id) = self.selected_component.clone() {
                if ui.button("Show Paths").clicked() {
                    if let Err(e) = self.show_component_paths(&selected_id) {
                        self.error_message = Some(format!("Failed to show paths: {}", e));
                    }
                }
            }
            
            if self.graph.path_visualization_mode {
                if ui.button("Clear Paths").clicked() {
                    self.graph.clear_path_visualization();
                }
                
                // Show path legend
                ui.separator();
                ui.label("Legend:");
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::from_rgb(50, 150, 255), "● Read Paths");
                    ui.colored_label(egui::Color32::from_rgb(255, 200, 50), "● Write Paths");
                });
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
                if ui.selectable_value(&mut self.view_mode, ViewMode::Investigation, "Investigation").clicked() {
                    if let Err(e) = self.investigation_manager.load_investigations(&self.db_path) {
                        self.error_message = Some(format!("Failed to load investigations: {}", e));
                    }
                }

                ui.separator();

                // Filter toggle
                if ui.button(if self.show_filters { "Hide Filters" } else { "Show Filters" }).clicked() {
                    self.show_filters = !self.show_filters;
                }

                ui.separator();

                // Performance panel toggle
                if ui.button(if self.show_performance_panel { "Hide Performance" } else { "Show Performance" }).clicked() {
                    self.show_performance_panel = !self.show_performance_panel;
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

        // Left panel - either component list, filters, or investigation list
        if self.view_mode == ViewMode::List || self.show_filters || self.view_mode == ViewMode::Investigation {
            egui::SidePanel::left("left_panel")
                .default_width(400.0)
                .show(ctx, |ui| {
                    if self.view_mode == ViewMode::List {
                        self.show_component_list(ui);
                    } else if self.view_mode == ViewMode::Investigation {
                        // Investigation view uses full central panel, so show investigation controls here
                        ui.heading("Investigation Console");
                        ui.label("Use central panel for full investigation interface");
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
        let right_panel_width = if self.show_performance_panel { 500.0 } else { 350.0 };
        egui::SidePanel::right("details_panel")
            .default_width(right_panel_width)
            .show(ctx, |ui| {
                if self.show_performance_panel {
                    // Split right panel for details and performance
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.set_width(250.0);
                            ui.heading("Component Details");
                            ui.separator();
                            self.show_component_details(ui);
                        });
                        
                        ui.separator();
                        
                        ui.vertical(|ui| {
                            ui.set_width(230.0);
                            self.show_performance_panel(ui);
                        });
                    });
                } else {
                    self.show_component_details(ui);
                }
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
                ViewMode::Investigation => {
                    let selected_component = self.selected_component.as_ref()
                        .and_then(|id| self.components.iter().find(|c| &c.id == id));
                    
                    if self.investigation_manager.render(ui, selected_component) {
                        // Investigation data changed, refresh if needed
                        if let Err(e) = self.investigation_manager.load_investigations(&self.db_path) {
                            self.error_message = Some(format!("Failed to refresh investigations: {}", e));
                        }
                    }
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

#[cfg(feature = "gui")]
impl AnalyzerApp {
    fn show_performance_panel(&mut self, ui: &mut Ui) {
        ui.heading("Performance Monitor");
        ui.separator();
        
        // Analysis timing
        if !self.performance_manager.metrics.analysis_times.is_empty() {
            ui.collapsing("Analysis Timing", |ui| {
                for (operation, duration) in &self.performance_manager.metrics.analysis_times {
                    ui.label(format!("{}: {:?}", operation, duration));
                }
            });
        }
        
        // Component counts
        if !self.performance_manager.metrics.component_counts.is_empty() {
            ui.collapsing("Component Counts", |ui| {
                for (component_type, count) in &self.performance_manager.metrics.component_counts {
                    ui.label(format!("{}: {}", component_type, count));
                }
            });
        }
        
        // Memory usage
        ui.collapsing("Memory Usage", |ui| {
            let mem = &self.performance_manager.metrics.memory_usage;
            ui.label(format!("Peak: {} MB", mem.peak_memory_mb));
            ui.label(format!("Current: {} MB", mem.current_memory_mb));
            ui.label(format!("Components: {} MB", mem.component_memory_mb));
            ui.label(format!("Analysis: {} MB", mem.analysis_memory_mb));
        });
        
        // Processing rate
        if self.performance_manager.metrics.processing_rate > 0.0 {
            ui.separator();
            ui.label(format!("Processing Rate: {:.2} comp/sec", 
                self.performance_manager.metrics.processing_rate));
        }
        
        // Cache statistics
        let cache_stats = &self.performance_manager.metrics.cache_stats;
        if cache_stats.hits + cache_stats.misses > 0 {
            ui.collapsing("Cache Statistics", |ui| {
                ui.label(format!("Hits: {}", cache_stats.hits));
                ui.label(format!("Misses: {}", cache_stats.misses));
                ui.label(format!("Hit Rate: {:.1}%", cache_stats.hit_rate * 100.0));
                ui.label(format!("Cache Size: {} MB", cache_stats.cache_size_mb));
            });
        }
        
        // Optimization recommendations
        let recommendations = self.performance_manager.get_optimization_recommendations();
        if !recommendations.is_empty() {
            ui.separator();
            ui.collapsing("Recommendations", |ui| {
                for rec in &recommendations {
                    ui.colored_label(
                        match rec.severity {
                            crate::performance::RecommendationSeverity::Critical => egui::Color32::RED,
                            crate::performance::RecommendationSeverity::High => egui::Color32::from_rgb(255, 165, 0),
                            crate::performance::RecommendationSeverity::Medium => egui::Color32::YELLOW,
                            crate::performance::RecommendationSeverity::Low => egui::Color32::LIGHT_BLUE,
                        },
                        format!("{:?}", rec.severity)
                    );
                    ui.label(format!("Category: {:?}", rec.category));
                    ui.label(&rec.description);
                    ui.label(format!("Action: {}", rec.action));
                    ui.separator();
                }
            });
        }
        
        // Clear metrics button
        if ui.button("Clear Metrics").clicked() {
            self.performance_manager = PerformanceManager::new();
        }
    }
}
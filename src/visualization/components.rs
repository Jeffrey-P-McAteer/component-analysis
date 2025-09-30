#[cfg(feature = "gui")]
use crate::types::{Component, Relationship, AnalysisResult, AnalysisType, FunctionDocumentation, ComponentType};
#[cfg(feature = "gui")]
use crate::database::{ComponentQueries, RelationshipQueries, AnalysisQueries, FunctionDocumentationQueries};
#[cfg(feature = "gui")]
use crate::documentation::{DocumentationService, SyntaxHighlighter};
#[cfg(feature = "gui")]
use crate::documentation::lookup::DocumentationSource;
#[cfg(feature = "gui")]
use egui::{Ui, TextEdit, ComboBox, ScrollArea, CollapsingHeader, RichText, Color32};

#[cfg(feature = "gui")]
pub struct ComponentDetailView {
    pub component: Option<Component>,
    pub relationships: Vec<Relationship>,
    pub analysis_results: Vec<AnalysisResult>,
    documentation_service: DocumentationService,
    syntax_highlighter: SyntaxHighlighter,
    cached_documentation: Option<FunctionDocumentation>,
    documentation_loading: bool,
    lookup_task: Option<std::thread::JoinHandle<anyhow::Result<Option<FunctionDocumentation>>>>,
    lookup_result: Option<anyhow::Result<Option<FunctionDocumentation>>>,
}

#[cfg(feature = "gui")]
impl ComponentDetailView {
    pub fn new() -> Self {
        Self {
            component: None,
            relationships: Vec::new(),
            analysis_results: Vec::new(),
            documentation_service: DocumentationService::new(),
            syntax_highlighter: SyntaxHighlighter::new(),
            cached_documentation: None,
            documentation_loading: false,
            lookup_task: None,
            lookup_result: None,
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

        // Clear cached documentation when component changes
        self.cached_documentation = None;
        self.documentation_loading = false;
        
        // Cancel any ongoing lookup task - note: we can't easily cancel std::thread, so we just drop it
        self.lookup_task = None;
        self.lookup_result = None;

        // If this is a function component, try to load cached documentation
        if component.component_type == ComponentType::Function {
            if let Ok(Some(doc)) = FunctionDocumentationQueries::get_by_function_name(conn, &component.name) {
                self.cached_documentation = Some(doc);
            }
        }

        self.component = Some(component);
        Ok(())
    }

    pub fn render(&mut self, ui: &mut Ui, db_conn: Option<&rusqlite::Connection>) {
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

            // Function Documentation (only for function components)
            if component.component_type == ComponentType::Function {
                CollapsingHeader::new("Function Documentation").show(ui, |ui| {
                    self.render_documentation_section(ui, db_conn);
                });
            }
        } else {
            ui.label("No component selected");
        }
    }

    fn render_documentation_section(&mut self, ui: &mut Ui, db_conn: Option<&rusqlite::Connection>) {
        // Check if lookup task is completed
        if let Some(task) = &self.lookup_task {
            if task.is_finished() {
                let task = self.lookup_task.take().unwrap();
                match task.join() {
                    Ok(Ok(Some(doc))) => {
                        log::info!("Documentation lookup completed successfully for: {}", doc.function_name);
                        self.cached_documentation = Some(doc);
                        self.documentation_loading = false;
                        
                        // Save to database if we have a connection
                        if let Some(conn) = db_conn {
                            if let Some(cached_doc) = &self.cached_documentation {
                                if let Err(e) = cached_doc.insert(conn) {
                                    log::warn!("Failed to cache documentation in database: {}", e);
                                } else {
                                    log::debug!("Successfully cached documentation for: {}", cached_doc.function_name);
                                }
                            }
                        }
                    },
                    Ok(Ok(None)) => {
                        log::warn!("Documentation lookup completed but no documentation found");
                        self.documentation_loading = false;
                        self.render_no_documentation_found(ui);
                        return;
                    },
                    Ok(Err(e)) => {
                        log::error!("Documentation lookup failed: {}", e);
                        self.documentation_loading = false;
                        self.render_documentation_error(ui, &e.to_string());
                        return;
                    },
                    Err(_) => {
                        log::error!("Documentation lookup task panicked");
                        self.documentation_loading = false;
                        self.render_documentation_error(ui, "Documentation lookup task failed unexpectedly");
                        return;
                    }
                }
                ui.ctx().request_repaint();
            }
        }

        if let Some(doc) = &self.cached_documentation {
            // Display cached or newly fetched documentation with enhanced rendering
            self.render_documentation_content(ui, doc);
        } else if self.documentation_loading {
            // Show progress indicator with modern circular spinner
            self.render_loading_state(ui);
        } else {
            // Automatically start lookup for function components
            if let (Some(component), Some(conn)) = (&self.component, db_conn) {
                let function_name = component.name.clone();
                log::info!("Auto-starting documentation lookup for function: {}", function_name);
                self.start_documentation_lookup(&function_name, conn);
            } else {
                // Show fallback message if no component or connection
                self.render_no_component_selected(ui);
            }
        }
    }

    fn render_no_documentation_found(&self, ui: &mut Ui) {
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.label(RichText::new("📚")
                    .size(32.0));
                ui.add_space(8.0);
                ui.label(RichText::new("No Documentation Found")
                    .size(16.0)
                    .strong()
                    .color(Color32::from_rgb(150, 150, 150)));
                ui.add_space(4.0);
                if let Some(component) = &self.component {
                    ui.label(RichText::new(format!("Could not find documentation for '{}'", component.name))
                        .size(12.0)
                        .color(Color32::GRAY));
                }
                ui.add_space(8.0);
                ui.label(RichText::new("Documentation sources checked but no results found.")
                    .size(11.0)
                    .color(Color32::GRAY));
                ui.add_space(20.0);
            });
        });
    }

    fn render_documentation_error(&self, ui: &mut Ui, error_message: &str) {
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.label(RichText::new("⚠️")
                    .size(32.0)
                    .color(Color32::from_rgb(255, 165, 0)));
                ui.add_space(8.0);
                ui.label(RichText::new("Documentation Lookup Failed")
                    .size(16.0)
                    .strong()
                    .color(Color32::from_rgb(255, 165, 0)));
                ui.add_space(4.0);
                ui.label(RichText::new(error_message)
                    .size(11.0)
                    .color(Color32::GRAY));
                ui.add_space(8.0);
                if ui.button("Retry Lookup").clicked() {
                    if let (Some(component), Some(_)) = (&self.component, &self.component) {
                        log::info!("User requested retry for documentation lookup: {}", component.name);
                        // Note: Would need to restart lookup process here
                    }
                }
                ui.add_space(20.0);
            });
        });
    }

    fn render_no_component_selected(&self, ui: &mut Ui) {
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.label(RichText::new("🔍")
                    .size(32.0)
                    .color(Color32::GRAY));
                ui.add_space(8.0);
                ui.label(RichText::new("Select a Function")
                    .size(16.0)
                    .strong()
                    .color(Color32::GRAY));
                ui.add_space(4.0);
                ui.label(RichText::new("Choose a function component to view its documentation")
                    .size(12.0)
                    .color(Color32::GRAY));
                ui.add_space(20.0);
            });
        });
    }

    fn render_loading_state(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            
            // Custom circular progress indicator
            let (rect, _response) = ui.allocate_exact_size(egui::Vec2::splat(64.0), egui::Sense::hover());
            
            // Draw circular progress spinner
            let painter = ui.painter_at(rect);
            let center = rect.center();
            let radius = 24.0;
            let time = ui.input(|i| i.time) as f32;
            let rotation = time * 2.0; // 2 radians per second
            
            // Background circle
            painter.circle_stroke(
                center,
                radius,
                egui::Stroke::new(3.0, egui::Color32::GRAY.linear_multiply(0.3))
            );
            
            // Progress arc
            let arc_length = std::f32::consts::PI * 1.5; // 3/4 circle
            let start_angle = rotation;
            
            for i in 0..32 {
                let angle = start_angle + (i as f32 / 32.0) * arc_length;
                let alpha = (i as f32 / 31.0).powf(2.0); // Fade effect
                let point = center + egui::Vec2::angled(angle) * radius;
                let color = egui::Color32::from_rgb(70, 130, 200).linear_multiply(alpha);
                painter.circle_filled(point, 2.0, color);
            }
            
            ui.add_space(16.0);
            
            // Loading text with animated dots
            let dots = match ((time * 2.0) as usize) % 4 {
                0 => "",
                1 => ".",
                2 => "..",
                3 => "...",
                _ => "",
            };
            
            ui.label(egui::RichText::new(format!("Looking up documentation{}", dots))
                .size(16.0)
                .color(egui::Color32::from_rgb(70, 130, 200)));
            
            ui.add_space(8.0);
            
            // Function name being looked up
            if let Some(component) = &self.component {
                ui.label(egui::RichText::new(&component.name)
                    .size(14.0)
                    .color(egui::Color32::GRAY)
                    .monospace());
            }
            
            ui.add_space(16.0);
            
            // Cancel button
            if ui.button("Cancel").clicked() {
                self.lookup_task = None;
                self.documentation_loading = false;
                log::info!("Documentation lookup cancelled by user");
            }
            
            ui.add_space(20.0);
        });
        
        // Request repaint for animation
        ui.ctx().request_repaint();
    }

    fn render_documentation_content(&self, ui: &mut Ui, doc: &FunctionDocumentation) {
        ui.add_space(8.0);
        
        // Enhanced header section with improved styling
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            
            // Function name and source badge
            ui.horizontal(|ui| {
                ui.label(RichText::new(&doc.function_name)
                    .size(18.0)
                    .strong()
                    .color(Color32::from_rgb(70, 130, 200)));
                
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Quality score badge
                    let quality_color = if doc.quality_score > 0.8 {
                        Color32::from_rgb(34, 139, 34)  // Green
                    } else if doc.quality_score > 0.5 {
                        Color32::from_rgb(255, 165, 0)  // Orange
                    } else {
                        Color32::from_rgb(220, 20, 60)   // Red
                    };
                    
                    ui.label(RichText::new(format!("Quality: {:.1}/10", doc.quality_score * 10.0))
                        .size(12.0)
                        .color(quality_color));
                        
                    ui.separator();
                    
                    // Documentation source badge
                    let source_text = match doc.documentation_type {
                        crate::types::DocumentationType::WindowsAPI => "Windows API",
                        crate::types::DocumentationType::StandardLibrary => "Standard Library",
                        crate::types::DocumentationType::LinuxAPI => "Linux API",
                        crate::types::DocumentationType::POSIX => "POSIX",
                        crate::types::DocumentationType::Manual => "Manual Page",
                        crate::types::DocumentationType::Official => "Official Docs",
                        _ => "Documentation",
                    };
                    
                    ui.label(RichText::new(source_text)
                        .size(12.0)
                        .color(Color32::from_rgb(100, 149, 237)));
                });
            });
            
            ui.add_space(4.0);
            ui.label(RichText::new(format!("Platform: {}", doc.platform))
                .size(12.0)
                .color(Color32::GRAY));
        });

        ui.add_space(12.0);

        // Function header with enhanced syntax highlighting
        if let Some(header) = &doc.header {
            if !header.is_empty() {
                ui.group(|ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new("Function Signature")
                        .size(14.0)
                        .strong()
                        .color(Color32::from_rgb(70, 130, 200)));
                    
                    ui.add_space(8.0);
                    
                    // Code background
                    let background_color = if ui.visuals().dark_mode {
                        Color32::from_rgb(30, 30, 30)
                    } else {
                        Color32::from_rgb(248, 248, 248)
                    };
                    
                    egui::Frame::none()
                        .fill(background_color)
                        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(200, 200, 200)))
                        .rounding(4.0)
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            let highlighted_header = self.syntax_highlighter.highlight_c_header(header);
                            ui.horizontal_wrapped(|ui| {
                                for (text, color) in highlighted_header {
                                    ui.add(egui::Label::new(RichText::new(text)
                                        .color(color)
                                        .monospace()
                                        .size(13.0)));
                                }
                            });
                        });
                });
                ui.add_space(12.0);
            }
        }

        // Enhanced description section
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Description")
                .size(14.0)
                .strong()
                .color(Color32::from_rgb(70, 130, 200)));
            
            ui.add_space(8.0);
            
            ScrollArea::vertical()
                .max_height(300.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.set_width(ui.available_width() - 16.0); // Account for scrollbar
                    
                    // Format description with better line breaks and paragraphs
                    let formatted_description = doc.description
                        .lines()
                        .map(|line| line.trim())
                        .collect::<Vec<_>>()
                        .join("\n");
                    
                    ui.label(RichText::new(formatted_description)
                        .size(13.0)
                        .color(if ui.visuals().dark_mode {
                            Color32::from_rgb(220, 220, 220)
                        } else {
                            Color32::from_rgb(60, 60, 60)
                        }));
                });
        });

        ui.add_space(12.0);

        // Enhanced footer with metadata and actions
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            
            // Metadata row
            ui.horizontal(|ui| {
                ui.label(RichText::new("Cached:")
                    .size(12.0)
                    .color(Color32::GRAY));
                ui.label(RichText::new(doc.lookup_timestamp.format("%Y-%m-%d %H:%M UTC").to_string())
                    .size(12.0)
                    .monospace());
                
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // External link button
                    if let Some(url) = &doc.source_url {
                        if ui.button(RichText::new("🔗 View Source")
                            .size(12.0))
                            .on_hover_text(format!("Open: {}", url))
                            .clicked() {
                            // Note: In a real implementation, we would open the URL
                            log::info!("User requested to open URL: {}", url);
                            println!("Would open: {}", url);
                        }
                    }
                    
                    ui.separator();
                    
                    // Refresh button
                    if ui.button(RichText::new("🔄 Refresh")
                        .size(12.0))
                        .on_hover_text("Look up fresh documentation")
                        .clicked() {
                        log::info!("User requested documentation refresh for: {}", doc.function_name);
                        // Note: In a real implementation, we would trigger a fresh lookup
                        // This would require access to the database connection and lookup service
                    }
                });
            });
        });
        
        ui.add_space(8.0);
    }

    fn start_documentation_lookup(&mut self, function_name: &str, _conn: &rusqlite::Connection) {
        self.documentation_loading = true;
        
        // Clone necessary data for the async task
        let function_name_clone = function_name.to_string();
        let _service = self.documentation_service.clone();
        
        // We need to clone the database connection, but rusqlite::Connection doesn't implement Clone
        // So we'll need to pass the database path and open a new connection in the task
        // For now, let's create a simpler approach using a channel
        
        log::info!("Creating async task for documentation lookup: {}", function_name);
        
        // Create a background thread for the documentation lookup with real HTTP fetching
        let task = std::thread::spawn(move || {
            log::info!("Task started for function: {}", function_name_clone);
            
            // Create a Tokio runtime for HTTP requests within this thread
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    log::error!("Failed to create Tokio runtime in thread: {}", e);
                    return Err(anyhow::anyhow!("Failed to create Tokio runtime: {}", e));
                }
            };
            
            // Use the actual documentation service with real HTTP lookup
            rt.block_on(async move {
                log::info!("Starting real documentation lookup for: {}", function_name_clone);
                
                // Try the actual documentation service sources
                let config = crate::types::DocumentationLookupConfig::default();
                
                // Try different sources in order
                let sources = vec![
                    crate::types::DocumentationType::WindowsAPI,
                    crate::types::DocumentationType::StandardLibrary,
                    crate::types::DocumentationType::LinuxAPI,
                    crate::types::DocumentationType::POSIX,
                    crate::types::DocumentationType::Manual,
                ];
                
                for doc_type in sources {
                    log::debug!("Trying documentation source: {:?}", doc_type);
                    
                    let result = match doc_type {
                        crate::types::DocumentationType::WindowsAPI => {
                            crate::documentation::WindowsAPISource::search(&function_name_clone, "windows", &config).await
                        },
                        crate::types::DocumentationType::StandardLibrary => {
                            crate::documentation::StandardLibrarySource::search(&function_name_clone, "generic", &config).await
                        },
                        crate::types::DocumentationType::LinuxAPI => {
                            crate::documentation::LinuxAPISource::search(&function_name_clone, "linux", &config).await
                        },
                        crate::types::DocumentationType::POSIX => {
                            crate::documentation::POSIXSource::search(&function_name_clone, "posix", &config).await
                        },
                        crate::types::DocumentationType::Manual => {
                            crate::documentation::ManualPageSource::search(&function_name_clone, "unix", &config).await
                        },
                        _ => Ok(None),
                    };
                    
                    match result {
                        Ok(Some(search_result)) => {
                            log::info!("Found documentation from {:?} source", doc_type);
                            
                            // Convert search result to FunctionDocumentation
                            let doc = crate::types::FunctionDocumentation::new(
                                search_result.function_name,
                                search_result.platform,
                                search_result.description,
                                search_result.documentation_type,
                            )
                            .with_header(search_result.header.unwrap_or_default())
                            .with_source_url(search_result.source_url)
                            .with_quality_score(search_result.quality_score);
                            
                            return Ok(Some(doc));
                        },
                        Ok(None) => {
                            log::debug!("No documentation found from {:?} source", doc_type);
                        },
                        Err(e) => {
                            log::warn!("Error searching {:?} source: {}", doc_type, e);
                        }
                    }
                }
                
                log::warn!("No documentation found for function: {}", function_name_clone);
                Ok(None)
            })
        });
        
        self.lookup_task = Some(task);
        log::info!("Documentation lookup task started for: {}", function_name);
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
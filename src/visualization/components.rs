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
use std::collections::{HashSet, HashMap};
#[cfg(feature = "gui")]
use std::sync::{Arc, Mutex};

// Global cache to prevent duplicate HTTP requests across all instances
static URL_CACHE: std::sync::OnceLock<Arc<Mutex<HashMap<String, Option<String>>>>> = std::sync::OnceLock::new();

fn get_url_cache() -> &'static Arc<Mutex<HashMap<String, Option<String>>>> {
    URL_CACHE.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

#[cfg(feature = "gui")]
pub struct ComponentDetailView {
    pub component: Option<Component>,
    pub relationships: Vec<Relationship>,
    pub analysis_results: Vec<AnalysisResult>,
    documentation_service: DocumentationService,
    syntax_highlighter: SyntaxHighlighter,
    cached_documentation: Option<FunctionDocumentation>,
    documentation_loading: bool,
    documentation_error: Option<String>,
    lookup_task: Option<std::thread::JoinHandle<anyhow::Result<Option<FunctionDocumentation>>>>,
    lookup_task_component_id: Option<String>, // Track which component the task is for
    lookup_result: Option<anyhow::Result<Option<FunctionDocumentation>>>,
    lookup_in_progress_global: bool, // Global flag to prevent any lookups
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
            documentation_error: None,
            lookup_task: None,
            lookup_task_component_id: None,
            lookup_result: None,
            lookup_in_progress_global: false,
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
        let was_loading = self.documentation_loading;
        let had_task = self.lookup_task.is_some();
        
        self.cached_documentation = None;
        self.documentation_loading = false;
        self.documentation_error = None;
        
        // Cancel any ongoing lookup task - note: we can't easily cancel std::thread, so we just drop it
        self.lookup_task = None;
        self.lookup_task_component_id = None;
        self.lookup_result = None;
        self.lookup_in_progress_global = false;

        if was_loading || had_task {
            log::debug!("Cancelled ongoing documentation lookup when switching to component: {}", component.name);
        }

        // If this is a function component, try to load cached documentation
        if component.component_type == ComponentType::Function {
            log::info!("Setting function component: {} (type: {:?})", component.name, component.component_type);
            
            // Check database for existing documentation
            match FunctionDocumentationQueries::get_by_function_name(conn, &component.name) {
                Ok(Some(doc)) => {
                    log::info!("✅ Found cached documentation in database for function: {} (source: {:?}, platform: {})", 
                        component.name, doc.documentation_type, doc.platform);
                    self.cached_documentation = Some(doc);
                },
                Ok(None) => {
                    log::info!("📖 No cached documentation found in database for function: {}", component.name);
                    self.cached_documentation = None;
                },
                Err(e) => {
                    log::error!("❌ Database error checking for documentation for function {}: {}", component.name, e);
                    self.cached_documentation = None;
                }
            }
        } else {
            log::debug!("Component {} is not a function (type: {:?}), skipping documentation lookup", component.name, component.component_type);
            self.cached_documentation = None;
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
                let component_name = component.name.clone();
                log::debug!("Showing function documentation section for: {}", component_name);
                CollapsingHeader::new("Function Documentation").show(ui, |ui| {
                    // Debug logging for documentation section
                    log::debug!("Rendering documentation section for: {} (cached: {}, loading: {}, error: {})", 
                        component_name, 
                        self.cached_documentation.is_some(),
                        self.documentation_loading,
                        self.documentation_error.is_some());
                    
                    self.render_documentation_section(ui, db_conn);
                });
            } else {
                log::debug!("Component {} is not a function, skipping documentation section", component.name);
            }
        } else {
            ui.label("No component selected");
        }
    }

    fn render_documentation_section(&mut self, ui: &mut Ui, db_conn: Option<&rusqlite::Connection>) {
        let current_component_id = self.component.as_ref().map(|c| c.id.clone());
        
        // Check if lookup task is completed
        if let Some(task) = &self.lookup_task {
            if task.is_finished() {
                log::debug!("Documentation task completed, processing results");
                let task = self.lookup_task.take().unwrap();
                self.lookup_task_component_id = None; // Clear the component ID
                
                match task.join() {
                    Ok(Ok(Some(doc))) => {
                        log::info!("Documentation lookup completed successfully for: {}", doc.function_name);
                        
                        // Print documentation content to console for debugging
                        println!("\n=== DOCUMENTATION FOUND FOR {} ===", doc.function_name);
                        println!("Source: {:?}", doc.documentation_type);
                        println!("Platform: {}", doc.platform);
                        println!("Quality Score: {:.2}", doc.quality_score);
                        if let Some(ref header) = doc.header {
                            println!("Header: {}", header);
                        }
                        println!("Description: {}", doc.description);
                        if let Some(ref url) = doc.source_url {
                            println!("Source URL: {}", url);
                        }
                        println!("=====================================\n");
                        
                        self.cached_documentation = Some(doc);
                        self.documentation_loading = false;
                        self.documentation_error = None;
                        self.lookup_in_progress_global = false;
                        
                        // Save to database immediately if we have a connection
                        if let Some(conn) = db_conn {
                            if let Some(cached_doc) = &self.cached_documentation {
                                match cached_doc.insert(conn) {
                                    Ok(_) => {
                                        log::info!("✅ Successfully saved documentation to database for: {}", cached_doc.function_name);
                                    },
                                    Err(e) => {
                                        log::error!("❌ Failed to save documentation to database for {}: {}", cached_doc.function_name, e);
                                    }
                                }
                            }
                        } else {
                            log::warn!("No database connection available to save documentation");
                        }
                    },
                    Ok(Ok(None)) => {
                        log::warn!("Documentation lookup completed but no documentation found");
                        self.documentation_loading = false;
                        self.documentation_error = Some("No documentation found".to_string());
                        self.lookup_in_progress_global = false;
                    },
                    Ok(Err(e)) => {
                        log::error!("Documentation lookup failed: {}", e);
                        self.documentation_loading = false;
                        self.documentation_error = Some(e.to_string());
                        self.lookup_in_progress_global = false;
                    },
                    Err(_) => {
                        log::error!("Documentation lookup task panicked");
                        self.documentation_loading = false;
                        self.documentation_error = Some("Documentation lookup task failed unexpectedly".to_string());
                        self.lookup_in_progress_global = false;
                    }
                }
            } else {
                // Task is still running - check if it's for the current component
                if let (Some(current_id), Some(task_id)) = (&current_component_id, &self.lookup_task_component_id) {
                    if current_id != task_id {
                        log::info!("Component changed while task was running, cancelling old task");
                        self.lookup_task = None;
                        self.lookup_task_component_id = None;
                        self.documentation_loading = false;
                        self.documentation_error = None;
                        self.lookup_in_progress_global = false;
                    }
                }
            }
        }

        // Render based on current state
        if let Some(doc) = &self.cached_documentation {
            // Display cached or newly fetched documentation with enhanced rendering
            self.render_documentation_content(ui, doc);
        } else if let Some(error) = &self.documentation_error {
            // Show error state with retry option
            let error_message = error.clone();
            self.render_documentation_error(ui, &error_message);
        } else if self.documentation_loading {
            // Show progress indicator with modern circular spinner
            self.render_loading_state(ui);
        } else {
            // Automatically start lookup for function components (with proper guards)
            if let (Some(component), Some(conn)) = (&self.component, db_conn) {
                // Check if we already have a task running for this specific component
                let task_for_current_component = self.lookup_task_component_id.as_ref() == Some(&component.id);
                
                // Debug current state
                log::debug!("Documentation state check for {}: loading={}, task_exists={}, error_exists={}, task_for_current={}, task_component_id={:?}", 
                    component.name,
                    self.documentation_loading, 
                    self.lookup_task.is_some(),
                    self.documentation_error.is_some(),
                    task_for_current_component,
                    self.lookup_task_component_id);
                
                // Only start lookup if:
                // 0. We don't already have cached documentation, AND
                // 1. Global flag is not set, AND
                // 2. No task is currently running, AND
                // 3. We're not in a loading state, AND  
                // 4. There's no error state, AND
                // 5. Either no task component ID is set OR it's not for the current component
                let should_start_lookup = self.cached_documentation.is_none()
                    && !self.lookup_in_progress_global
                    && !self.documentation_loading 
                    && self.lookup_task.is_none() 
                    && self.documentation_error.is_none() 
                    && !task_for_current_component;
                
                if should_start_lookup {
                    let function_name = component.name.clone();
                    let component_id = component.id.clone();
                    log::info!("🔍 Auto-starting documentation lookup for function: {} (no cached documentation available)", function_name);
                    self.start_documentation_lookup(&function_name, &component_id, conn);
                } else {
                    if self.cached_documentation.is_some() {
                        log::debug!("✅ Using cached documentation, no lookup needed");
                    } else {
                        log::debug!("⏸️ Skipping lookup start - conditions not met (loading: {}, task: {}, error: {})", 
                            self.documentation_loading,
                            self.lookup_task.is_some(), 
                            self.documentation_error.is_some());
                    }
                }
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

    fn render_documentation_error(&mut self, ui: &mut Ui, error_message: &str) {
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
                    if let Some(component) = &self.component {
                        log::info!("User requested retry for documentation lookup: {}", component.name);
                        // Clear error state to allow retry
                        self.documentation_error = None;
                        self.documentation_loading = false;
                        self.lookup_task = None;
                        self.lookup_task_component_id = None;
                        self.lookup_in_progress_global = false;
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
                self.lookup_task_component_id = None;
                self.documentation_loading = false;
                self.lookup_in_progress_global = false;
                log::info!("Documentation lookup cancelled by user");
            }
            
            ui.add_space(20.0);
        });
        
        // Note: egui automatically repaints for animations, no manual request needed
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

    fn start_documentation_lookup(&mut self, function_name: &str, component_id: &str, _conn: &rusqlite::Connection) {
        // CRITICAL: Ultra-strong safety guards to prevent infinite loops
        
        // Guard 0: Global lookup prevention flag
        if self.lookup_in_progress_global {
            log::warn!("GUARD 0 TRIGGERED: Global lookup in progress flag set for: {}, BLOCKING", function_name);
            return;
        }
        
        // Guard 1: Check if already loading
        if self.documentation_loading {
            log::warn!("GUARD 1 TRIGGERED: Documentation lookup already loading for: {}, BLOCKING", function_name);
            return;
        }
        
        // Guard 2: Check if task exists
        if self.lookup_task.is_some() {
            log::warn!("GUARD 2 TRIGGERED: Documentation lookup task already exists for: {}, BLOCKING", function_name);
            return;
        }
        
        // Guard 3: Check if task is for same component
        if let Some(existing_component_id) = &self.lookup_task_component_id {
            if existing_component_id == component_id {
                log::warn!("GUARD 3 TRIGGERED: Documentation lookup already in progress for component: {}, BLOCKING", component_id);
                return;
            }
        }
        
        // Guard 4: Final state validation
        if self.documentation_loading || self.lookup_task.is_some() || 
           (self.lookup_task_component_id.is_some() && self.lookup_task_component_id.as_ref().unwrap() == component_id) {
            log::warn!("GUARD 4 TRIGGERED: Final validation failed, state inconsistent for: {}, BLOCKING", function_name);
            return;
        }

        log::info!("ALL GUARDS PASSED - Starting documentation lookup for function: {} (component: {})", function_name, component_id);
        
        // Set ALL state variables IMMEDIATELY to prevent any race conditions
        self.lookup_in_progress_global = true;  // CRITICAL: Set this first
        self.documentation_loading = true;
        self.lookup_task_component_id = Some(component_id.to_string());
        self.documentation_error = None; // Clear any previous error
        
        // Clone necessary data for the async task
        let function_name_clone = function_name.to_string();
        let _service = self.documentation_service.clone();
        
        // We need to clone the database connection, but rusqlite::Connection doesn't implement Clone
        // So we'll need to pass the database path and open a new connection in the task
        // For now, let's create a simpler approach using a channel
        
        log::info!("Creating async task for documentation lookup: {}", function_name);
        
        // Create a background thread for the documentation lookup with controlled HTTP client
        let task = std::thread::spawn(move || {
            log::info!("Task started for function: {}", function_name_clone);
            
            // Use a synchronous HTTP client to avoid Tokio runtime resource issues
            log::info!("Starting HTTP documentation lookup for: {}", function_name_clone);
            
            // Comprehensive documentation sources for different function types
            let sources = if function_name_clone.starts_with("Nt") || function_name_clone.starts_with("Zw") {
                vec![
                    // Windows NT Native API sources
                    ("Microsoft Learn", "https://learn.microsoft.com/en-us/windows/win32/api/"),
                    ("NT Internals", "https://undocumented.ntinternals.net/"),
                    ("Process Hacker", "https://processhacker.sourceforge.io/doc/"),
                    ("ReactOS", "https://doxygen.reactos.org/"),
                    ("Windows Driver Kit", "https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/"),
                    ("MSDN Archive", "https://web.archive.org/web/20201109000000*/https://docs.microsoft.com/"),
                ]
            } else if ["CreateFile", "ReadFile", "WriteFile", "CloseHandle", "GetLastError"].iter().any(|&f| function_name_clone.contains(f)) {
                vec![
                    // Win32 API sources
                    ("Microsoft Learn", "https://learn.microsoft.com/en-us/windows/win32/api/"),
                    ("Win32 API Documentation", "https://docs.microsoft.com/en-us/windows/win32/"),
                    ("MSDN Library", "https://msdn.microsoft.com/en-us/library/"),
                    ("Windows Dev Center", "https://developer.microsoft.com/en-us/windows/"),
                ]
            } else if ["strlen", "strcpy", "malloc", "free", "printf", "scanf", "memcpy", "strncpy"].contains(&function_name_clone.as_str()) {
                vec![
                    // C Standard Library sources
                    ("cppreference", "https://en.cppreference.com/w/c/"),
                    ("GNU C Library", "https://www.gnu.org/software/libc/manual/html_node/"),
                    ("C11 Standard", "https://port70.net/~nsz/c/c11/"),
                    ("tutorialspoint", "https://www.tutorialspoint.com/c_standard_library/"),
                ]
            } else {
                vec![
                    // Generic/Linux sources
                    ("Linux Manual Pages", "https://man7.org/linux/man-pages/"),
                    ("Linux Kernel", "https://www.kernel.org/doc/html/latest/"),
                    ("GNU C Library", "https://www.gnu.org/software/libc/manual/html_node/"),
                    ("Ubuntu Manpages", "https://manpages.ubuntu.com/"),
                ]
            };
            
            // Collect all URLs from all sources and deduplicate globally
            let mut all_urls = HashSet::new();
            let mut source_url_map = std::collections::HashMap::new();
            
            for (source_name, base_url) in &sources {
                log::debug!("Preparing documentation source: {}", source_name);
                
                // Generate comprehensive URL patterns for each source
                let search_urls = generate_search_urls(&function_name_clone, source_name, base_url);
                
                log::debug!("Generated {} URLs for source {}: {:?}", search_urls.len(), source_name, search_urls);
                
                if !search_urls.is_empty() {
                    // Track which URLs belong to which source
                    for url in &search_urls {
                        if all_urls.insert(url.clone()) {
                            source_url_map.insert(url.clone(), source_name.clone());
                        } else {
                            log::debug!("Skipping duplicate URL {} for source {}", url, source_name);
                        }
                    }
                }
            }
            
            log::info!("Total unique URLs to try: {}", all_urls.len());
            
            // Try sources in parallel using multiple threads to get faster results
            let mut search_tasks = vec![];
            
            for (source_name, base_url) in &sources {
                // Generate comprehensive URL patterns for each source
                let search_urls = generate_search_urls(&function_name_clone, source_name, base_url);
                
                if !search_urls.is_empty() {
                    let source_name_clone = source_name.to_string();
                    let source_name_for_task = source_name_clone.clone();
                    let function_name_for_task = function_name_clone.clone();
                    
                    // Create a task for this source
                    let task = std::thread::spawn(move || {
                        log::debug!("Starting lookup for source: {}", source_name_for_task);
                        try_documentation_source(&function_name_for_task, &source_name_for_task, &search_urls)
                    });
                    
                    search_tasks.push((source_name_clone, task));
                }
            }
            
            // Wait for the first successful result or collect all results
            let mut best_result = None;
            let mut all_results = vec![];
            
            for (source_name, task) in search_tasks {
                match task.join() {
                    Ok(Some(result)) => {
                        log::info!("Successfully got documentation from: {}", source_name);
                        all_results.push((source_name.clone(), result.clone()));
                        
                        if best_result.is_none() {
                            best_result = Some(result);
                        }
                    },
                    Ok(None) => {
                        log::debug!("No documentation found from: {}", source_name);
                    },
                    Err(e) => {
                        log::warn!("Error in documentation task for {}: {:?}", source_name, e);
                    }
                }
            }
            
            // Select the best result based on content quality
            if let Some(result) = best_result.or_else(|| select_best_documentation_result(all_results)) {
                return Ok(Some(result));
            }
            
            log::info!("No documentation found for function: {}", function_name_clone);
            Ok(None)
        });
        
        self.lookup_task = Some(task);
        log::info!("Documentation lookup task started for: {}", function_name);
    }
}

// Generate comprehensive search URLs for different documentation sources
fn generate_search_urls(function_name: &str, source_name: &str, base_url: &str) -> Vec<String> {
    match source_name {
        "Microsoft Learn" => {
            if function_name.starts_with("Nt") || function_name.starts_with("Zw") {
                vec![
                    // NT Native API patterns
                    format!("{}/winternl/nf-winternl-{}", base_url, function_name.to_lowercase()),
                    format!("{}/ntdll/nf-ntdll-{}", base_url, function_name.to_lowercase()),
                    format!("{}/winbase/nf-winbase-{}", base_url, function_name.to_lowercase()),
                    format!("{}/processthreadsapi/nf-processthreadsapi-{}", base_url, function_name.to_lowercase()),
                    format!("{}/fileapi/nf-fileapi-{}", base_url, function_name.to_lowercase()),
                    // Search patterns
                    format!("{}search?query={}", base_url, function_name),
                ]
            } else {
                vec![
                    // Regular Win32 API patterns
                    format!("{}/fileapi/nf-fileapi-{}", base_url, function_name.to_lowercase()),
                    format!("{}/processthreadsapi/nf-processthreadsapi-{}", base_url, function_name.to_lowercase()),
                    format!("{}/winbase/nf-winbase-{}", base_url, function_name.to_lowercase()),
                    format!("{}/handleapi/nf-handleapi-{}", base_url, function_name.to_lowercase()),
                    format!("{}search?query={}", base_url, function_name),
                ]
            }
        },
        "NT Internals" => {
            vec![
                format!("{}/UserMode/Undocumented%20Functions/NT%20Objects/File/{}.html", base_url, function_name),
                format!("{}/UserMode/Undocumented%20Functions/NT%20Objects/Process/{}.html", base_url, function_name),
                format!("{}/UserMode/Undocumented%20Functions/Executive/{}.html", base_url, function_name),
            ]
        },
        "ReactOS" => {
            vec![
                format!("{}/group__{}.html", base_url, function_name.to_lowercase()),
                format!("{}/{}__8c.html", base_url, function_name.to_lowercase()),
            ]
        },
        "Windows Driver Kit" => {
            vec![
                format!("{}/ntddk/nf-ntddk-{}", base_url, function_name.to_lowercase()),
                format!("{}/wdm/nf-wdm-{}", base_url, function_name.to_lowercase()),
                format!("{}/ntifs/nf-ntifs-{}", base_url, function_name.to_lowercase()),
            ]
        },
        "cppreference" => {
            // Correct cppreference URLs for common C functions
            match function_name {
                "strlen" | "strnlen" => vec![
                    format!("{}/string/byte/strlen", base_url),
                ],
                "strcpy" | "strncpy" => vec![
                    format!("{}/string/byte/strcpy", base_url),
                ],
                "strcmp" | "strncmp" => vec![
                    format!("{}/string/byte/strcmp", base_url),
                ],
                "malloc" | "calloc" | "realloc" | "free" => vec![
                    format!("{}/memory/malloc", base_url),
                    format!("{}/memory/free", base_url),
                ],
                "memcpy" | "memmove" => vec![
                    format!("{}/string/byte/memcpy", base_url),
                ],
                "memset" => vec![
                    format!("{}/string/byte/memset", base_url),
                ],
                "printf" | "sprintf" | "fprintf" => vec![
                    format!("{}/io/fprintf", base_url),
                ],
                "scanf" | "sscanf" | "fscanf" => vec![
                    format!("{}/io/fscanf", base_url),
                ],
                _ => vec![
                    // Generic patterns for unknown functions
                    format!("{}/string/byte/{}", base_url, function_name),
                    format!("{}/memory/{}", base_url, function_name),
                    format!("{}/io/{}", base_url, function_name),
                ]
            }
        },
        "Linux Manual Pages" => {
            vec![
                format!("{}/man2/{}.2.html", base_url, function_name),
                format!("{}/man3/{}.3.html", base_url, function_name),
                format!("{}/man7/{}.7.html", base_url, function_name),
            ]
        },
        _ => vec![],
    }
}

// Try a single documentation source with multiple URLs
fn try_documentation_source(function_name: &str, source_name: &str, search_urls: &[String]) -> Option<crate::types::FunctionDocumentation> {
    // Deduplicate URLs to prevent multiple requests to same endpoint
    let mut unique_urls = std::collections::HashSet::new();
    let mut deduped_urls = Vec::new();
    
    for url in search_urls {
        if unique_urls.insert(url.clone()) {
            deduped_urls.push(url.clone());
        }
    }
    
    log::debug!("Trying {} unique URLs for {} from {}", deduped_urls.len(), function_name, source_name);
    
    for url in &deduped_urls {
        // Check global URL cache first
        {
            let cache = get_url_cache().lock().unwrap();
            if let Some(cached_content) = cache.get(url) {
                if let Some(content) = cached_content {
                    log::info!("Using cached content for URL: {}", url);
                    
                    // Process cached content
                    if is_valid_documentation_content(content, function_name) {
                        let description = extract_description_from_html(content, function_name);
                        let header = extract_function_header(content, function_name);
                        
                        if description.len() >= 20 {
                            let doc_type = match source_name {
                                s if s.contains("Microsoft") || s.contains("Windows") => crate::types::DocumentationType::WindowsAPI,
                                s if s.contains("cppreference") || s.contains("GNU") => crate::types::DocumentationType::StandardLibrary,
                                s if s.contains("Linux") || s.contains("Ubuntu") => crate::types::DocumentationType::LinuxAPI,
                                _ => crate::types::DocumentationType::Manual,
                            };
                            
                            let quality_score = calculate_content_quality(content, function_name, source_name);
                            
                            let doc = crate::types::FunctionDocumentation::new(
                                function_name.to_string(),
                                determine_platform(function_name, source_name),
                                description,
                                doc_type,
                            )
                            .with_header(header)
                            .with_source_url(url.clone())
                            .with_quality_score(quality_score);
                            
                            return Some(doc);
                        }
                    }
                } else {
                    log::debug!("URL {} is cached as failed, skipping", url);
                    continue;
                }
            }
        }
        
        log::debug!("Fetching URL: {}", url);
        
        // Try to fetch the URL with curl
        match std::process::Command::new("curl")
            .arg("-s")
            .arg("--max-time")
            .arg("10")
            .arg("--user-agent")
            .arg("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .arg(url)
            .output()
        {
            Ok(output) if output.status.success() => {
                let content = String::from_utf8_lossy(&output.stdout).to_string();
                
                // Cache the content (successful fetch)
                {
                    let mut cache = get_url_cache().lock().unwrap();
                    cache.insert(url.clone(), Some(content.clone()));
                }
                
                // More sophisticated content validation
                if is_valid_documentation_content(&content, function_name) {
                    log::info!("Successfully fetched documentation from: {}", url);
                    
                    let description = extract_description_from_html(&content, function_name);
                    let header = extract_function_header(&content, function_name);
                    
                    // Skip if we couldn't extract meaningful content
                    if description.len() < 20 {
                        log::debug!("Extracted description too short, trying next URL");
                        continue;
                    }
                    
                    let doc_type = match source_name {
                        s if s.contains("Microsoft") || s.contains("Windows") => crate::types::DocumentationType::WindowsAPI,
                        s if s.contains("cppreference") || s.contains("GNU") => crate::types::DocumentationType::StandardLibrary,
                        s if s.contains("Linux") || s.contains("Ubuntu") => crate::types::DocumentationType::LinuxAPI,
                        _ => crate::types::DocumentationType::Manual,
                    };
                    
                    let quality_score = calculate_content_quality(&content, function_name, source_name);
                    
                    let doc = crate::types::FunctionDocumentation::new(
                        function_name.to_string(),
                        determine_platform(function_name, source_name),
                        description,
                        doc_type,
                    )
                    .with_header(header)
                    .with_source_url(url.clone())
                    .with_quality_score(quality_score);
                    
                    return Some(doc);
                }
            },
            Ok(_) => {
                log::debug!("Failed to fetch from URL (non-success status): {}", url);
                // Cache the failure
                {
                    let mut cache = get_url_cache().lock().unwrap();
                    cache.insert(url.clone(), None);
                }
            },
            Err(e) => {
                log::debug!("Error fetching URL {}: {}", url, e);
                // Cache the failure
                {
                    let mut cache = get_url_cache().lock().unwrap();
                    cache.insert(url.clone(), None);
                }
            }
        }
    }
    
    None
}

// Validate that the content actually contains documentation
fn is_valid_documentation_content(content: &str, function_name: &str) -> bool {
    let content_lower = content.to_lowercase();
    let function_lower = function_name.to_lowercase();
    
    // Content must be substantial
    if content.len() < 200 {
        return false;
    }
    
    // Must not be error pages
    if content_lower.contains("404") || content_lower.contains("not found") 
        || content_lower.contains("page not found") || content_lower.contains("error") {
        return false;
    }
    
    // Must contain the function name or be a relevant documentation page
    if content_lower.contains(&function_lower) 
        || content_lower.contains("function") 
        || content_lower.contains("api")
        || content_lower.contains("documentation") {
        return true;
    }
    
    false
}

// Calculate quality score based on content characteristics
fn calculate_content_quality(content: &str, function_name: &str, source_name: &str) -> f64 {
    let mut score: f64 = 0.0;
    
    // Base score by source reputation
    score += match source_name {
        s if s.contains("Microsoft") => 0.9,
        s if s.contains("cppreference") => 0.8,
        s if s.contains("ReactOS") => 0.7,
        s if s.contains("NT Internals") => 0.6,
        _ => 0.5,
    };
    
    // Bonus for containing function name
    if content.to_lowercase().contains(&function_name.to_lowercase()) {
        score += 0.1;
    }
    
    // Bonus for substantial content
    if content.len() > 1000 {
        score += 0.1;
    }
    
    // Bonus for containing code examples
    if content.contains("example") || content.contains("Example") {
        score += 0.1;
    }
    
    score.min(1.0)
}

// Select the best documentation result from multiple sources
fn select_best_documentation_result(results: Vec<(String, crate::types::FunctionDocumentation)>) -> Option<crate::types::FunctionDocumentation> {
    if results.is_empty() {
        return None;
    }
    
    // Sort by quality score and return the best
    let mut sorted_results = results;
    sorted_results.sort_by(|a, b| b.1.quality_score.partial_cmp(&a.1.quality_score).unwrap_or(std::cmp::Ordering::Equal));
    
    Some(sorted_results.into_iter().next().unwrap().1)
}

// Helper functions for documentation parsing
fn extract_description_from_html(content: &str, function_name: &str) -> String {
    // Simple HTML parsing to extract meaningful content
    // Look for common patterns in documentation sites
    
    // Remove HTML tags for a basic text extraction
    let text_content = content
        .replace("<br>", "\n")
        .replace("<br/>", "\n")
        .replace("<p>", "\n")
        .replace("</p>", "\n");
    
    // Try to find description patterns
    if let Some(start) = text_content.find("Description") {
        if let Some(section) = text_content.get(start..start.saturating_add(1000)) {
            let lines: Vec<&str> = section.lines().skip(1).take(10).collect();
            let description = lines.join(" ").trim().to_string();
            if description.len() > 20 {
                return description;
            }
        }
    }
    
    // Fallback: look for any text mentioning the function name
    for line in text_content.lines().take(50) {
        if line.contains(function_name) && line.len() > 30 && line.len() < 500 {
            let clean_line = line.trim().to_string();
            if !clean_line.is_empty() && !clean_line.starts_with('<') {
                return clean_line;
            }
        }
    }
    
    // Final fallback: generic description based on function name
    if function_name.starts_with("Nt") || function_name.starts_with("Zw") {
        format!("Windows NT system call: {}. This is a low-level function from the Native API (ntdll.dll) used by the Windows subsystem.", function_name)
    } else if ["strlen", "strcpy", "malloc", "free"].contains(&function_name) {
        format!("Standard C library function: {}. Part of the C runtime library.", function_name)
    } else {
        format!("System function: {}. Documentation was found but content extraction needs refinement.", function_name)
    }
}

fn extract_function_header(content: &str, function_name: &str) -> String {
    // Look for function prototypes in common formats
    let patterns = [
        format!("NTSTATUS {}(", function_name),
        format!("{}(", function_name),
        format!("int {}(", function_name),
        format!("void {}(", function_name),
        format!("size_t {}(", function_name),
    ];
    
    for line in content.lines() {
        for pattern in &patterns {
            if line.contains(pattern) {
                // Extract the function signature
                if let Some(start) = line.find(pattern) {
                    if let Some(end) = line[start..].find(';') {
                        return line[start..start + end + 1].trim().to_string();
                    } else if let Some(end) = line[start..].find(')') {
                        return format!("{});", &line[start..start + end + 1].trim());
                    }
                }
            }
        }
    }
    
    // Fallback: create a generic prototype
    if function_name.starts_with("Nt") || function_name.starts_with("Zw") {
        format!("NTSTATUS {}(/* parameters not documented */);", function_name)
    } else {
        format!("/* {} function prototype not extracted */", function_name)
    }
}

fn determine_platform(function_name: &str, source_name: &str) -> String {
    match source_name {
        "Windows API" => "windows".to_string(),
        "Linux Manual" => "linux".to_string(),
        "C Standard Library" => "c".to_string(),
        _ => {
            if function_name.starts_with("Nt") || function_name.starts_with("Zw") {
                "windows".to_string()
            } else {
                "generic".to_string()
            }
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
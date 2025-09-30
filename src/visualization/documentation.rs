use std::collections::HashMap;
#[cfg(feature = "gui")]
use crate::types::{FunctionDocumentation, ComponentType};
#[cfg(feature = "gui")]
use crate::database::FunctionDocumentationQueries;
#[cfg(feature = "gui")]
use crate::documentation::{DocumentationService, SyntaxHighlighter};
#[cfg(feature = "gui")]
use egui::{Ui, ScrollArea, RichText, Color32};
#[cfg(feature = "gui")]
#[cfg(feature = "gui")]
use std::sync::{Arc, Mutex};

// Global cache to prevent duplicate HTTP requests across all instances
#[allow(dead_code)]
static URL_CACHE: std::sync::OnceLock<Arc<Mutex<HashMap<String, Option<String>>>>> = std::sync::OnceLock::new();

#[allow(dead_code)]
fn get_url_cache() -> &'static Arc<Mutex<HashMap<String, Option<String>>>> {
    URL_CACHE.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

#[cfg(feature = "gui")]
pub struct DocumentationRenderer {
    pub syntax_highlighter: SyntaxHighlighter,
    #[allow(dead_code)]
    pub documentation_service: DocumentationService,
    pub cached_documentation: Option<FunctionDocumentation>,
    pub documentation_loading: bool,
    pub documentation_error: Option<String>,
    pub lookup_task: Option<std::thread::JoinHandle<anyhow::Result<Option<FunctionDocumentation>>>>,
    pub lookup_task_component_id: Option<String>,
    pub lookup_in_progress_global: bool,
}

#[cfg(feature = "gui")]
impl Default for DocumentationRenderer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "gui")]
impl DocumentationRenderer {
    pub fn new() -> Self {
        Self {
            syntax_highlighter: SyntaxHighlighter::new(),
            documentation_service: DocumentationService::new(),
            cached_documentation: None,
            documentation_loading: false,
            documentation_error: None,
            lookup_task: None,
            lookup_task_component_id: None,
            lookup_in_progress_global: false,
        }
    }

    pub fn clear_state(&mut self) {
        self.cached_documentation = None;
        self.documentation_loading = false;
        self.documentation_error = None;
        self.lookup_task = None;
        self.lookup_task_component_id = None;
        self.lookup_in_progress_global = false;
    }

    pub fn load_cached_documentation(&mut self, function_name: &str, conn: &rusqlite::Connection) -> anyhow::Result<()> {
        match FunctionDocumentationQueries::get_by_function_name(conn, function_name) {
            Ok(Some(doc)) => {
                log::info!("Found cached documentation in database for function: {} (source: {:?}, platform: {})", 
                    function_name, doc.documentation_type, doc.platform);
                self.cached_documentation = Some(doc);
            },
            Ok(None) => {
                log::info!("No cached documentation found in database for function: {}", function_name);
                self.cached_documentation = None;
            },
            Err(e) => {
                log::error!("Database error checking for documentation for function {}: {}", function_name, e);
                self.cached_documentation = None;
            }
        }
        Ok(())
    }

    pub fn render_section(&mut self, ui: &mut Ui, component_name: Option<&str>, component_id: Option<&str>, component_type: Option<ComponentType>, db_conn: Option<&rusqlite::Connection>) {
        // Request repaint continuously while task is running to poll for completion
        if self.documentation_loading || self.lookup_task.is_some() {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(100));
        }
        
        // Check if lookup task is completed
        let task_finished = self.lookup_task.as_ref().map(|task| task.is_finished()).unwrap_or(false);
        if task_finished {
            if let Some(task) = self.lookup_task.take() {
                self.handle_task_completion(task, ui, db_conn);
            }
        } else if self.lookup_task.is_some() {
            // Task is still running - check if it's for the current component
            if let (Some(current_id), Some(task_id)) = (component_id, &self.lookup_task_component_id) {
                if current_id != task_id {
                    log::info!("Component changed while task was running, cancelling old task");
                    self.clear_state();
                }
            }
        }

        // Render based on current state
        if let Some(doc) = &self.cached_documentation {
            log::debug!("Rendering cached documentation for: {}", doc.function_name);
            self.render_documentation_content(ui, doc);
        } else if let Some(error) = &self.documentation_error {
            let error_message = error.clone();
            log::debug!("Rendering error state: {}", error_message);
            self.render_documentation_error(ui, &error_message);
        } else if self.documentation_loading {
            log::debug!("Rendering loading state");
            self.render_loading_state(ui);
        } else {
            // Start lookup if needed
            if let (Some(name), Some(id), Some(conn)) = (component_name, component_id, db_conn) {
                if let Some(ComponentType::Function) = component_type {
                    self.maybe_start_lookup(name, id, conn, ui);
                } else {
                    self.render_no_component_selected(ui);
                }
            } else {
                self.render_no_component_selected(ui);
            }
        }
    }

    fn handle_task_completion(&mut self, task: std::thread::JoinHandle<anyhow::Result<Option<FunctionDocumentation>>>, ui: &mut Ui, db_conn: Option<&rusqlite::Connection>) {
        log::debug!("Documentation task completed, processing results");
        self.lookup_task_component_id = None;
        
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
                
                // Force immediate UI update
                ui.ctx().request_repaint();
                
                // Save to database immediately if we have a connection
                if let Some(conn) = db_conn {
                    if let Some(cached_doc) = &self.cached_documentation {
                        match cached_doc.insert(conn) {
                            Ok(_) => {
                                log::info!("Successfully saved documentation to database for: {}", cached_doc.function_name);
                            },
                            Err(e) => {
                                log::error!("Failed to save documentation to database for {}: {}", cached_doc.function_name, e);
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
                ui.ctx().request_repaint();
            },
            Ok(Err(e)) => {
                log::error!("Documentation lookup failed: {}", e);
                self.documentation_loading = false;
                self.documentation_error = Some(e.to_string());
                self.lookup_in_progress_global = false;
                ui.ctx().request_repaint();
            },
            Err(_) => {
                log::error!("Documentation lookup task panicked");
                self.documentation_loading = false;
                self.documentation_error = Some("Documentation lookup task failed unexpectedly".to_string());
                self.lookup_in_progress_global = false;
                ui.ctx().request_repaint();
            }
        }
    }

    fn maybe_start_lookup(&mut self, function_name: &str, component_id: &str, _conn: &rusqlite::Connection, ui: &mut Ui) {
        let task_for_current_component = self.lookup_task_component_id.as_ref() == Some(&component_id.to_string());
        
        let should_start_lookup = self.cached_documentation.is_none()
            && !self.lookup_in_progress_global
            && !self.documentation_loading 
            && self.lookup_task.is_none() 
            && self.documentation_error.is_none() 
            && !task_for_current_component;
        
        if should_start_lookup {
            log::info!("Auto-starting documentation lookup for function: {} (no cached documentation available)", function_name);
            self.start_documentation_lookup(function_name, component_id);
            ui.ctx().request_repaint();
        } else {
            if self.cached_documentation.is_some() {
                log::debug!("Using cached documentation, no lookup needed");
            } else {
                log::debug!("Skipping lookup start - conditions not met (loading: {}, task: {}, error: {})", 
                    self.documentation_loading,
                    self.lookup_task.is_some(), 
                    self.documentation_error.is_some());
            }
        }
    }

    fn start_documentation_lookup(&mut self, function_name: &str, component_id: &str) {
        // Multiple strong safety guards to prevent infinite loops
        if self.lookup_in_progress_global {
            log::warn!("GUARD 0 TRIGGERED: Global lookup in progress flag set for: {}, BLOCKING", function_name);
            return;
        }
        
        if self.documentation_loading {
            log::warn!("GUARD 1 TRIGGERED: Documentation lookup already loading for: {}, BLOCKING", function_name);
            return;
        }
        
        if self.lookup_task.is_some() {
            log::warn!("GUARD 2 TRIGGERED: Documentation lookup task already exists for: {}, BLOCKING", function_name);
            return;
        }
        
        if let Some(existing_component_id) = &self.lookup_task_component_id {
            if existing_component_id == component_id {
                log::warn!("GUARD 3 TRIGGERED: Documentation lookup already in progress for component: {}, BLOCKING", component_id);
                return;
            }
        }

        log::info!("ALL GUARDS PASSED - Starting documentation lookup for function: {} (component: {})", function_name, component_id);
        
        // Set ALL state variables IMMEDIATELY to prevent any race conditions
        self.lookup_in_progress_global = true;
        self.documentation_loading = true;
        self.lookup_task_component_id = Some(component_id.to_string());
        self.documentation_error = None;

        // Clone necessary data for the async task
        let function_name_clone = function_name.to_string();

        // Create a background thread for documentation lookup
        let task = std::thread::spawn(move || {
            log::info!("Task started for function: {}", function_name_clone);
            
            // Simple mock for now - can be replaced with real HTTP lookup
            std::thread::sleep(std::time::Duration::from_millis(500));
            
            if function_name_clone.starts_with("Nt") || function_name_clone.starts_with("Zw") {
                let doc = crate::types::FunctionDocumentation::new(
                    function_name_clone.clone(),
                    "windows".to_string(),
                    format!("Windows NT system call: {}\n\nThis is a low-level Windows API function from the Native API (ntdll.dll).", function_name_clone),
                    crate::types::DocumentationType::WindowsAPI,
                )
                .with_header(format!("NTSTATUS {}(/* parameters not available */);", function_name_clone))
                .with_source_url("https://learn.microsoft.com/en-us/windows/win32/api/".to_string())
                .with_quality_score(0.7);
                
                Ok(Some(doc))
            } else if ["strlen", "strcpy", "malloc", "free", "printf", "scanf"].contains(&function_name_clone.as_str()) {
                let description = match function_name_clone.as_str() {
                    "strlen" => "Calculates the length of a null-terminated string.",
                    "strcpy" => "Copies a null-terminated string from source to destination.",
                    "malloc" => "Allocates a block of memory on the heap.",
                    "free" => "Deallocates memory previously allocated by malloc.",
                    "printf" => "Formatted output function that prints to stdout.",
                    "scanf" => "Formatted input function that reads from stdin.",
                    _ => "Standard C library function.",
                };
                
                let doc = crate::types::FunctionDocumentation::new(
                    function_name_clone.clone(),
                    "c".to_string(),
                    description.to_string(),
                    crate::types::DocumentationType::StandardLibrary,
                )
                .with_header(format!("/* {} function prototype */", function_name_clone))
                .with_source_url("https://en.cppreference.com/w/c/".to_string())
                .with_quality_score(0.9);
                
                Ok(Some(doc))
            } else {
                Ok(None)
            }
        });
        
        self.lookup_task = Some(task);
        log::info!("Documentation lookup task started for: {} (task created successfully)", function_name);
    }

    fn render_loading_state(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            
            // Modern circular progress indicator
            let (rect, _response) = ui.allocate_exact_size(egui::Vec2::splat(64.0), egui::Sense::hover());
            let painter = ui.painter_at(rect);
            let center = rect.center();
            let radius = 24.0;
            let time = ui.input(|i| i.time) as f32;
            let rotation = time * 2.0;
            
            // Progress arc parameters
            let arc_length = std::f32::consts::PI * 1.5;
            let start_angle = rotation;
            
            // Background circle
            painter.circle_stroke(center, radius, egui::Stroke::new(3.0, egui::Color32::GRAY.linear_multiply(0.3)));
            
            // Progress arc with fade effect
            for i in 0..32 {
                let angle = start_angle + (i as f32 / 32.0) * arc_length;
                let alpha = (i as f32 / 31.0).powf(2.0);
                let point = center + egui::Vec2::angled(angle) * radius;
                let color = egui::Color32::from_rgb(70, 130, 200).linear_multiply(alpha);
                painter.circle_filled(point, 2.0, color);
            }
            
            ui.add_space(16.0);
            
            // Loading text with animated dots
            let dots_count = ((time * 2.0) % 4.0) as usize;
            let dots = ".".repeat(dots_count);
            ui.label(RichText::new(format!("Looking up documentation{}", dots))
                .size(14.0)
                .color(Color32::GRAY));
                
            if let Some(component_id) = &self.lookup_task_component_id {
                ui.label(RichText::new(format!("Component: {}", component_id))
                    .size(11.0)
                    .color(Color32::DARK_GRAY));
            }
            
            ui.add_space(8.0);
            
            if ui.button("Cancel").clicked() {
                self.lookup_task = None;
                self.lookup_task_component_id = None;
                self.documentation_loading = false;
                self.lookup_in_progress_global = false;
                log::info!("Documentation lookup cancelled by user");
            }
            
            ui.add_space(20.0);
        });
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
                            log::info!("User requested to open URL: {}", url);
                            println!("Would open: {}", url);
                        }
                    }
                    
                    ui.separator();
                    
                    // Refresh button
                    if ui.button(RichText::new("[PROCESS] Refresh")
                        .size(12.0))
                        .on_hover_text("Look up fresh documentation")
                        .clicked() {
                        log::info!("User requested documentation refresh for: {}", doc.function_name);
                    }
                });
            });
        });
        
        ui.add_space(8.0);
    }

    fn render_documentation_error(&mut self, ui: &mut Ui, error_message: &str) {
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.label(RichText::new("[WARNING]")
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
                    // Clear error state to allow retry
                    self.documentation_error = None;
                    self.documentation_loading = false;
                    self.lookup_task = None;
                    self.lookup_task_component_id = None;
                    self.lookup_in_progress_global = false;
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
                ui.label(RichText::new("[SEARCH]")
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
}
use crate::database::{open_database, ComponentQueries};
use crate::parser::BinaryParser;
use crate::types::{Component, ComponentType, Relationship, RelationshipType};
use crate::analysis::{DisassemblyEngine, CallGraphBuilder, SyscallAnalyzer, CapabilityAnalyzer, create_disassembler_for_binary};
use crate::performance::{PerformanceManager, OptimizationStrategy};
use anyhow::Result;
use log::{info, warn, debug};
use std::path::Path;
use std::fs;

pub fn run(
    db_path: &Path,
    input_path: &Path,
    focus_syscalls: bool,
    focus_network: bool,
    deep: bool,
) -> Result<()> {
    info!("Starting analysis of {}", input_path.display());
    
    // Initialize performance manager
    let mut perf_manager = PerformanceManager::new();
    let analysis_timer = perf_manager.start_timer("total_analysis");
    
    // Open database
    let db = open_database(db_path)?;
    let conn = db.connection();

    // Initialize schema if needed
    db.init_schema()?;

    // Parse the binary
    let parser = BinaryParser::new(input_path)?;
    info!("Binary format: {}", parser.get_format());

    // Read binary data for analysis
    let binary_data = fs::read(input_path)?;

    // Create binary component
    let binary_component = parser.create_binary_component()?;
    info!("Created binary component: {}", binary_component.name);
    
    // Insert binary component
    binary_component.insert(conn)?;

    // Initialize analysis engines if doing deep analysis
    let analysis_engines = if deep {
        match create_disassembler_for_binary(&binary_data) {
            Ok(disassembler) => {
                info!("Initialized disassembly engine for deep analysis");
                Some((
                    disassembler,
                    SyscallAnalyzer::new(),
                    CapabilityAnalyzer::new(),
                ))
            }
            Err(e) => {
                warn!("Failed to initialize disassembly engine: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Extract functions and perform deep analysis if enabled
    let function_timer = perf_manager.start_timer("function_extraction");
    match parser.extract_functions() {
        Ok(functions) => {
            perf_manager.record_timer(function_timer);
            let function_count = functions.len();
            info!("Found {} functions", function_count);
            
            // Optimize analysis based on function count
            let optimization_strategy = perf_manager.optimize_for_scale(function_count);
            log_optimization_strategy(&optimization_strategy);
            
            // Initialize call graph builder if we have analysis engines
            let mut call_graph_builder = if let Some((ref disassembler, _, _)) = analysis_engines {
                let binary_base = parser.get_binary_base().unwrap_or(0);
                Some(CallGraphBuilder::new(disassembler, binary_base, binary_data.clone()))
            } else {
                None
            };
            
            perf_manager.update_component_count("functions", function_count);
            let process_timer = perf_manager.start_timer("function_processing");
            
            // Process functions (with batch optimization if enabled)
            if optimization_strategy.use_parallel_processing && function_count > 100 {
                info!("Processing {} functions in batches of {}", function_count, optimization_strategy.batch_size);
                let mut batch_processor = perf_manager.optimizer.create_batch_processor(functions);
                
                while let Some(batch) = batch_processor.next_batch() {
                    let batch_timer = perf_manager.start_timer("batch_processing");
                    process_function_batch(batch, &binary_component, conn, &mut call_graph_builder)?;
                    perf_manager.record_timer(batch_timer);
                    
                    if batch_processor.remaining_batches() % 10 == 0 {
                        info!("Progress: {:.1}%", batch_processor.progress_percentage());
                        perf_manager.update_memory_usage();
                    }
                }
            } else {
                // Process functions sequentially
                for function in functions {
                // Create function component
                let function_name = function.name.clone()
                    .unwrap_or_else(|| format!("func_{:x}", function.address));
                
                let mut function_component = Component::new(ComponentType::Function, function_name);
                function_component = function_component.with_metadata(
                    "address".to_string(),
                    serde_json::json!(format!("0x{:x}", function.address))
                );
                
                if let Some(size) = function.size {
                    function_component = function_component.with_metadata(
                        "size".to_string(),
                        serde_json::json!(size)
                    );
                }

                // Add to call graph builder for deep analysis
                if let Some(ref mut builder) = call_graph_builder {
                    builder.add_function(function.clone());
                }

                // Insert function component
                function_component.insert(conn)?;

                // Create relationship: binary contains function
                let relationship = Relationship::new(
                    binary_component.id.clone(),
                    function_component.id.clone(),
                    RelationshipType::Contains,
                    serde_json::json!({}),
                );
                relationship.insert(conn)?;

                debug!("Added function: {} at 0x{:x}", 
                       function_component.name, function.address);
                }
            }
            
            perf_manager.record_timer(process_timer);

            // Build call graph if deep analysis is enabled
            if let Some(mut builder) = call_graph_builder {
                match builder.build_call_graph() {
                    Ok(call_graph) => {
                        info!("Built call graph with {} edges", call_graph.edges.len());
                        
                        // Store call graph relationships in database
                        for edge in &call_graph.edges {
                            if let (Some(caller_func), Some(callee_func)) = (
                                call_graph.functions.get(&edge.caller),
                                call_graph.functions.get(&edge.callee)
                            ) {
                                let caller_name = caller_func.name.clone()
                                    .unwrap_or_else(|| format!("func_{:x}", caller_func.address));
                                let callee_name = callee_func.name.clone()
                                    .unwrap_or_else(|| format!("func_{:x}", callee_func.address));
                                
                                // Find components by name pattern
                                if let Ok(caller_components) = ComponentQueries::get_by_name_pattern(conn, &caller_name) {
                                    if let Ok(callee_components) = ComponentQueries::get_by_name_pattern(conn, &callee_name) {
                                        if let (Some(caller_comp), Some(callee_comp)) = (caller_components.first(), callee_components.first()) {
                                            let call_relationship = Relationship::new(
                                                caller_comp.id.clone(),
                                                callee_comp.id.clone(),
                                                RelationshipType::Calls,
                                                serde_json::json!({}),
                                            );
                                            call_relationship.insert(conn)?;
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Find and analyze syscall paths if syscall analysis is enabled
                        if focus_syscalls {
                            match builder.find_syscall_paths() {
                                Ok(syscall_paths) => {
                                    info!("Found {} syscall paths", syscall_paths.len());
                                    
                                    if let Some((_, ref syscall_analyzer, _)) = analysis_engines {
                                        for syscall_path in syscall_paths {
                                            let syscall_report = syscall_analyzer.analyze_syscalls(vec![syscall_path.clone()])?;
                                            if let Some(syscall_analysis) = syscall_report.syscall_analyses.first() {
                                                // Create analysis result
                                                let result = crate::types::AnalysisResult::new(
                                                    binary_component.id.clone(),
                                                    crate::types::AnalysisType::Syscalls,
                                                    serde_json::json!({
                                                        "syscall": syscall_analysis.syscall_details.as_ref().map(|s| s.number).unwrap_or(0),
                                                        "name": syscall_analysis.syscall_details.as_ref().map(|s| &s.name).unwrap_or(&"unknown".to_string()),
                                                        "category": syscall_analysis.syscall_details.as_ref()
                                                            .and_then(|s| s.categories.first())
                                                            .map(|c| format!("{:?}", c))
                                                            .unwrap_or_else(|| "unknown".to_string()),
                                                        "risk_level": syscall_analysis.risk_level,
                                                        "address": format!("0x{:x}", syscall_path.syscall_info.address),
                                                        "call_path_length": syscall_path.call_path.len(),
                                                    })
                                                );
                                                result.insert(conn)?;
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to find syscall paths: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to build call graph: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            warn!("Failed to extract functions: {}", e);
        }
    }

    // Get imports and create import relationships with capability analysis
    match parser.get_imported_functions() {
        Ok(imports) => {
            info!("Found {} imported functions", imports.len());
            
            // Analyze capabilities from imports if capability analysis is available
            if let Some((_, _, ref capability_analyzer)) = analysis_engines {
                let capability_analysis = capability_analyzer.analyze_imports(&imports);
                
                // Store capability analysis results
                let capability_result = crate::types::AnalysisResult::new(
                    binary_component.id.clone(),
                    crate::types::AnalysisType::Capabilities,
                    serde_json::json!({
                        "capabilities": capability_analysis.capabilities.iter().map(|cap| {
                            serde_json::json!({
                                "name": cap.name,
                                "category": cap.category,
                                "risk_level": cap.risk_level,
                                "description": cap.description,
                            })
                        }).collect::<Vec<_>>(),
                        "risk_score": capability_analysis.risk_score,
                        "behaviors": capability_analysis.detected_behaviors.iter().map(|behavior| {
                            serde_json::json!({
                                "behavior": behavior.behavior_type,
                                "confidence": behavior.confidence,
                                "evidence": behavior.evidence,
                            })
                        }).collect::<Vec<_>>(),
                    })
                );
                capability_result.insert(conn)?;
                info!("Capability analysis completed with risk score: {}", capability_analysis.risk_score);
            }
            
            for import_name in imports {
                // Create import component (external function)
                let import_component = Component::new(ComponentType::Function, import_name.clone())
                    .with_metadata("external".to_string(), serde_json::json!(true));
                
                // Check if this import already exists
                if ComponentQueries::get_by_name_pattern(conn, &import_name)?.is_empty() {
                    import_component.insert(conn)?;
                    
                    // Create relationship: binary imports function
                    let relationship = Relationship::new(
                        binary_component.id.clone(),
                        import_component.id.clone(),
                        RelationshipType::Imports,
                        serde_json::json!({}),
                    );
                    relationship.insert(conn)?;

                    debug!("Added import: {}", import_name);
                }
            }
        }
        Err(e) => {
            warn!("Failed to extract imports: {}", e);
        }
    }

    // Additional analysis based on flags
    if focus_syscalls && analysis_engines.is_none() {
        info!("Performing basic syscall analysis...");
        analyze_syscalls(&binary_component, conn, deep)?;
    }

    if focus_network {
        info!("Performing network analysis...");
        analyze_network_capabilities(&binary_component, conn, deep, &analysis_engines)?;
    }

    // Record final analysis metrics
    perf_manager.record_timer(analysis_timer);
    perf_manager.update_memory_usage();
    
    // Display performance summary
    display_performance_summary(&perf_manager);
    
    info!("Analysis complete");
    Ok(())
}

fn analyze_syscalls(binary_component: &Component, conn: &rusqlite::Connection, _deep: bool) -> Result<()> {
    // Syscall analysis would involve:
    // 1. Disassembling code sections
    // 2. Looking for syscall instructions (int 0x80, syscall, etc.)
    // 3. Identifying syscall numbers and mapping to system calls
    // 4. Tracking data flow to syscall arguments
    
    // For now, create a placeholder analysis result
    let syscall_analysis = crate::types::AnalysisResult::new(
        binary_component.id.clone(),
        crate::types::AnalysisType::Syscalls,
        serde_json::json!({
            "syscalls_found": [],
            "analysis_status": "placeholder",
            "note": "Syscall analysis requires disassembly engine"
        })
    );
    
    syscall_analysis.insert(conn)?;
    info!("Syscall analysis placeholder created");
    Ok(())
}

fn analyze_network_capabilities(
    binary_component: &Component, 
    conn: &rusqlite::Connection, 
    _deep: bool,
    analysis_engines: &Option<(DisassemblyEngine, SyscallAnalyzer, CapabilityAnalyzer)>,
) -> Result<()> {
    if let Some((_, _, ref capability_analyzer)) = analysis_engines {
        // Enhanced network analysis using capability analyzer
        let network_capabilities = capability_analyzer.get_network_capabilities();
        
        let network_analysis = crate::types::AnalysisResult::new(
            binary_component.id.clone(),
            crate::types::AnalysisType::NetworkAnalysis,
            serde_json::json!({
                "network_capabilities": network_capabilities.iter().map(|cap| {
                    serde_json::json!({
                        "name": cap.name,
                        "category": cap.category,
                        "risk_level": cap.risk_level,
                        "description": cap.description,
                    })
                }).collect::<Vec<_>>(),
                "analysis_status": "complete",
                "capability_count": network_capabilities.len(),
            })
        );
        
        network_analysis.insert(conn)?;
        info!("Network capability analysis completed: {} capabilities found", network_capabilities.len());
    } else {
        // Basic network analysis - looking for network-related imports
        let network_analysis = crate::types::AnalysisResult::new(
            binary_component.id.clone(),
            crate::types::AnalysisType::NetworkAnalysis,
            serde_json::json!({
                "network_capabilities": [],
                "analysis_status": "basic",
                "note": "Enhanced network analysis requires --deep flag"
            })
        );
        
        network_analysis.insert(conn)?;
        info!("Basic network analysis placeholder created");
    }
    
    Ok(())
}

fn process_function_batch(
    batch: &[crate::types::Function],
    binary_component: &Component,
    conn: &rusqlite::Connection,
    call_graph_builder: &mut Option<CallGraphBuilder>,
) -> Result<()> {
    for function in batch {
        // Create function component
        let function_name = function.name.clone()
            .unwrap_or_else(|| format!("func_{:x}", function.address));
        
        let mut function_component = Component::new(ComponentType::Function, function_name);
        function_component = function_component.with_metadata(
            "address".to_string(),
            serde_json::json!(format!("0x{:x}", function.address))
        );
        
        if let Some(size) = function.size {
            function_component = function_component.with_metadata(
                "size".to_string(),
                serde_json::json!(size)
            );
        }

        // Add to call graph builder for deep analysis
        if let Some(ref mut builder) = call_graph_builder {
            builder.add_function(function.clone());
        }

        // Insert function component
        function_component.insert(conn)?;

        // Create relationship: binary contains function
        let relationship = Relationship::new(
            binary_component.id.clone(),
            function_component.id.clone(),
            RelationshipType::Contains,
            serde_json::json!({}),
        );
        relationship.insert(conn)?;

        debug!("Added function: {} at 0x{:x}", 
               function_component.name, function.address);
    }
    Ok(())
}

fn log_optimization_strategy(strategy: &OptimizationStrategy) {
    info!("Analysis optimization strategy:");
    info!("  Parallel processing: {}", strategy.use_parallel_processing);
    info!("  Batch size: {}", strategy.batch_size);
    info!("  Streaming: {}", strategy.enable_streaming);
    info!("  Caching: {}", strategy.enable_caching);
    info!("  Memory conservative: {}", strategy.memory_conservative);
}

fn display_performance_summary(perf_manager: &PerformanceManager) {
    info!("=== Performance Summary ===");
    
    // Analysis timing
    for (operation, duration) in &perf_manager.metrics.analysis_times {
        info!("  {}: {:?}", operation, duration);
    }
    
    // Component counts
    for (component_type, count) in &perf_manager.metrics.component_counts {
        info!("  {}: {} components", component_type, count);
    }
    
    // Memory usage
    info!("  Peak memory: {} MB", perf_manager.metrics.memory_usage.peak_memory_mb);
    info!("  Processing rate: {:.2} components/sec", perf_manager.metrics.processing_rate);
    
    // Cache statistics
    if perf_manager.metrics.cache_stats.hits + perf_manager.metrics.cache_stats.misses > 0 {
        info!("  Cache hit rate: {:.1}%", perf_manager.metrics.cache_stats.hit_rate * 100.0);
    }
    
    // Performance recommendations
    let recommendations = perf_manager.get_optimization_recommendations();
    if !recommendations.is_empty() {
        info!("=== Optimization Recommendations ===");
        for rec in &recommendations {
            info!("  {} - {}: {}", 
                format!("{:?}", rec.severity), 
                format!("{:?}", rec.category), 
                rec.description
            );
        }
    }
}
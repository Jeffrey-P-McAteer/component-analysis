use crate::database::{open_database, ComponentQueries};
use crate::dynamic::{DynamicAnalysisManager, AnalysisStatus};
use crate::types::{AnalysisResult, AnalysisType};
use anyhow::Result;
use log::{info, warn, error};
use std::path::Path;
use std::time::Duration;

pub fn run(
    db_path: &Path,
    component_id: &str,
    sandbox_name: &str,
    timeout_seconds: u64,
    list_sandboxes: bool,
    status_session: Option<&str>,
    report_session: Option<&str>,
) -> Result<()> {
    let mut dynamic_manager = DynamicAnalysisManager::new();
    dynamic_manager.default_timeout = Duration::from_secs(timeout_seconds);
    
    if list_sandboxes {
        return list_available_sandboxes(&dynamic_manager);
    }
    
    if let Some(session_id) = status_session {
        return show_session_status(&dynamic_manager, session_id);
    }
    
    if let Some(session_id) = report_session {
        return generate_session_report(&dynamic_manager, session_id, db_path);
    }
    
    // Main dynamic analysis workflow
    info!("Starting dynamic analysis for component: {}", component_id);
    
    // Open database and get component
    let db = open_database(db_path)?;
    let conn = db.connection();
    
    let components = ComponentQueries::get_by_id_pattern(conn, component_id)?;
    let component = components.into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Component '{}' not found", component_id))?;
    
    info!("Found component: {} ({})", component.name, component.component_type);
    
    // Validate component has binary path
    let binary_path = component.metadata.get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Component does not have a binary path. Add path metadata first."))?;
    
    info!("Binary path: {}", binary_path);
    
    // Start dynamic analysis
    match dynamic_manager.start_dynamic_analysis(&component, sandbox_name) {
        Ok(session_id) => {
            info!("Dynamic analysis started successfully!");
            info!("Session ID: {}", session_id);
            info!("Sandbox: {}", sandbox_name);
            info!("Timeout: {} seconds", timeout_seconds);
            
            // Monitor analysis progress
            monitor_analysis_progress(&mut dynamic_manager, &session_id, timeout_seconds)?;
            
            // Generate and store report
            match dynamic_manager.generate_analysis_report(&session_id) {
                Ok(report) => {
                    info!("Analysis completed. Risk Score: {:.1}/100", report.risk_score);
                    info!("Risk Level: {:?}", report.risk_level);
                    
                    // Store results in database
                    let analysis_result = AnalysisResult::new(
                        component.id.clone(),
                        AnalysisType::DynamicAnalysis,
                        serde_json::to_value(&report)?
                    );
                    
                    analysis_result.insert(conn)?;
                    info!("Dynamic analysis results saved to database");
                    
                    // Display summary
                    display_analysis_summary(&report);
                }
                Err(e) => {
                    error!("Failed to generate analysis report: {}", e);
                    return Err(e);
                }
            }
        }
        Err(e) => {
            error!("Failed to start dynamic analysis: {}", e);
            return Err(e);
        }
    }
    
    Ok(())
}

fn list_available_sandboxes(dynamic_manager: &DynamicAnalysisManager) -> Result<()> {
    println!("Available Sandboxes:");
    println!("===================");
    
    for (name, config) in &dynamic_manager.sandboxes {
        println!("Name: {}", name);
        println!("  Type: {:?}", config.sandbox_type);
        println!("  Network Isolation: {}", config.network_isolation);
        println!("  File System Isolation: {}", config.file_system_isolation);
        println!("  Timeout: {} seconds", config.timeout_seconds);
        println!("  Capabilities: {:?}", config.capabilities);
        
        if let Some(ref image) = config.container_image {
            println!("  Container Image: {}", image);
        }
        
        if let Some(ref snapshot) = config.vm_snapshot {
            println!("  VM Snapshot: {}", snapshot);
        }
        
        println!();
    }
    
    println!("Monitoring Tools:");
    println!("=================");
    
    for tool in &dynamic_manager.monitoring_tools {
        println!("Name: {}", tool.name);
        println!("  Type: {:?}", tool.tool_type);
        println!("  Executable: {}", tool.executable_path);
        println!("  Output Format: {:?}", tool.output_format);
        println!("  Capabilities: {:?}", tool.capabilities);
        println!();
    }
    
    Ok(())
}

fn show_session_status(dynamic_manager: &DynamicAnalysisManager, session_id: &str) -> Result<()> {
    match dynamic_manager.get_session_status(session_id) {
        Some(status) => {
            println!("Session ID: {}", session_id);
            println!("Status: {:?}", status);
            
            // Find the session for more details
            if let Some(session) = dynamic_manager.active_analyses.iter().find(|s| s.id == session_id) {
                println!("Component: {}", session.component_id);
                println!("Sandbox: {}", session.sandbox_name);
                println!("Start Time: {}", session.start_time.format("%Y-%m-%d %H:%M:%S UTC"));
                
                if let Some(end_time) = session.end_time {
                    println!("End Time: {}", end_time.format("%Y-%m-%d %H:%M:%S UTC"));
                    let duration = end_time.signed_duration_since(session.start_time);
                    println!("Duration: {} seconds", duration.num_seconds());
                }
                
                println!("Observations: {}", session.observations.len());
                println!("Network Activities: {}", session.network_activity.len());
                println!("Process Activities: {}", session.process_activity.len());
                println!("File Activities: {}", session.file_activity.len());
                println!("Risk Indicators: {}", session.risk_indicators.len());
            }
        }
        None => {
            println!("Session '{}' not found", session_id);
        }
    }
    
    Ok(())
}

fn generate_session_report(
    dynamic_manager: &DynamicAnalysisManager, 
    session_id: &str,
    db_path: &Path
) -> Result<()> {
    match dynamic_manager.generate_analysis_report(session_id) {
        Ok(report) => {
            println!("Dynamic Analysis Report");
            println!("=======================");
            display_analysis_summary(&report);
            
            // Store in database if not already stored
            let db = open_database(db_path)?;
            let conn = db.connection();
            
            let analysis_result = AnalysisResult::new(
                report.component_id.clone(),
                AnalysisType::DynamicAnalysis,
                serde_json::to_value(&report)?
            );
            
            // Try to insert, ignore if already exists
            match analysis_result.insert(conn) {
                Ok(()) => info!("Report saved to database"),
                Err(e) => warn!("Report may already exist in database: {}", e),
            }
        }
        Err(e) => {
            error!("Failed to generate report for session {}: {}", session_id, e);
            return Err(e);
        }
    }
    
    Ok(())
}

fn monitor_analysis_progress(
    dynamic_manager: &mut DynamicAnalysisManager,
    session_id: &str,
    timeout_seconds: u64
) -> Result<()> {
    info!("Monitoring analysis progress...");
    
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_seconds);
    
    loop {
        std::thread::sleep(Duration::from_secs(5)); // Check every 5 seconds
        
        match dynamic_manager.get_session_status(session_id) {
            Some(status) => {
                match status {
                    AnalysisStatus::Completed => {
                        info!("Analysis completed successfully");
                        return Ok(());
                    }
                    AnalysisStatus::Failed(err) => {
                        error!("Analysis failed: {}", err);
                        return Err(anyhow::anyhow!("Analysis failed: {}", err));
                    }
                    AnalysisStatus::TimedOut => {
                        warn!("Analysis timed out");
                        return Err(anyhow::anyhow!("Analysis timed out"));
                    }
                    AnalysisStatus::Running => {
                        info!("Analysis still running... ({:.0}s elapsed)", start.elapsed().as_secs_f64());
                    }
                    AnalysisStatus::Queued => {
                        info!("Analysis queued... ({:.0}s elapsed)", start.elapsed().as_secs_f64());
                    }
                }
            }
            None => {
                error!("Session not found: {}", session_id);
                return Err(anyhow::anyhow!("Session not found"));
            }
        }
        
        // Check for timeout
        if start.elapsed() > timeout {
            warn!("Analysis monitoring timed out after {} seconds", timeout_seconds);
            dynamic_manager.update_session_status(session_id, AnalysisStatus::TimedOut)?;
            return Err(anyhow::anyhow!("Analysis timed out"));
        }
    }
}

fn display_analysis_summary(report: &crate::dynamic::DynamicAnalysisReport) {
    println!("\nAnalysis Summary:");
    println!("================");
    println!("Session ID: {}", report.session_id);
    println!("Component ID: {}", report.component_id);
    
    if let Some(duration) = &report.analysis_duration {
        println!("Analysis Duration: {} seconds", duration.as_secs());
    }
    
    println!("Risk Score: {:.1}/100", report.risk_score);
    println!("Risk Level: {:?}", report.risk_level);
    
    println!("\nNetwork Summary:");
    println!("  Total Connections: {}", report.network_summary.total_connections);
    println!("  Unique Destinations: {}", report.network_summary.unique_destinations);
    println!("  Bytes Sent: {}", report.network_summary.total_bytes_sent);
    println!("  Bytes Received: {}", report.network_summary.total_bytes_received);
    println!("  Suspicious Connections: {}", report.network_summary.suspicious_connections);
    
    println!("\nProcess Summary:");
    println!("  Total Processes: {}", report.process_summary.total_processes);
    println!("  Unique Process Names: {}", report.process_summary.unique_process_names);
    println!("  Child Processes: {}", report.process_summary.child_processes);
    
    println!("\nFile Summary:");
    println!("  Files Created: {}", report.file_summary.files_created);
    println!("  Files Modified: {}", report.file_summary.files_modified);
    println!("  Files Deleted: {}", report.file_summary.files_deleted);
    println!("  Total File Operations: {}", report.file_summary.total_file_operations);
    
    if !report.behavioral_indicators.is_empty() {
        println!("\nBehavioral Indicators:");
        for indicator in &report.behavioral_indicators {
            println!("  - {}", indicator);
        }
    }
    
    if !report.recommendations.is_empty() {
        println!("\nRecommendations:");
        for recommendation in &report.recommendations {
            println!("  - {}", recommendation);
        }
    }
}
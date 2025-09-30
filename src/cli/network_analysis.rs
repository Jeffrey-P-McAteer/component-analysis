use crate::database::{open_database, ComponentQueries};
use crate::network::{NetworkTopologyAnalyzer, NetworkTopologyReport};
use crate::types::{AnalysisResult, AnalysisType};
use anyhow::Result;
use log::{info, warn};
use std::path::Path;

pub fn run(
    db_path: &Path,
    segment: Option<&str>,
    attack_paths: bool,
    threats: bool,
    export_path: Option<&Path>,
    security_report: bool,
    stats: bool,
) -> Result<()> {
    info!("Starting network topology analysis");
    
    // Open database and get components
    let db = open_database(db_path)?;
    let conn = db.connection();
    
    // Get all components for network analysis
    let components = ComponentQueries::get_all(conn)?;
    info!("Loaded {} components for network analysis", components.len());
    
    // Filter components if segment is specified
    let filtered_components = if let Some(segment_filter) = segment {
        filter_components_by_segment(&components, segment_filter)
    } else {
        components
    };
    
    info!("Analyzing {} components", filtered_components.len());
    
    if filtered_components.is_empty() {
        warn!("No components found for network analysis");
        return Ok(());
    }
    
    // Initialize network topology analyzer
    let mut analyzer = NetworkTopologyAnalyzer::new();
    
    // Perform network topology discovery
    let topology_report = analyzer.discover_network_topology(&filtered_components)?;
    
    if stats {
        display_network_statistics(&topology_report);
    }
    
    if attack_paths {
        display_attack_paths(&analyzer);
    }
    
    if threats {
        display_threat_indicators(&analyzer);
    }
    
    if security_report {
        generate_security_report(&analyzer, &topology_report)?;
    }
    
    if let Some(export_file) = export_path {
        export_topology_data(&analyzer, &topology_report, export_file)?;
    }
    
    // Store analysis results in database
    store_network_analysis_results(&filtered_components, &analyzer, &topology_report, conn)?;
    
    // Display summary
    display_analysis_summary(&topology_report);
    
    info!("Network topology analysis completed");
    Ok(())
}

fn filter_components_by_segment(components: &[crate::types::Component], segment: &str) -> Vec<crate::types::Component> {
    info!("Filtering components by network segment: {}", segment);
    
    // Parse CIDR notation (simplified)
    let network_parts: Vec<&str> = segment.split('/').collect();
    if network_parts.len() != 2 {
        warn!("Invalid CIDR notation: {}", segment);
        return components.to_vec();
    }
    
    let network_addr = network_parts[0];
    let prefix_parts: Vec<&str> = network_addr.split('.').collect();
    
    if prefix_parts.len() != 4 {
        warn!("Invalid IPv4 address: {}", network_addr);
        return components.to_vec();
    }
    
    // Simple /24 subnet filtering
    let subnet_prefix = format!("{}.{}.{}", prefix_parts[0], prefix_parts[1], prefix_parts[2]);
    
    components.iter()
        .filter(|component| {
            if let Some(ip_value) = component.metadata.get("ip_address") {
                if let Some(ip_str) = ip_value.as_str() {
                    return ip_str.starts_with(&subnet_prefix);
                }
            }
            false
        })
        .cloned()
        .collect()
}

fn display_network_statistics(report: &NetworkTopologyReport) {
    println!("Network Topology Statistics");
    println!("===========================");
    println!("Topology Type: {:?}", report.topology_type);
    println!("Total Nodes: {}", report.total_nodes);
    println!("Total Edges: {}", report.total_edges);
    println!("Network Segments: {}", report.network_segments);
    println!("Discovered Hosts: {}", report.discovered_hosts);
    println!("Communication Patterns: {}", report.communication_patterns);
    println!("Attack Paths: {}", report.attack_paths);
    println!("Threat Indicators: {}", report.threat_indicators);
    println!("Security Score: {:.2}/1.0", report.security_score);
    
    println!("\nNetwork Health:");
    println!("Overall Score: {:.2}/1.0", report.network_health.overall_score);
    println!("Threat Level: {:?}", report.network_health.threat_level);
    println!("Connectivity Health: {:.2}/1.0", report.network_health.connectivity_health);
    println!("Segmentation Quality: {:.2}/1.0", report.network_health.segmentation_quality);
    
    if !report.high_risk_nodes.is_empty() {
        println!("\nHigh Risk Nodes:");
        for node in &report.high_risk_nodes {
            println!("  - {}", node);
        }
    }
    
    if !report.critical_paths.is_empty() {
        println!("\nCritical Attack Paths:");
        for path in &report.critical_paths {
            println!("  - {}", path);
        }
    }
}

fn display_attack_paths(analyzer: &NetworkTopologyAnalyzer) {
    println!("\nAttack Path Analysis");
    println!("===================");
    
    if analyzer.attack_paths.is_empty() {
        println!("No attack paths identified.");
        return;
    }
    
    for (i, path) in analyzer.attack_paths.iter().enumerate() {
        println!("Attack Path #{}", i + 1);
        println!("  ID: {}", path.id);
        println!("  Start: {} -> Target: {}", path.start_node, path.target_node);
        println!("  Path: {}", path.path_nodes.join(" -> "));
        println!("  Difficulty Score: {:.2}", path.difficulty_score);
        println!("  Impact Score: {:.2}", path.impact_score);
        println!("  Probability: {:.2}", path.probability);
        
        if !path.attack_techniques.is_empty() {
            println!("  Techniques:");
            for technique in &path.attack_techniques {
                println!("    - {} ({})", technique.name, 
                    technique.mitre_id.as_deref().unwrap_or("N/A"));
                println!("      {}", technique.description);
            }
        }
        
        if !path.mitigation_strategies.is_empty() {
            println!("  Mitigations:");
            for mitigation in &path.mitigation_strategies {
                println!("    - {}", mitigation);
            }
        }
        
        println!();
    }
}

fn display_threat_indicators(analyzer: &NetworkTopologyAnalyzer) {
    println!("\nThreat Indicators");
    println!("================");
    
    if analyzer.threat_indicators.is_empty() {
        println!("No threat indicators detected.");
        return;
    }
    
    // Group by severity
    let mut critical_threats = Vec::new();
    let mut high_threats = Vec::new();
    let mut medium_threats = Vec::new();
    let mut low_threats = Vec::new();
    
    for indicator in &analyzer.threat_indicators {
        match indicator.severity {
            crate::types::RiskLevel::Critical => critical_threats.push(indicator),
            crate::types::RiskLevel::High => high_threats.push(indicator),
            crate::types::RiskLevel::Medium => medium_threats.push(indicator),
            crate::types::RiskLevel::Low => low_threats.push(indicator),
        }
    }
    
    for (severity, threats) in [
        ("CRITICAL", critical_threats),
        ("HIGH", high_threats),
        ("MEDIUM", medium_threats),
        ("LOW", low_threats),
    ] {
        if !threats.is_empty() {
            println!("\n{} Severity Threats:", severity);
            for threat in threats {
                println!("  Type: {:?}", threat.indicator_type);
                println!("  Description: {}", threat.description);
                println!("  Affected Nodes: {}", threat.affected_nodes.join(", "));
                println!("  First Detected: {}", threat.first_detected.format("%Y-%m-%d %H:%M:%S"));
                println!("  Last Detected: {}", threat.last_detected.format("%Y-%m-%d %H:%M:%S"));
                
                if !threat.evidence.is_empty() {
                    println!("  Evidence:");
                    for evidence in &threat.evidence {
                        println!("    - {}", evidence);
                    }
                }
                
                if !threat.recommendations.is_empty() {
                    println!("  Recommendations:");
                    for rec in &threat.recommendations {
                        println!("    - {}", rec);
                    }
                }
                
                println!();
            }
        }
    }
}

fn generate_security_report(analyzer: &NetworkTopologyAnalyzer, report: &NetworkTopologyReport) -> Result<()> {
    println!("\nNetwork Security Report");
    println!("======================");
    
    // Executive Summary
    println!("EXECUTIVE SUMMARY");
    println!("-----------------");
    println!("Network Security Score: {:.1}%", report.security_score * 100.0);
    
    let risk_assessment = match report.network_health.threat_level {
        crate::types::RiskLevel::Low => "LOW - Network security appears adequate",
        crate::types::RiskLevel::Medium => "MEDIUM - Some security concerns identified",
        crate::types::RiskLevel::High => "HIGH - Significant security risks present", 
        crate::types::RiskLevel::Critical => "CRITICAL - Immediate security attention required",
    };
    println!("Risk Assessment: {}", risk_assessment);
    
    // Key Findings
    println!("\nKEY FINDINGS");
    println!("------------");
    println!("• {} network nodes analyzed", report.total_nodes);
    println!("• {} communication patterns identified", report.communication_patterns);
    println!("• {} potential attack paths discovered", report.attack_paths);
    println!("• {} threat indicators detected", report.threat_indicators);
    
    if report.attack_paths > 0 {
        println!("• {} critical attack paths require immediate attention", report.critical_paths.len());
    }
    
    if report.threat_indicators > 0 {
        let critical_threats = analyzer.threat_indicators.iter()
            .filter(|t| matches!(t.severity, crate::types::RiskLevel::Critical))
            .count();
        if critical_threats > 0 {
            println!("• {} critical threat indicators need urgent response", critical_threats);
        }
    }
    
    // Network Topology Analysis
    println!("\nNETWORK TOPOLOGY ANALYSIS");
    println!("-------------------------");
    println!("Topology Type: {:?}", report.topology_type);
    println!("Network Segmentation: {} segments identified", report.network_segments);
    println!("Segmentation Quality: {:.1}%", report.network_health.segmentation_quality * 100.0);
    
    match report.topology_type {
        crate::network::TopologyType::Star => {
            println!("Analysis: Star topology provides centralized control but creates single point of failure");
        }
        crate::network::TopologyType::Mesh => {
            println!("Analysis: Mesh topology provides redundancy but increases attack surface");
        }
        crate::network::TopologyType::Hybrid => {
            println!("Analysis: Hybrid topology balances performance and security considerations");
        }
        _ => {
            println!("Analysis: Network topology requires further investigation for security implications");
        }
    }
    
    // Recommendations
    println!("\nRECOMMENDATIONS");
    println!("---------------");
    
    let mut priority_recommendations = Vec::new();
    let mut general_recommendations = Vec::new();
    
    for rec in &report.recommendations {
        if rec.contains("critical") || rec.contains("urgent") || rec.contains("immediate") {
            priority_recommendations.push(rec);
        } else {
            general_recommendations.push(rec);
        }
    }
    
    if !priority_recommendations.is_empty() {
        println!("Priority Actions:");
        for (i, rec) in priority_recommendations.iter().enumerate() {
            println!("{}. {}", i + 1, rec);
        }
        println!();
    }
    
    println!("General Recommendations:");
    for (i, rec) in report.recommendations.iter().enumerate() {
        if !priority_recommendations.contains(&rec) {
            println!("{}. {}", i + 1, rec);
        }
    }
    
    // Additional security recommendations based on analysis
    println!("\nADDITIONAL SECURITY MEASURES");
    println!("-----------------------------");
    
    if report.network_health.segmentation_quality < 0.5 {
        println!("• Implement network micro-segmentation to limit blast radius");
    }
    
    if report.attack_paths > 5 {
        println!("• Deploy network access control (NAC) to prevent lateral movement");
    }
    
    if report.threat_indicators > 3 {
        println!("• Enhance network monitoring with SIEM/SOAR integration");
        println!("• Implement network behavior analytics for anomaly detection");
    }
    
    println!("• Regular network topology review and security assessment");
    println!("• Incident response plan testing for network security events");
    println!("• Employee training on network security best practices");
    
    Ok(())
}

fn export_topology_data(analyzer: &NetworkTopologyAnalyzer, report: &NetworkTopologyReport, export_path: &Path) -> Result<()> {
    info!("Exporting network topology data to: {}", export_path.display());
    
    let export_data = serde_json::json!({
        "export_timestamp": chrono::Utc::now().to_rfc3339(),
        "topology_report": report,
        "network_graph": analyzer.network_graph,
        "discovered_hosts": analyzer.discovered_hosts,
        "network_segments": analyzer.network_segments,
        "communication_patterns": analyzer.communication_patterns,
        "attack_paths": analyzer.attack_paths,
        "threat_indicators": analyzer.threat_indicators
    });
    
    std::fs::write(export_path, serde_json::to_string_pretty(&export_data)?)?;
    info!("Network topology data exported successfully");
    
    Ok(())
}

fn store_network_analysis_results(
    components: &[crate::types::Component],
    analyzer: &NetworkTopologyAnalyzer,
    report: &NetworkTopologyReport,
    conn: &rusqlite::Connection,
) -> Result<()> {
    info!("Storing network analysis results in database");
    
    // Store analysis results for each component that participated in the analysis
    for component in components {
        let analysis_result = AnalysisResult::new(
            component.id.clone(),
            AnalysisType::NetworkAnalysis,
            serde_json::json!({
                "topology_report": report,
                "node_info": analyzer.network_graph.nodes.get(&component.id),
                "communication_patterns": analyzer.communication_patterns.iter()
                    .filter(|p| p.source_nodes.contains(&component.id) || p.target_nodes.contains(&component.id))
                    .collect::<Vec<_>>(),
                "threat_indicators": analyzer.threat_indicators.iter()
                    .filter(|t| t.affected_nodes.contains(&component.id))
                    .collect::<Vec<_>>(),
                "attack_paths": analyzer.attack_paths.iter()
                    .filter(|p| p.path_nodes.contains(&component.id))
                    .collect::<Vec<_>>(),
            })
        );
        
        analysis_result.insert(conn)?;
    }
    
    info!("Network analysis results stored successfully");
    Ok(())
}

fn display_analysis_summary(report: &NetworkTopologyReport) {
    println!("\nNetwork Analysis Summary");
    println!("=======================");
    println!("✓ Network topology discovery completed");
    println!("✓ {} nodes and {} connections analyzed", report.total_nodes, report.total_edges);
    println!("✓ {} network segments identified", report.network_segments);
    println!("✓ {} communication patterns analyzed", report.communication_patterns);
    
    if report.attack_paths > 0 {
        println!("⚠ {} potential attack paths identified", report.attack_paths);
    }
    
    if report.threat_indicators > 0 {
        println!("⚠ {} threat indicators detected", report.threat_indicators);
    } else {
        println!("✓ No immediate threat indicators detected");
    }
    
    println!("\nOverall Network Security Score: {:.1}%", report.security_score * 100.0);
    
    let status_emoji = match report.network_health.threat_level {
        crate::types::RiskLevel::Low => "[SUCCESS]",
        crate::types::RiskLevel::Medium => "[WARNING]",
        crate::types::RiskLevel::High => "🔶",
        crate::types::RiskLevel::Critical => "🔴",
    };
    
    println!("{} Network Threat Level: {:?}", status_emoji, report.network_health.threat_level);
}
use crate::database::{open_database, ComponentQueries};
use crate::network::{NetworkScanner, ScanConfig, ScanType, PortRange};
use crate::types::{Component, ComponentType, Relationship, RelationshipType};
use anyhow::Result;
use log::{info, warn, error};
use std::path::Path;

pub fn run(
    db_path: &Path,
    target: &str,
    ports: &str,
    scan_type: &str,
    timeout: u64,
    threads: usize,
    service_detection: bool,
    aggressive: bool,
    export_path: Option<&Path>,
    save_to_db: bool,
    verbose_output: bool,
) -> Result<()> {
    info!("Starting network scan for target: {}", target);
    
    // Parse scan configuration
    let scan_config = create_scan_config(
        target,
        ports,
        scan_type,
        timeout,
        threads,
        service_detection,
        aggressive,
    )?;
    
    // Initialize network scanner
    let mut scanner = NetworkScanner::new(scan_config);
    
    // Perform the scan
    let scan_result = scanner.scan_network(target)?;
    
    // Display results
    display_scan_results(&scanner, &scan_result, verbose_output);
    
    // Save to database if requested
    if save_to_db {
        save_scan_results_to_database(&scanner, db_path)?;
    }
    
    // Export results if requested
    if let Some(export_file) = export_path {
        export_scan_results(&scanner, &scan_result, export_file)?;
    }
    
    info!("Network scan completed successfully");
    Ok(())
}

fn create_scan_config(
    target: &str,
    ports: &str,
    scan_type: &str,
    timeout: u64,
    threads: usize,
    service_detection: bool,
    aggressive: bool,
) -> Result<ScanConfig> {
    // Parse port ranges
    let port_ranges = parse_port_ranges(ports)?;
    
    // Parse scan type
    let scan_type_enum = match scan_type.to_lowercase().as_str() {
        "tcp-connect" => ScanType::TcpConnect,
        "icmp-ping" => ScanType::IcmpPing,
        "comprehensive" => ScanType::ComprehensiveScan,
        "service-discovery" => ScanType::ServiceDiscovery,
        _ => {
            warn!("Unknown scan type '{}', defaulting to tcp-connect", scan_type);
            ScanType::TcpConnect
        }
    };
    
    Ok(ScanConfig {
        target_ranges: vec![target.to_string()],
        port_ranges,
        scan_type: scan_type_enum.clone(),
        timeout_ms: timeout,
        max_threads: threads,
        tcp_scan: true,
        icmp_scan: matches!(scan_type_enum, ScanType::IcmpPing | ScanType::ComprehensiveScan),
        service_detection,
        aggressive_scan: aggressive,
    })
}

fn parse_port_ranges(ports: &str) -> Result<Vec<PortRange>> {
    let mut port_ranges = Vec::new();
    
    for range_str in ports.split(',') {
        let range_str = range_str.trim();
        
        if range_str.contains('-') {
            // Range format (e.g., "1-1000")
            let parts: Vec<&str> = range_str.split('-').collect();
            if parts.len() == 2 {
                let start_port: u16 = parts[0].parse()?;
                let end_port: u16 = parts[1].parse()?;
                port_ranges.push(PortRange { start_port, end_port });
            } else {
                return Err(anyhow::anyhow!("Invalid port range format: {}", range_str));
            }
        } else {
            // Single port
            let port: u16 = range_str.parse()?;
            port_ranges.push(PortRange { start_port: port, end_port: port });
        }
    }
    
    if port_ranges.is_empty() {
        // Default to common ports
        port_ranges.push(PortRange { start_port: 1, end_port: 1000 });
    }
    
    Ok(port_ranges)
}

fn display_scan_results(
    scanner: &NetworkScanner,
    scan_result: &crate::network::ScanResult,
    verbose: bool,
) {
    println!("Network Scan Results");
    println!("===================");
    println!("Target: {}", scan_result.target);
    println!("Scan Duration: {:.2} seconds", 
        (scan_result.scan_end - scan_result.scan_start).num_seconds());
    println!("Hosts Discovered: {}", scan_result.hosts_discovered);
    println!("Ports Scanned: {}", scan_result.ports_scanned);
    println!("Services Identified: {}", scan_result.services_identified);
    println!("Scan Status: {:?}", scan_result.scan_status);
    
    if verbose && !scanner.discovered_hosts.is_empty() {
        println!("\nDiscovered Hosts:");
        println!("================");
        
        for host in &scanner.discovered_hosts {
            println!("\nHost: {}", host.ip_address);
            
            if let Some(hostname) = &host.hostname {
                println!("  Hostname: {}", hostname);
            }
            
            if let Some(mac) = &host.mac_address {
                println!("  MAC Address: {}", mac);
            }
            
            println!("  Responsive: {}", host.responsive);
            println!("  ICMP Responsive: {}", host.icmp_responsive);
            
            if let Some(os) = &host.operating_system {
                println!("  OS: {} (Confidence: {:.1}%)", os.os_name, os.confidence * 100.0);
            }
            
            if !host.open_ports.is_empty() {
                println!("  Open Ports:");
                for port in &host.open_ports {
                    print!("    {}/{:?}", port.port, port.protocol);
                    
                    if let Some(service) = &port.service {
                        print!(" - {}", service.name);
                        if let Some(version) = &service.version {
                            print!(" {}", version);
                        }
                        if let Some(product) = &service.product {
                            print!(" ({})", product);
                        }
                    }
                    
                    if let Some(banner) = &port.banner {
                        print!(" [{}]", banner.chars().take(50).collect::<String>());
                    }
                    
                    println!();
                }
            }
            
            if let Some(response_time) = host.response_time {
                println!("  Response Time: {:?}", response_time);
            }
        }
    } else if !scanner.discovered_hosts.is_empty() {
        println!("\nDiscovered Host IPs:");
        for host in &scanner.discovered_hosts {
            print!("{} ", host.ip_address);
        }
        println!();
    }
}

fn save_scan_results_to_database(scanner: &NetworkScanner, db_path: &Path) -> Result<()> {
    info!("Saving scan results to database");
    
    // Open database
    let db = open_database(db_path)?;
    let conn = db.connection();
    
    // Convert scan results to components
    let components = scanner.convert_to_components();
    
    info!("Saving {} components to database", components.len());
    
    // Log categorized results for analysis
    let mut category_counts = std::collections::HashMap::new();
    for component in &components {
        if let Some(category) = component.metadata.get("responsiveness_category")
            .and_then(|v| v.as_str()) {
            *category_counts.entry(category).or_insert(0) += 1;
        }
    }
    
    if !category_counts.is_empty() {
        info!("Host responsiveness breakdown:");
        for (category, count) in category_counts {
            info!("  {}: {} hosts", category, count);
        }
    }
    
    // Save each component
    for component in &components {
        component.insert(conn)?;
    }
    
    // Create relationships between hosts and services
    let mut relationships = Vec::new();
    
    for host in &scanner.discovered_hosts {
        let host_id = host.ip_address.to_string();
        
        // Create relationships between host and its services
        for port in &host.open_ports {
            if port.service.is_some() {
                let service_id = format!("{}:{}", host.ip_address, port.port);
                
                let relationship = Relationship::new(
                    host_id.clone(),
                    service_id,
                    RelationshipType::Contains,
                    serde_json::json!({
                        "relationship_type": "host_runs_service",
                        "port": port.port,
                        "protocol": format!("{:?}", port.protocol),
                        "scan_discovered": true
                    }),
                );
                
                relationships.push(relationship);
            }
        }
    }
    
    // Save relationships
    for relationship in &relationships {
        relationship.insert(conn)?;
    }
    
    info!("Saved {} components and {} relationships to database", 
        components.len(), relationships.len());
    
    Ok(())
}

fn export_scan_results(
    scanner: &NetworkScanner,
    scan_result: &crate::network::ScanResult,
    export_path: &Path,
) -> Result<()> {
    info!("Exporting scan results to: {}", export_path.display());
    
    let export_data = serde_json::json!({
        "scan_result": scan_result,
        "discovered_hosts": scanner.discovered_hosts,
        "scan_config": scanner.scan_config,
        "export_timestamp": chrono::Utc::now().to_rfc3339(),
        "version": "1.0"
    });
    
    std::fs::write(export_path, serde_json::to_string_pretty(&export_data)?)?;
    info!("Scan results exported successfully");
    
    Ok(())
}

pub fn list_hosts_and_services(db_path: &Path) -> Result<()> {
    info!("Listing hosts and services from database");
    
    let db = open_database(db_path)?;
    let conn = db.connection();
    
    // Get all host components
    let all_components = ComponentQueries::get_all(conn)?;
    let hosts: Vec<&Component> = all_components.iter()
        .filter(|c| c.component_type == ComponentType::Host)
        .collect();
    
    if hosts.is_empty() {
        println!("No hosts found in database. Run a network scan first.");
        return Ok(());
    }
    
    println!("Hosts and Services in Database");
    println!("=============================");
    
    for host in hosts {
        println!("\nHost: {} ({})", host.name, host.id);
        
        // Extract metadata
        if let Some(ip) = host.metadata.get("ip_address").and_then(|v| v.as_str()) {
            println!("  IP Address: {}", ip);
        }
        
        if let Some(hostname) = host.metadata.get("hostname").and_then(|v| v.as_str()) {
            println!("  Hostname: {}", hostname);
        }
        
        if let Some(os) = host.metadata.get("operating_system").and_then(|v| v.as_str()) {
            println!("  OS: {}", os);
        }
        
        // Find services running on this host
        let services: Vec<&Component> = all_components.iter()
            .filter(|c| {
                c.component_type == ComponentType::Process &&
                c.metadata.get("host_ip").and_then(|v| v.as_str()) == 
                    host.metadata.get("ip_address").and_then(|v| v.as_str())
            })
            .collect();
        
        if !services.is_empty() {
            println!("  Services:");
            for service in services {
                print!("    {} ", service.name);
                
                if let Some(port) = service.metadata.get("port").and_then(|v| v.as_u64()) {
                    print!("(port {})", port);
                }
                
                if let Some(version) = service.metadata.get("version").and_then(|v| v.as_str()) {
                    print!(" - version {}", version);
                }
                
                if let Some(product) = service.metadata.get("product").and_then(|v| v.as_str()) {
                    print!(" [{}]", product);
                }
                
                println!();
            }
        }
    }
    
    Ok(())
}

pub fn query_hosts_by_responsiveness(db_path: &Path, category: Option<&str>) -> Result<()> {
    info!("Querying hosts by responsiveness from database");
    
    let db = open_database(db_path)?;
    let conn = db.connection();
    
    // Get all host components
    let all_components = ComponentQueries::get_all(conn)?;
    let hosts: Vec<&Component> = all_components.iter()
        .filter(|c| c.component_type == ComponentType::Host)
        .collect();
    
    if hosts.is_empty() {
        println!("No hosts found in database. Run a network scan first.");
        return Ok(());
    }
    
    // Filter by category if specified
    let filtered_hosts: Vec<&Component> = if let Some(filter_category) = category {
        hosts.into_iter()
            .filter(|host| {
                host.metadata.get("responsiveness_category")
                    .and_then(|v| v.as_str())
                    .map(|cat| cat == filter_category)
                    .unwrap_or(false)
            })
            .collect()
    } else {
        hosts
    };
    
    if filtered_hosts.is_empty() {
        if let Some(cat) = category {
            println!("No hosts found with responsiveness category: {}", cat);
        }
        return Ok(());
    }
    
    println!("Host Responsiveness Analysis");
    println!("===========================");
    
    if let Some(cat) = category {
        println!("Filter: {} hosts only\n", cat);
    }
    
    // Group hosts by category for summary
    let mut category_groups: std::collections::HashMap<String, Vec<&Component>> = std::collections::HashMap::new();
    
    for host in &filtered_hosts {
        let category = host.metadata.get("responsiveness_category")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        category_groups.entry(category).or_insert_with(Vec::new).push(host);
    }
    
    // Display summary
    println!("Summary:");
    for (cat, host_list) in &category_groups {
        println!("  {}: {} hosts", cat, host_list.len());
    }
    println!();
    
    // Display detailed information
    for (cat, host_list) in category_groups {
        println!("=== {} ({} hosts) ===", cat.replace('_', " ").to_uppercase(), host_list.len());
        
        for host in host_list {
            println!("Host: {} ({})", host.name, host.id);
            
            if let Some(ip) = host.metadata.get("ip_address").and_then(|v| v.as_str()) {
                println!("  IP: {}", ip);
            }
            
            if let Some(tcp_resp) = host.metadata.get("tcp_responsive").and_then(|v| v.as_bool()) {
                println!("  TCP Responsive: {}", tcp_resp);
            }
            
            if let Some(icmp_resp) = host.metadata.get("icmp_responsive").and_then(|v| v.as_bool()) {
                println!("  ICMP Responsive: {}", icmp_resp);
            }
            
            if let Some(port_count) = host.metadata.get("open_port_count").and_then(|v| v.as_u64()) {
                println!("  Open Ports: {}", port_count);
            }
            
            if let Some(scan_time) = host.metadata.get("scan_time").and_then(|v| v.as_str()) {
                println!("  Last Scan: {}", scan_time);
            }
            
            println!();
        }
    }
    
    Ok(())
}

pub fn assign_application_to_host(
    db_path: &Path,
    host_id: &str,
    application_name: &str,
    description: Option<&str>,
) -> Result<()> {
    info!("Assigning application '{}' to host '{}'", application_name, host_id);
    
    let db = open_database(db_path)?;
    let conn = db.connection();
    
    // Verify host exists
    if ComponentQueries::get_by_id(conn, host_id)?.is_none() {
        return Err(anyhow::anyhow!("Host with ID '{}' not found in database", host_id));
    }
    
    // Create application component
    let mut app_metadata = serde_json::Map::new();
    app_metadata.insert("host_id".to_string(), serde_json::Value::String(host_id.to_string()));
    app_metadata.insert("user_assigned".to_string(), serde_json::Value::Bool(true));
    app_metadata.insert("assignment_time".to_string(), 
        serde_json::Value::String(chrono::Utc::now().to_rfc3339()));
    
    if let Some(desc) = description {
        app_metadata.insert("description".to_string(), serde_json::Value::String(desc.to_string()));
    }
    
    let app_component = Component::with_full_details(
        format!("{}:app:{}", host_id, application_name),
        ComponentType::Process,
        application_name.to_string(),
        None,
        serde_json::Value::Object(app_metadata),
    );
    
    // Save application component
    app_component.insert(conn)?;
    
    // Create relationship between host and application
    let relationship = Relationship::new(
        host_id.to_string(),
        app_component.id,
        RelationshipType::Contains,
        serde_json::json!({
            "relationship_type": "host_runs_application",
            "user_assigned": true,
            "assignment_time": chrono::Utc::now().to_rfc3339()
        }),
    );
    
    relationship.insert(conn)?;
    
    println!("Successfully assigned application '{}' to host '{}'", application_name, host_id);
    Ok(())
}
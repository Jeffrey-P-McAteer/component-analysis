use crate::types::{Component, RiskLevel, ComponentType};
use anyhow::Result;
use log::{info, warn, debug};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};
use std::io::{Read, Write};
use petgraph::{Graph, Directed, graph::NodeIndex};
use chrono::{DateTime, Utc};
use std::process::Command;
use std::thread;
use std::sync::{Arc, Mutex};
use tokio::net::TcpSocket;
use tokio::time::timeout;
use futures::future::join_all;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopologyAnalyzer {
    pub network_graph: NetworkGraph,
    pub discovered_hosts: HashMap<String, NetworkHost>,
    pub network_segments: Vec<NetworkSubnet>,
    pub communication_patterns: Vec<CommunicationPattern>,
    pub attack_paths: Vec<AttackPath>,
    pub threat_indicators: Vec<NetworkThreatIndicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScanner {
    pub scan_config: ScanConfig,
    pub discovered_hosts: Vec<ScannedHost>,
    pub scan_results: HashMap<String, ScanResult>,
    pub active_scans: Vec<ScanSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub target_ranges: Vec<String>,
    pub port_ranges: Vec<PortRange>,
    pub scan_type: ScanType,
    pub timeout_ms: u64,
    pub max_threads: usize,
    pub tcp_scan: bool,
    pub icmp_scan: bool,
    pub service_detection: bool,
    pub aggressive_scan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    TcpConnect,
    TcpSyn,
    IcmpPing,
    ComprehensiveScan,
    ServiceDiscovery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedHost {
    pub ip_address: IpAddr,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub responsive: bool,
    pub open_ports: Vec<ScannedPort>,
    pub icmp_responsive: bool,
    pub operating_system: Option<OSFingerprint>,
    pub scan_time: DateTime<Utc>,
    pub response_time: Option<Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedPort {
    pub port: u16,
    pub protocol: NetworkProtocol,
    pub state: PortState,
    pub service: Option<DetectedService>,
    pub banner: Option<String>,
    pub response_time: Option<Duration>,
    pub fingerprint: Option<ServiceFingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedService {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub extra_info: Option<String>,
    pub confidence: f64,
    pub cpe: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFingerprint {
    pub protocol: String,
    pub service_type: String,
    pub banner_pattern: Option<String>,
    pub probe_response: Option<String>,
    pub version_detection: Vec<VersionMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMatch {
    pub pattern: String,
    pub product: String,
    pub version: String,
    pub info: Option<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSFingerprint {
    pub os_family: String,
    pub os_name: String,
    pub os_version: Option<String>,
    pub device_type: Option<String>,
    pub confidence: f64,
    pub tcp_fingerprint: Option<String>,
    pub icmp_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub scan_start: DateTime<Utc>,
    pub scan_end: DateTime<Utc>,
    pub hosts_discovered: usize,
    pub ports_scanned: usize,
    pub services_identified: usize,
    pub scan_status: ScanStatus,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanStatus {
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    pub session_id: String,
    pub target_range: String,
    pub scan_type: ScanType,
    pub start_time: DateTime<Utc>,
    pub status: ScanStatus,
    pub progress_percent: f32,
    pub hosts_found: usize,
    pub total_targets: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkGraph {
    pub nodes: HashMap<String, NetworkNode>,
    pub edges: Vec<NetworkEdge>,
    pub subnets: Vec<NetworkSubnet>,
    pub topology_type: TopologyType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkNode {
    pub id: String,
    pub node_type: NodeType,
    pub ip_addresses: Vec<IpAddr>,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub operating_system: Option<String>,
    pub open_ports: Vec<NetworkPort>,
    pub services: Vec<NetworkService>,
    pub vulnerability_score: f64,
    pub criticality_level: CriticalityLevel,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    Host,
    Router,
    Switch,
    Firewall,
    LoadBalancer,
    Server,
    Workstation,
    IoTDevice,
    MobileDevice,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEdge {
    pub id: String,
    pub source_node: String,
    pub target_node: String,
    pub connection_type: ConnectionType,
    pub protocol: NetworkProtocol,
    pub port_range: PortRange,
    pub bandwidth: Option<u64>,
    pub latency: Option<u32>,
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub connection_state: ConnectionState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionType {
    DirectConnection,
    RoutedConnection,
    VpnTunnel,
    WirelessConnection,
    BridgedConnection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkProtocol {
    TCP,
    UDP,
    ICMP,
    HTTP,
    HTTPS,
    SSH,
    FTP,
    SMTP,
    DNS,
    DHCP,
    SNMP,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRange {
    pub start_port: u16,
    pub end_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionState {
    Active,
    Inactive,
    Suspicious,
    Blocked,
    Monitored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPort {
    pub port: u16,
    pub protocol: NetworkProtocol,
    pub state: PortState,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkService {
    pub name: String,
    pub version: Option<String>,
    pub port: u16,
    pub protocol: NetworkProtocol,
    pub risk_level: RiskLevel,
    pub vulnerabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSubnet {
    pub id: String,
    pub cidr: String,
    pub network_type: SubnetType,
    pub vlan_id: Option<u16>,
    pub security_zone: SecurityZone,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubnetType {
    Corporate,
    DMZ,
    Internal,
    Management,
    Guest,
    IoT,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityZone {
    Trusted,
    Untrusted,
    DMZ,
    Management,
    Isolated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TopologyType {
    Star,
    Mesh,
    Bus,
    Ring,
    Tree,
    Hybrid,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CriticalityLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHost {
    pub ip_address: IpAddr,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub operating_system: Option<OperatingSystem>,
    pub device_type: DeviceType,
    pub open_ports: Vec<NetworkPort>,
    pub running_services: Vec<NetworkService>,
    pub last_activity: DateTime<Utc>,
    pub reputation_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatingSystem {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub patch_level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceType {
    Server,
    Workstation,
    Laptop,
    Mobile,
    Router,
    Switch,
    Firewall,
    PrinterScanner,
    IoT,
    Industrial,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationPattern {
    pub id: String,
    pub pattern_type: PatternType,
    pub source_nodes: Vec<String>,
    pub target_nodes: Vec<String>,
    pub frequency: u64,
    pub data_volume: u64,
    pub time_pattern: TimePattern,
    pub risk_score: f64,
    pub anomaly_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    BeaconingTraffic,
    BulkDataTransfer,
    ScanningActivity,
    LateralMovement,
    DataExfiltration,
    CommandAndControl,
    NormalBusiness,
    Suspicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimePattern {
    pub pattern_type: TimePatternType,
    pub interval_seconds: Option<u64>,
    pub active_hours: Vec<u8>, // 0-23 hours
    pub active_days: Vec<u8>,  // 0-6 days (Sunday=0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimePatternType {
    Continuous,
    Periodic,
    Scheduled,
    Irregular,
    Burst,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub id: String,
    pub start_node: String,
    pub target_node: String,
    pub path_nodes: Vec<String>,
    pub attack_techniques: Vec<AttackTechnique>,
    pub difficulty_score: f64,
    pub impact_score: f64,
    pub probability: f64,
    pub mitigation_strategies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    pub technique_id: String,
    pub name: String,
    pub mitre_id: Option<String>,
    pub description: String,
    pub prerequisites: Vec<String>,
    pub detection_methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkThreatIndicator {
    pub indicator_type: ThreatIndicatorType,
    pub severity: RiskLevel,
    pub description: String,
    pub affected_nodes: Vec<String>,
    pub evidence: Vec<String>,
    pub recommendations: Vec<String>,
    pub first_detected: DateTime<Utc>,
    pub last_detected: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatIndicatorType {
    UnauthorizedAccess,
    SuspiciousTraffic,
    MalwareBeaconing,
    DataExfiltration,
    LateralMovement,
    PrivilegeEscalation,
    NetworkScanning,
    DenialOfService,
    ManInTheMiddle,
    RogueDevice,
}

impl NetworkTopologyAnalyzer {
    pub fn new() -> Self {
        Self {
            network_graph: NetworkGraph::new(),
            discovered_hosts: HashMap::new(),
            network_segments: Vec::new(),
            communication_patterns: Vec::new(),
            attack_paths: Vec::new(),
            threat_indicators: Vec::new(),
        }
    }
    
    pub fn discover_network_topology(&mut self, components: &[Component]) -> Result<NetworkTopologyReport> {
        info!("Starting network topology discovery");
        
        // Extract network-related components
        let network_components: Vec<&Component> = components.iter()
            .filter(|c| self.is_network_related(c))
            .collect();
        
        info!("Found {} network-related components", network_components.len());
        
        // Build network graph from components
        self.build_network_graph(&network_components)?;
        
        // Discover hosts and services
        self.discover_hosts_and_services(&network_components)?;
        
        // Identify network segments
        self.identify_network_segments()?;
        
        // Analyze communication patterns
        self.analyze_communication_patterns()?;
        
        // Calculate attack paths
        self.calculate_attack_paths()?;
        
        // Detect threat indicators
        self.detect_threat_indicators()?;
        
        self.generate_topology_report()
    }
    
    fn is_network_related(&self, component: &Component) -> bool {
        match component.component_type {
            crate::types::ComponentType::Network => true,
            crate::types::ComponentType::Host => true,
            _ => {
                // Check metadata for network indicators
                component.metadata.contains_key("ip_address") ||
                component.metadata.contains_key("network_interface") ||
                component.metadata.contains_key("port") ||
                component.metadata.contains_key("protocol")
            }
        }
    }
    
    fn build_network_graph(&mut self, components: &[&Component]) -> Result<()> {
        info!("Building network graph from {} components", components.len());
        
        for component in components {
            let node = self.create_network_node(component)?;
            self.network_graph.nodes.insert(node.id.clone(), node);
        }
        
        // Build edges from relationships
        // This would typically come from network discovery or relationship data
        self.infer_network_connections()?;
        
        // Detect topology type
        self.network_graph.topology_type = self.detect_topology_type();
        
        Ok(())
    }
    
    fn create_network_node(&self, component: &Component) -> Result<NetworkNode> {
        let mut node = NetworkNode {
            id: component.id.clone(),
            node_type: self.infer_node_type(component),
            ip_addresses: Vec::new(),
            mac_address: None,
            hostname: Some(component.name.clone()),
            operating_system: None,
            open_ports: Vec::new(),
            services: Vec::new(),
            vulnerability_score: 0.0,
            criticality_level: CriticalityLevel::Medium,
            last_seen: Utc::now(),
        };
        
        // Extract IP addresses from metadata
        if let Some(ip_value) = component.metadata.get("ip_address") {
            if let Some(ip_str) = ip_value.as_str() {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    node.ip_addresses.push(ip);
                }
            }
        }
        
        // Extract MAC address
        if let Some(mac_value) = component.metadata.get("mac_address") {
            if let Some(mac_str) = mac_value.as_str() {
                node.mac_address = Some(mac_str.to_string());
            }
        }
        
        // Extract operating system info
        if let Some(os_value) = component.metadata.get("operating_system") {
            if let Some(os_str) = os_value.as_str() {
                node.operating_system = Some(os_str.to_string());
            }
        }
        
        // Extract port information
        if let Some(port_value) = component.metadata.get("port") {
            if let Some(port_num) = port_value.as_u64() {
                let port = NetworkPort {
                    port: port_num as u16,
                    protocol: NetworkProtocol::TCP, // Default assumption
                    state: PortState::Open,
                    service: component.metadata.get("service")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    version: None,
                    banner: None,
                };
                node.open_ports.push(port);
            }
        }
        
        Ok(node)
    }
    
    fn infer_node_type(&self, component: &Component) -> NodeType {
        match component.component_type {
            crate::types::ComponentType::Host => {
                // Check metadata for more specific type
                if let Some(device_type) = component.metadata.get("device_type") {
                    if let Some(type_str) = device_type.as_str() {
                        match type_str.to_lowercase().as_str() {
                            "router" => return NodeType::Router,
                            "switch" => return NodeType::Switch,
                            "firewall" => return NodeType::Firewall,
                            "server" => return NodeType::Server,
                            "workstation" => return NodeType::Workstation,
                            "iot" => return NodeType::IoTDevice,
                            "mobile" => return NodeType::MobileDevice,
                            _ => {}
                        }
                    }
                }
                NodeType::Host
            }
            crate::types::ComponentType::Network => NodeType::Switch, // Default assumption
            _ => NodeType::Unknown,
        }
    }
    
    fn infer_network_connections(&mut self) -> Result<()> {
        // This is a simplified implementation
        // In practice, this would use network discovery protocols, routing tables, etc.
        
        let node_ids: Vec<String> = self.network_graph.nodes.keys().cloned().collect();
        
        for (i, source_id) in node_ids.iter().enumerate() {
            for target_id in node_ids.iter().skip(i + 1) {
                if self.should_create_connection(source_id, target_id) {
                    let edge = NetworkEdge {
                        id: uuid::Uuid::new_v4().to_string(),
                        source_node: source_id.clone(),
                        target_node: target_id.clone(),
                        connection_type: ConnectionType::DirectConnection,
                        protocol: NetworkProtocol::TCP,
                        port_range: PortRange { start_port: 1, end_port: 65535 },
                        bandwidth: None,
                        latency: None,
                        packet_count: 0,
                        byte_count: 0,
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                        connection_state: ConnectionState::Active,
                    };
                    
                    self.network_graph.edges.push(edge);
                }
            }
        }
        
        Ok(())
    }
    
    fn should_create_connection(&self, source_id: &str, target_id: &str) -> bool {
        // Simplified heuristic - in practice this would be based on actual network data
        if let (Some(source), Some(target)) = (
            self.network_graph.nodes.get(source_id),
            self.network_graph.nodes.get(target_id)
        ) {
            // Create connections between nodes in the same subnet
            self.nodes_in_same_subnet(source, target)
        } else {
            false
        }
    }
    
    fn nodes_in_same_subnet(&self, node1: &NetworkNode, node2: &NetworkNode) -> bool {
        // Simplified subnet detection
        for ip1 in &node1.ip_addresses {
            for ip2 in &node2.ip_addresses {
                if self.same_subnet(ip1, ip2) {
                    return true;
                }
            }
        }
        false
    }
    
    fn same_subnet(&self, ip1: &IpAddr, ip2: &IpAddr) -> bool {
        match (ip1, ip2) {
            (IpAddr::V4(ipv4_1), IpAddr::V4(ipv4_2)) => {
                // Simple /24 subnet check
                let octets1 = ipv4_1.octets();
                let octets2 = ipv4_2.octets();
                octets1[0] == octets2[0] && octets1[1] == octets2[1] && octets1[2] == octets2[2]
            }
            _ => false, // Simplified - would implement proper IPv6 subnet logic
        }
    }
    
    fn discover_hosts_and_services(&mut self, _components: &[&Component]) -> Result<()> {
        info!("Discovering hosts and services");
        
        // Convert network nodes to discovered hosts
        for node in self.network_graph.nodes.values() {
            if !node.ip_addresses.is_empty() {
                let host = NetworkHost {
                    ip_address: node.ip_addresses[0],
                    hostname: node.hostname.clone(),
                    mac_address: node.mac_address.clone(),
                    operating_system: node.operating_system.as_ref().map(|os| OperatingSystem {
                        name: os.clone(),
                        version: "Unknown".to_string(),
                        architecture: "Unknown".to_string(),
                        patch_level: None,
                    }),
                    device_type: self.convert_node_type_to_device_type(&node.node_type),
                    open_ports: node.open_ports.clone(),
                    running_services: node.services.clone(),
                    last_activity: node.last_seen,
                    reputation_score: 0.5, // Default neutral score
                };
                
                self.discovered_hosts.insert(node.id.clone(), host);
            }
        }
        
        Ok(())
    }
    
    fn convert_node_type_to_device_type(&self, node_type: &NodeType) -> DeviceType {
        match node_type {
            NodeType::Host => DeviceType::Workstation,
            NodeType::Router => DeviceType::Router,
            NodeType::Switch => DeviceType::Switch,
            NodeType::Firewall => DeviceType::Firewall,
            NodeType::Server => DeviceType::Server,
            NodeType::Workstation => DeviceType::Workstation,
            NodeType::IoTDevice => DeviceType::IoT,
            NodeType::MobileDevice => DeviceType::Mobile,
            _ => DeviceType::Unknown,
        }
    }
    
    fn identify_network_segments(&mut self) -> Result<()> {
        info!("Identifying network segments");
        
        // Group nodes by subnet
        let mut subnet_groups: HashMap<String, Vec<String>> = HashMap::new();
        
        for node in self.network_graph.nodes.values() {
            for ip in &node.ip_addresses {
                let subnet_key = self.get_subnet_key(ip);
                subnet_groups.entry(subnet_key).or_insert_with(Vec::new).push(node.id.clone());
            }
        }
        
        // Create network segments
        for (subnet_key, hosts) in subnet_groups {
            let segment = NetworkSubnet {
                id: uuid::Uuid::new_v4().to_string(),
                cidr: subnet_key,
                network_type: self.infer_subnet_type(&hosts),
                vlan_id: None,
                security_zone: self.infer_security_zone(&hosts),
                hosts,
            };
            
            self.network_segments.push(segment);
        }
        
        Ok(())
    }
    
    fn get_subnet_key(&self, ip: &IpAddr) -> String {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(_) => "::0/64".to_string(), // Simplified
        }
    }
    
    fn infer_subnet_type(&self, _hosts: &[String]) -> SubnetType {
        // Simplified inference based on IP ranges
        SubnetType::Internal // Default assumption
    }
    
    fn infer_security_zone(&self, _hosts: &[String]) -> SecurityZone {
        // Simplified inference
        SecurityZone::Trusted // Default assumption
    }
    
    fn analyze_communication_patterns(&mut self) -> Result<()> {
        info!("Analyzing communication patterns");
        
        // Analyze traffic patterns from network edges
        let mut pattern_map: HashMap<String, u64> = HashMap::new();
        
        for edge in &self.network_graph.edges {
            let pattern_key = format!("{}:{}", edge.source_node, edge.target_node);
            *pattern_map.entry(pattern_key).or_insert(0) += edge.packet_count;
        }
        
        // Create communication patterns from high-traffic connections
        for (pattern_key, frequency) in pattern_map {
            if frequency > 100 { // Threshold for significant communication
                let parts: Vec<&str> = pattern_key.split(':').collect();
                if parts.len() == 2 {
                    let pattern = CommunicationPattern {
                        id: uuid::Uuid::new_v4().to_string(),
                        pattern_type: self.classify_pattern_type(frequency),
                        source_nodes: vec![parts[0].to_string()],
                        target_nodes: vec![parts[1].to_string()],
                        frequency,
                        data_volume: 0, // Would be calculated from actual data
                        time_pattern: TimePattern {
                            pattern_type: TimePatternType::Continuous,
                            interval_seconds: None,
                            active_hours: (0..24).collect(),
                            active_days: (0..7).collect(),
                        },
                        risk_score: self.calculate_pattern_risk_score(frequency),
                        anomaly_indicators: Vec::new(),
                    };
                    
                    self.communication_patterns.push(pattern);
                }
            }
        }
        
        Ok(())
    }
    
    fn classify_pattern_type(&self, frequency: u64) -> PatternType {
        match frequency {
            0..=100 => PatternType::NormalBusiness,
            101..=1000 => PatternType::BulkDataTransfer,
            1001..=10000 => PatternType::BeaconingTraffic,
            _ => PatternType::Suspicious,
        }
    }
    
    fn calculate_pattern_risk_score(&self, frequency: u64) -> f64 {
        // Simple risk scoring based on frequency
        match frequency {
            0..=100 => 0.1,
            101..=1000 => 0.3,
            1001..=10000 => 0.6,
            _ => 0.9,
        }
    }
    
    fn calculate_attack_paths(&mut self) -> Result<()> {
        info!("Calculating potential attack paths");
        
        // Build adjacency list for path finding
        let mut graph = Graph::<String, f64, Directed>::new();
        let mut node_indices: HashMap<String, NodeIndex> = HashMap::new();
        
        // Add nodes
        for node_id in self.network_graph.nodes.keys() {
            let idx = graph.add_node(node_id.clone());
            node_indices.insert(node_id.clone(), idx);
        }
        
        // Add edges with weights (inverse of security score)
        for edge in &self.network_graph.edges {
            if let (Some(&source_idx), Some(&target_idx)) = (
                node_indices.get(&edge.source_node),
                node_indices.get(&edge.target_node),
            ) {
                let weight = self.calculate_edge_vulnerability_weight(edge);
                graph.add_edge(source_idx, target_idx, weight);
            }
        }
        
        // Find attack paths between high-value targets
        let critical_nodes = self.identify_critical_nodes();
        let entry_points = self.identify_entry_points();
        
        for entry_point in &entry_points {
            for target in &critical_nodes {
                if let Some(path) = self.find_attack_path(&graph, &node_indices, entry_point, target) {
                    self.attack_paths.push(path);
                }
            }
        }
        
        Ok(())
    }
    
    fn calculate_edge_vulnerability_weight(&self, edge: &NetworkEdge) -> f64 {
        // Higher weight = easier to exploit
        let base_weight = 1.0;
        
        // Adjust based on connection state
        let state_multiplier = match edge.connection_state {
            ConnectionState::Active => 1.0,
            ConnectionState::Suspicious => 1.5,
            ConnectionState::Monitored => 0.8,
            ConnectionState::Blocked => 10.0, // Very hard to exploit
            ConnectionState::Inactive => 5.0,
        };
        
        base_weight * state_multiplier
    }
    
    fn identify_critical_nodes(&self) -> Vec<String> {
        self.network_graph.nodes.iter()
            .filter(|(_, node)| matches!(node.criticality_level, CriticalityLevel::Critical | CriticalityLevel::High))
            .map(|(id, _)| id.clone())
            .collect()
    }
    
    fn identify_entry_points(&self) -> Vec<String> {
        // Nodes with external connections or low security
        self.network_graph.nodes.iter()
            .filter(|(_, node)| node.vulnerability_score > 0.7)
            .map(|(id, _)| id.clone())
            .collect()
    }
    
    fn find_attack_path(
        &self,
        _graph: &Graph<String, f64, Directed>,
        _node_indices: &HashMap<String, NodeIndex>,
        entry_point: &str,
        target: &str,
    ) -> Option<AttackPath> {
        // Simplified path finding - would use proper graph algorithms like Dijkstra
        let path = AttackPath {
            id: uuid::Uuid::new_v4().to_string(),
            start_node: entry_point.to_string(),
            target_node: target.to_string(),
            path_nodes: vec![entry_point.to_string(), target.to_string()],
            attack_techniques: vec![
                AttackTechnique {
                    technique_id: "T1021".to_string(),
                    name: "Remote Services".to_string(),
                    mitre_id: Some("T1021".to_string()),
                    description: "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections".to_string(),
                    prerequisites: vec!["Valid credentials".to_string()],
                    detection_methods: vec!["Monitor authentication logs".to_string()],
                },
            ],
            difficulty_score: 0.6,
            impact_score: 0.8,
            probability: 0.3,
            mitigation_strategies: vec![
                "Implement network segmentation".to_string(),
                "Enable multi-factor authentication".to_string(),
                "Monitor network traffic".to_string(),
            ],
        };
        
        Some(path)
    }
    
    fn detect_topology_type(&self) -> TopologyType {
        let node_count = self.network_graph.nodes.len();
        let edge_count = self.network_graph.edges.len();
        
        if node_count == 0 {
            return TopologyType::Unknown;
        }
        
        let connectivity_ratio = edge_count as f64 / node_count as f64;
        
        match connectivity_ratio {
            ratio if ratio < 1.2 => TopologyType::Star,
            ratio if ratio < 2.0 => TopologyType::Tree,
            ratio if ratio > (node_count as f64 * 0.8) => TopologyType::Mesh,
            _ => TopologyType::Hybrid,
        }
    }
    
    fn detect_threat_indicators(&mut self) -> Result<()> {
        info!("Detecting network threat indicators");
        
        // Analyze communication patterns for threats
        for pattern in &self.communication_patterns {
            if pattern.risk_score > 0.7 {
                let indicator = NetworkThreatIndicator {
                    indicator_type: match pattern.pattern_type {
                        PatternType::BeaconingTraffic => ThreatIndicatorType::MalwareBeaconing,
                        PatternType::ScanningActivity => ThreatIndicatorType::NetworkScanning,
                        PatternType::LateralMovement => ThreatIndicatorType::LateralMovement,
                        PatternType::DataExfiltration => ThreatIndicatorType::DataExfiltration,
                        PatternType::Suspicious => ThreatIndicatorType::SuspiciousTraffic,
                        _ => ThreatIndicatorType::SuspiciousTraffic,
                    },
                    severity: match pattern.risk_score {
                        score if score > 0.9 => RiskLevel::Critical,
                        score if score > 0.7 => RiskLevel::High,
                        score if score > 0.5 => RiskLevel::Medium,
                        _ => RiskLevel::Low,
                    },
                    description: format!("Suspicious communication pattern detected: {:?}", pattern.pattern_type),
                    affected_nodes: pattern.source_nodes.iter().chain(pattern.target_nodes.iter()).cloned().collect(),
                    evidence: vec![
                        format!("Frequency: {} packets", pattern.frequency),
                        format!("Data volume: {} bytes", pattern.data_volume),
                        format!("Pattern type: {:?}", pattern.pattern_type),
                    ],
                    recommendations: vec![
                        "Investigate the communication pattern".to_string(),
                        "Review logs for the affected nodes".to_string(),
                        "Consider blocking suspicious traffic".to_string(),
                    ],
                    first_detected: Utc::now(),
                    last_detected: Utc::now(),
                };
                
                self.threat_indicators.push(indicator);
            }
        }
        
        Ok(())
    }
    
    pub fn generate_topology_report(&self) -> Result<NetworkTopologyReport> {
        let report = NetworkTopologyReport {
            topology_type: self.network_graph.topology_type.clone(),
            total_nodes: self.network_graph.nodes.len(),
            total_edges: self.network_graph.edges.len(),
            network_segments: self.network_segments.len(),
            discovered_hosts: self.discovered_hosts.len(),
            communication_patterns: self.communication_patterns.len(),
            attack_paths: self.attack_paths.len(),
            threat_indicators: self.threat_indicators.len(),
            security_score: self.calculate_overall_security_score(),
            high_risk_nodes: self.identify_high_risk_nodes(),
            critical_paths: self.identify_critical_attack_paths(),
            recommendations: self.generate_security_recommendations(),
            network_health: self.assess_network_health(),
        };
        
        Ok(report)
    }
    
    fn calculate_overall_security_score(&self) -> f64 {
        if self.network_graph.nodes.is_empty() {
            return 0.0;
        }
        
        let total_vulnerability: f64 = self.network_graph.nodes.values()
            .map(|node| node.vulnerability_score)
            .sum();
        
        let avg_vulnerability = total_vulnerability / self.network_graph.nodes.len() as f64;
        
        // Invert score so higher is better
        1.0 - avg_vulnerability
    }
    
    fn identify_high_risk_nodes(&self) -> Vec<String> {
        self.network_graph.nodes.iter()
            .filter(|(_, node)| node.vulnerability_score > 0.7)
            .map(|(id, _)| id.clone())
            .collect()
    }
    
    fn identify_critical_attack_paths(&self) -> Vec<String> {
        self.attack_paths.iter()
            .filter(|path| path.impact_score > 0.7 && path.probability > 0.5)
            .map(|path| path.id.clone())
            .collect()
    }
    
    fn generate_security_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        if self.threat_indicators.len() > 5 {
            recommendations.push("High number of threat indicators detected - implement comprehensive monitoring".to_string());
        }
        
        if self.attack_paths.len() > 10 {
            recommendations.push("Multiple attack paths available - implement network segmentation".to_string());
        }
        
        if self.calculate_overall_security_score() < 0.6 {
            recommendations.push("Overall network security score is low - conduct security audit".to_string());
        }
        
        recommendations.push("Regular network topology analysis recommended".to_string());
        recommendations.push("Implement network monitoring for suspicious activities".to_string());
        
        recommendations
    }
    
    fn assess_network_health(&self) -> NetworkHealth {
        let security_score = self.calculate_overall_security_score();
        let threat_level = match self.threat_indicators.len() {
            0..=2 => RiskLevel::Low,
            3..=5 => RiskLevel::Medium,
            6..=10 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };
        
        NetworkHealth {
            overall_score: security_score,
            threat_level,
            connectivity_health: if self.network_graph.edges.len() > 0 { 0.8 } else { 0.0 },
            segmentation_quality: if self.network_segments.len() > 1 { 0.7 } else { 0.3 },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopologyReport {
    pub topology_type: TopologyType,
    pub total_nodes: usize,
    pub total_edges: usize,
    pub network_segments: usize,
    pub discovered_hosts: usize,
    pub communication_patterns: usize,
    pub attack_paths: usize,
    pub threat_indicators: usize,
    pub security_score: f64,
    pub high_risk_nodes: Vec<String>,
    pub critical_paths: Vec<String>,
    pub recommendations: Vec<String>,
    pub network_health: NetworkHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealth {
    pub overall_score: f64,
    pub threat_level: RiskLevel,
    pub connectivity_health: f64,
    pub segmentation_quality: f64,
}

impl NetworkGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            subnets: Vec::new(),
            topology_type: TopologyType::Unknown,
        }
    }
}

impl Default for NetworkTopologyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkScanner {
    pub fn new(config: ScanConfig) -> Self {
        Self {
            scan_config: config,
            discovered_hosts: Vec::new(),
            scan_results: HashMap::new(),
            active_scans: Vec::new(),
        }
    }

    pub fn scan_network(&mut self, target_range: &str) -> Result<ScanResult> {
        info!("Starting network scan for range: {}", target_range);

        let session_id = uuid::Uuid::new_v4().to_string();
        let scan_start = Utc::now();

        let session = ScanSession {
            session_id: session_id.clone(),
            target_range: target_range.to_string(),
            scan_type: self.scan_config.scan_type.clone(),
            start_time: scan_start,
            status: ScanStatus::InProgress,
            progress_percent: 0.0,
            hosts_found: 0,
            total_targets: 0,
        };

        self.active_scans.push(session);

        let hosts = match self.scan_config.scan_type {
            ScanType::TcpConnect => self.perform_tcp_scan(target_range)?,
            ScanType::IcmpPing => self.perform_icmp_scan(target_range)?,
            ScanType::ComprehensiveScan => self.perform_comprehensive_scan(target_range)?,
            ScanType::ServiceDiscovery => self.perform_service_discovery_scan(target_range)?,
            _ => self.perform_tcp_scan(target_range)?,
        };

        let scan_end = Utc::now();
        let result = ScanResult {
            target: target_range.to_string(),
            scan_start,
            scan_end,
            hosts_discovered: hosts.len(),
            ports_scanned: self.count_scanned_ports(&hosts),
            services_identified: self.count_identified_services(&hosts),
            scan_status: ScanStatus::Completed,
            error_message: None,
        };

        self.discovered_hosts.extend(hosts);
        self.scan_results.insert(session_id, result.clone());

        info!("Network scan completed. Found {} hosts", result.hosts_discovered);
        Ok(result)
    }

    fn perform_tcp_scan(&self, target_range: &str) -> Result<Vec<ScannedHost>> {
        info!("Performing TCP connect scan (always using async scanner for optimal performance)");
        
        // Always use async scanning for optimal performance and timeouts
        self.perform_tcp_scan_async(target_range)
    }

    fn perform_tcp_scan_async(&self, target_range: &str) -> Result<Vec<ScannedHost>> {
        // Create a new Tokio runtime for async scanning
        let rt = tokio::runtime::Runtime::new()?;
        
        rt.block_on(async {
            let targets = self.parse_target_range(target_range)?;
            let mut discovered_hosts = Vec::new();
            
            info!("Starting async TCP scan for {} targets", targets.len());
            
            // Create async tasks for each target
            let mut tasks = Vec::new();
            
            for target_ip in targets {
                let config = self.scan_config.clone();
                let task = async move {
                    Self::scan_tcp_host_async(target_ip, &config).await
                };
                tasks.push(task);
            }
            
            // Execute all scans concurrently with timeout
            let scan_timeout = Duration::from_secs(65); // Slightly more than individual host timeout
            let results = match timeout(scan_timeout, join_all(tasks)).await {
                Ok(results) => results,
                Err(_) => {
                    warn!("Overall TCP scan timeout after 65 seconds");
                    return Ok(Vec::new());
                }
            };
            
            // Collect results
            for result in results {
                if let Ok(host) = result {
                    if host.responsive || !host.open_ports.is_empty() {
                        discovered_hosts.push(host);
                    }
                }
            }
            
            info!("Async TCP scan completed, found {} responsive hosts", discovered_hosts.len());
            Ok(discovered_hosts)
        })
    }

    async fn scan_tcp_host_async(ip: IpAddr, config: &ScanConfig) -> Result<ScannedHost> {
        let scan_start = Instant::now();
        
        // Collect all ports to scan
        let mut all_ports = Vec::new();
        for port_range in &config.port_ranges {
            for port in port_range.start_port..=port_range.end_port {
                all_ports.push(port);
            }
        }
        
        info!("Scanning {} ports on {} with async TCP scanner", all_ports.len(), ip);
        
        // Use aggressive timeouts for 10k+ port scans
        let port_timeout = if all_ports.len() > 5000 {
            Duration::from_millis(50) // 50ms for large port ranges
        } else if all_ports.len() > 1000 {
            Duration::from_millis(100) // 100ms for medium port ranges  
        } else {
            Duration::from_millis(config.timeout_ms.min(500)) // Normal timeout for small ranges
        };
        
        // Create concurrent tasks for all ports
        let mut tasks = Vec::new();
        
        for port in all_ports {
            let task = Self::scan_single_port_async(ip, port, port_timeout);
            tasks.push(task);
        }
        
        // Execute all port scans concurrently with overall timeout
        let overall_timeout = Duration::from_secs(60); // 60 second overall limit
        let results = match timeout(overall_timeout, join_all(tasks)).await {
            Ok(results) => results,
            Err(_) => {
                warn!("TCP scan timeout after 60 seconds for {}", ip);
                return Ok(ScannedHost {
                    ip_address: ip,
                    hostname: None,
                    mac_address: None,
                    responsive: false,
                    open_ports: Vec::new(),
                    icmp_responsive: false,
                    operating_system: None,
                    scan_time: Utc::now(),
                    response_time: Some(scan_start.elapsed()),
                });
            }
        };
        
        // Collect successful open ports
        let mut open_ports = Vec::new();
        let mut responsive = false;
        
        for result in results {
            if let Ok(scanned_port) = result {
                if scanned_port.state == PortState::Open {
                    responsive = true;
                    open_ports.push(scanned_port);
                }
            }
        }
        
        let response_time = Some(scan_start.elapsed());
        let hostname = Self::resolve_hostname(ip);
        
        info!("Async TCP scan of {} completed in {:?}, found {} open ports", 
               ip, response_time.unwrap(), open_ports.len());

        Ok(ScannedHost {
            ip_address: ip,
            hostname,
            mac_address: None,
            responsive,
            open_ports,
            icmp_responsive: false,
            operating_system: None,
            scan_time: Utc::now(),
            response_time,
        })
    }

    async fn scan_single_port_async(ip: IpAddr, port: u16, timeout_duration: Duration) -> Result<ScannedPort> {
        let socket_addr = SocketAddr::new(ip, port);
        let scan_start = Instant::now();
        
        // Create socket based on IP version
        let socket = match ip {
            IpAddr::V4(_) => TcpSocket::new_v4()?,
            IpAddr::V6(_) => TcpSocket::new_v6()?,
        };
        
        // Set socket options for faster scanning
        socket.set_nodelay(true)?;
        
        let state = match timeout(timeout_duration, socket.connect(socket_addr)).await {
            Ok(Ok(_stream)) => {
                // Successfully connected - port is open
                PortState::Open
            }
            Ok(Err(_)) | Err(_) => {
                // Connection failed or timed out - port is closed/filtered
                PortState::Closed
            }
        };
        
        let response_time = Some(scan_start.elapsed());
        
        Ok(ScannedPort {
            port,
            protocol: NetworkProtocol::TCP,
            state,
            service: None, // Will be filled by service detection later
            banner: None,  // Skip banner grabbing in fast scan mode
            response_time,
            fingerprint: None,
        })
    }

    fn scan_tcp_host(ip: IpAddr, config: &ScanConfig) -> Result<ScannedHost> {
        let scan_start = Instant::now();
        
        // Collect all ports to scan
        let mut all_ports = Vec::new();
        for port_range in &config.port_ranges {
            for port in port_range.start_port..=port_range.end_port {
                all_ports.push(port);
            }
        }
        
        // Use threading for port scanning to prevent hanging on single IP
        let open_ports_data = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        let responsive_flag = Arc::new(Mutex::new(false));
        
        // Limit concurrent port scans to prevent overwhelming the target
        let max_port_threads = config.max_threads.min(50);
        
        for chunk in all_ports.chunks(max_port_threads) {
            for port in chunk {
                let port = *port;
                let config_timeout = config.timeout_ms;
                let open_ports_data = Arc::clone(&open_ports_data);
                let responsive_flag = Arc::clone(&responsive_flag);
                
                let handle = thread::spawn(move || {
                    if let Ok(scanned_port) = Self::scan_tcp_port(ip, port, config_timeout) {
                        if scanned_port.state == PortState::Open {
                            *responsive_flag.lock().unwrap() = true;
                            open_ports_data.lock().unwrap().push(scanned_port);
                        }
                    }
                });
                
                handles.push(handle);
            }
            
            // Wait for current batch to complete
            for handle in handles.drain(..) {
                let _ = handle.join();
            }
        }
        
        let open_ports = open_ports_data.lock().unwrap().clone();
        let responsive = *responsive_flag.lock().unwrap();
        let response_time = Some(scan_start.elapsed());
        let hostname = Self::resolve_hostname(ip);

        Ok(ScannedHost {
            ip_address: ip,
            hostname,
            mac_address: None,
            responsive,
            open_ports,
            icmp_responsive: false,
            operating_system: None,
            scan_time: Utc::now(),
            response_time,
        })
    }

    fn scan_tcp_port(ip: IpAddr, port: u16, timeout_ms: u64) -> Result<ScannedPort> {
        let socket_addr = SocketAddr::new(ip, port);
        let timeout = Duration::from_millis(timeout_ms);
        let scan_start = Instant::now();

        let state = match TcpStream::connect_timeout(&socket_addr, timeout) {
            Ok(mut stream) => {
                // Try to grab banner if service detection is enabled
                let _banner = Self::grab_banner(&mut stream, timeout);
                PortState::Open
            }
            Err(_) => PortState::Closed,
        };

        let response_time = Some(scan_start.elapsed());

        Ok(ScannedPort {
            port,
            protocol: NetworkProtocol::TCP,
            state,
            service: None, // Will be filled by service detection
            banner: None,
            response_time,
            fingerprint: None,
        })
    }

    fn grab_banner(stream: &mut TcpStream, timeout: Duration) -> Option<String> {
        stream.set_read_timeout(Some(timeout)).ok()?;

        let mut buffer = [0; 1024];
        match stream.read(&mut buffer) {
            Ok(bytes_read) if bytes_read > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
                Some(banner.trim().to_string())
            }
            _ => None,
        }
    }

    fn perform_icmp_scan(&self, target_range: &str) -> Result<Vec<ScannedHost>> {
        info!("Performing ICMP ping scan");

        let targets = self.parse_target_range(target_range)?;
        
        // Use threading to speed up ICMP scan and prevent hanging
        let hosts_data = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        
        for chunk in targets.chunks(self.scan_config.max_threads) {
            for target_ip in chunk {
                let ip = *target_ip;
                let config = self.scan_config.clone();
                let hosts_data = Arc::clone(&hosts_data);
                
                let handle = thread::spawn(move || {
                    if let Ok(host) = Self::ping_host_static(ip, &config) {
                        if host.icmp_responsive {
                            hosts_data.lock().unwrap().push(host);
                        }
                    }
                });
                
                handles.push(handle);
            }
            
            // Wait for current batch to complete
            for handle in handles.drain(..) {
                let _ = handle.join();
            }
        }
        
        let hosts = hosts_data.lock().unwrap().clone();
        Ok(hosts)
    }

    fn ping_host_static(ip: IpAddr, config: &ScanConfig) -> Result<ScannedHost> {
        let scan_start = Instant::now();
        
        // Calculate reasonable timeout (max 5 seconds, min 1 second)
        let timeout_seconds = ((config.timeout_ms / 1000).max(1)).min(5);
        
        // Use system ping command for ICMP
        let ping_result = match ip {
            IpAddr::V4(ipv4) => {
                Command::new("ping")
                    .arg("-c")
                    .arg("1")
                    .arg("-W")
                    .arg(format!("{}", timeout_seconds))
                    .arg(ipv4.to_string())
                    .output()
            }
            IpAddr::V6(ipv6) => {
                Command::new("ping6")
                    .arg("-c")
                    .arg("1")
                    .arg("-W")
                    .arg(format!("{}", timeout_seconds))
                    .arg(ipv6.to_string())
                    .output()
            }
        };
        
        let icmp_responsive = match ping_result {
            Ok(output) => {
                // Check if the command completed within reasonable time
                let elapsed = scan_start.elapsed();
                let max_time = Duration::from_secs(timeout_seconds + 1);
                if elapsed > max_time {
                    warn!("Ping for {} took too long: {:?}", ip, elapsed);
                    false
                } else {
                    output.status.success()
                }
            }
            Err(_) => false,
        };
        
        let response_time = Some(scan_start.elapsed());
        let hostname = Self::resolve_hostname(ip);
        
        Ok(ScannedHost {
            ip_address: ip,
            hostname,
            mac_address: None,
            responsive: icmp_responsive,
            open_ports: Vec::new(),
            icmp_responsive,
            operating_system: None,
            scan_time: Utc::now(),
            response_time,
        })
    }

    fn ping_host(&self, ip: IpAddr) -> Result<ScannedHost> {
        Self::ping_host_static(ip, &self.scan_config)
    }

    fn perform_comprehensive_scan(&self, target_range: &str) -> Result<Vec<ScannedHost>> {
        info!("Performing comprehensive scan (TCP + ICMP + Service Detection)");

        // For comprehensive scan, do ICMP first to check responsiveness
        info!("Starting with ICMP ping to check host responsiveness...");
        let icmp_hosts = self.perform_icmp_scan(target_range)?;
        
        // Count responsive vs non-responsive
        let responsive_count = icmp_hosts.iter().filter(|h| h.icmp_responsive).count();
        let total_count = icmp_hosts.len();
        let non_responsive_count = total_count - responsive_count;
        
        info!("ICMP scan results: {} responsive, {} non-responsive hosts", 
              responsive_count, non_responsive_count);
        
        if responsive_count == 0 {
            info!("No hosts responded to ICMP ping, but continuing with full TCP scan for analysis...");
        } else {
            info!("Found {} ICMP-responsive hosts, continuing with TCP scan on all targets", responsive_count);
        }

        // Always perform TCP scan on ALL targets (both responsive and non-responsive)
        // This ensures we capture complete data for analysis
        info!("Performing TCP port scan on all {} target(s)...", total_count);
        let mut tcp_hosts = self.perform_tcp_scan(target_range)?;

        // Merge ICMP results with TCP results to preserve ICMP responsiveness data
        for icmp_host in icmp_hosts {
            if let Some(tcp_host) = tcp_hosts.iter_mut().find(|h| h.ip_address == icmp_host.ip_address) {
                // Merge ICMP data into existing TCP host record
                tcp_host.icmp_responsive = icmp_host.icmp_responsive;
                if icmp_host.hostname.is_some() && tcp_host.hostname.is_none() {
                    tcp_host.hostname = icmp_host.hostname;
                }
            } else {
                // Create new host record for ICMP-only data (if no TCP ports were found)
                // This ensures we capture ICMP non-responsive hosts that had no open TCP ports
                let mut host_record = icmp_host;
                host_record.responsive = false; // Mark as non-responsive since no TCP ports found
                tcp_hosts.push(host_record);
            }
        }

        // Perform service detection on all hosts (both responsive and non-responsive)
        // This allows analysis of partial service information even from non-responsive hosts
        if self.scan_config.service_detection {
            info!("Performing service detection on {} hosts...", tcp_hosts.len());
            let service_start = Instant::now();
            let service_timeout = Duration::from_secs(60); // 60-second limit for service detection
            
            for (index, host) in tcp_hosts.iter_mut().enumerate() {
                // Check if we've exceeded the service detection timeout
                if service_start.elapsed() > service_timeout {
                    warn!("Service detection timeout reached after 60 seconds, processed {} of {} hosts", 
                          index, tcp_hosts.len());
                    break;
                }
                
                if host.responsive || !host.open_ports.is_empty() {
                    // Only attempt service detection if host has open ports
                    // Use a per-host timeout to prevent individual hosts from hanging
                    let host_start = Instant::now();
                    let host_timeout = Duration::from_secs(10); // 10 seconds per host max
                    
                    match self.detect_services_for_host_with_timeout(host, host_timeout) {
                        Ok(_) => {
                            debug!("Service detection for {} completed in {:?}", 
                                   host.ip_address, host_start.elapsed());
                        }
                        Err(e) => {
                            warn!("Service detection failed for {}: {}", host.ip_address, e);
                        }
                    }
                }
            }
            
            info!("Service detection phase completed in {:?}", service_start.elapsed());
        }

        // Log final statistics for analysis
        let hosts_with_open_ports = tcp_hosts.iter().filter(|h| h.responsive).count();
        let hosts_icmp_only = tcp_hosts.iter().filter(|h| !h.responsive && h.icmp_responsive).count();
        let hosts_completely_unresponsive = tcp_hosts.iter().filter(|h| !h.responsive && !h.icmp_responsive).count();
        
        info!("Scan complete: {} hosts with open TCP ports, {} ICMP-only responsive, {} completely unresponsive", 
              hosts_with_open_ports, hosts_icmp_only, hosts_completely_unresponsive);

        Ok(tcp_hosts)
    }

    fn perform_service_discovery_scan(&self, target_range: &str) -> Result<Vec<ScannedHost>> {
        info!("Performing service discovery scan");

        let mut hosts = self.perform_tcp_scan(target_range)?;

        // Enhanced service detection for all responsive hosts with timeout
        info!("Starting service detection phase...");
        let service_start = Instant::now();
        let service_timeout = Duration::from_secs(60); // 60-second limit
        
        for host in &mut hosts {
            if service_start.elapsed() > service_timeout {
                warn!("Service discovery timeout reached after 60 seconds, skipping remaining hosts");
                break;
            }
            
            let host_timeout = Duration::from_secs(10); // 10 seconds per host
            match self.detect_services_for_host_with_timeout(host, host_timeout) {
                Ok(_) => {}
                Err(e) => warn!("Service detection failed for {}: {}", host.ip_address, e),
            }
            
            if self.scan_config.aggressive_scan {
                match self.perform_os_fingerprinting(host) {
                    Ok(_) => {}
                    Err(e) => warn!("OS fingerprinting failed for {}: {}", host.ip_address, e),
                }
            }
        }
        
        info!("Service discovery completed in {:?}", service_start.elapsed());
        Ok(hosts)
    }

    fn detect_services_for_host(&self, host: &mut ScannedHost) -> Result<()> {
        debug!("Detecting services for host: {}", host.ip_address);

        for port in &mut host.open_ports {
            if let Some(service) = self.identify_service(host.ip_address, port.port, &port.protocol) {
                port.service = Some(service);
            }

            if let Some(fingerprint) = self.generate_service_fingerprint(host.ip_address, port.port) {
                port.fingerprint = Some(fingerprint);
            }
        }

        Ok(())
    }

    fn detect_services_for_host_with_timeout(&self, host: &mut ScannedHost, timeout: Duration) -> Result<()> {
        let start_time = Instant::now();
        debug!("Detecting services for host: {} with timeout: {:?}", host.ip_address, timeout);

        for port in &mut host.open_ports {
            // Check timeout before each port
            if start_time.elapsed() > timeout {
                warn!("Service detection timeout reached for host {}, skipping remaining ports", host.ip_address);
                break;
            }

            // Use faster service identification for timeouts
            if let Some(service) = self.identify_service_fast(host.ip_address, port.port, &port.protocol, timeout) {
                port.service = Some(service);
            }

            // Skip fingerprinting in timeout mode for speed
            // if let Some(fingerprint) = self.generate_service_fingerprint(host.ip_address, port.port) {
            //     port.fingerprint = Some(fingerprint);
            // }
        }

        Ok(())
    }

    fn identify_service_fast(&self, _ip: IpAddr, port: u16, _protocol: &NetworkProtocol, _timeout: Duration) -> Option<DetectedService> {
        // Fast service identification based only on port numbers (no network probing)
        let (service_name, _default_version): (&str, Option<&str>) = match port {
            21 => ("ftp", None),
            22 => ("ssh", None),
            23 => ("telnet", None),
            25 => ("smtp", None),
            53 => ("dns", None),
            80 => ("http", None),
            110 => ("pop3", None),
            143 => ("imap", None),
            443 => ("https", None),
            993 => ("imaps", None),
            995 => ("pop3s", None),
            3389 => ("rdp", None),
            5432 => ("postgresql", None),
            3306 => ("mysql", None),
            1433 => ("mssql", None),
            27017 => ("mongodb", None),
            6379 => ("redis", None),
            _ => ("unknown", None),
        };
        
        // Return basic service info without network probing for speed
        Some(DetectedService {
            name: service_name.to_string(),
            version: None, // Skip version detection for speed
            product: None, // Skip product detection for speed
            extra_info: None, // Skip extra info for speed
            confidence: if service_name == "unknown" { 0.3 } else { 0.7 }, // Lower confidence without probing
            cpe: None,
        })
    }

    fn identify_service(&self, ip: IpAddr, port: u16, _protocol: &NetworkProtocol) -> Option<DetectedService> {
        // Common service identification based on port numbers
        let (service_name, _default_version): (&str, Option<&str>) = match port {
            21 => ("ftp", None),
            22 => ("ssh", None),
            23 => ("telnet", None),
            25 => ("smtp", None),
            53 => ("dns", None),
            80 => ("http", None),
            110 => ("pop3", None),
            143 => ("imap", None),
            443 => ("https", None),
            993 => ("imaps", None),
            995 => ("pop3s", None),
            3389 => ("rdp", None),
            5432 => ("postgresql", None),
            3306 => ("mysql", None),
            1433 => ("mssql", None),
            27017 => ("mongodb", None),
            6379 => ("redis", None),
            _ => ("unknown", None),
        };

        // Try to get more detailed version information through banner grabbing
        let version_info = self.probe_service_version(ip, port);

        Some(DetectedService {
            name: service_name.to_string(),
            version: version_info.as_ref().and_then(|v| v.version.clone()),
            product: version_info.as_ref().and_then(|v| v.product.clone()),
            extra_info: version_info.as_ref().and_then(|v| v.extra_info.clone()),
            confidence: version_info.as_ref().map(|v| v.confidence).unwrap_or(0.5),
            cpe: None,
        })
    }

    fn probe_service_version(&self, ip: IpAddr, port: u16) -> Option<DetectedService> {
        let socket_addr = SocketAddr::new(ip, port);
        let timeout = Duration::from_millis(self.scan_config.timeout_ms);

        if let Ok(mut stream) = TcpStream::connect_timeout(&socket_addr, timeout) {
            // Send service-specific probes and analyze responses
            match port {
                80 | 8080 | 8443 => self.probe_http_service(&mut stream),
                21 => self.probe_ftp_service(&mut stream),
                22 => self.probe_ssh_service(&mut stream),
                25 => self.probe_smtp_service(&mut stream),
                _ => self.probe_generic_service(&mut stream),
            }
        } else {
            None
        }
    }

    fn probe_http_service(&self, stream: &mut TcpStream) -> Option<DetectedService> {
        let request = "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: ComponentAnalyzer/1.0\r\n\r\n";

        if stream.write_all(request.as_bytes()).is_ok() {
            let mut buffer = [0; 4096];
            if let Ok(bytes_read) = stream.read(&mut buffer) {
                let response = String::from_utf8_lossy(&buffer[..bytes_read]);

                // Parse HTTP response for server information
                if let Some(server_line) = response.lines().find(|line| line.to_lowercase().starts_with("server:")) {
                    let server_info = server_line.split(':').nth(1)?.trim();

                    // Parse server version (simplified)
                    let parts: Vec<&str> = server_info.split_whitespace().collect();
                    if !parts.is_empty() {
                        let product_version: Vec<&str> = parts[0].split('/').collect();
                        return Some(DetectedService {
                            name: "http".to_string(),
                            version: product_version.get(1).map(|v| v.to_string()),
                            product: Some(product_version[0].to_string()),
                            extra_info: if parts.len() > 1 { Some(parts[1..].join(" ")) } else { None },
                            confidence: 0.9,
                            cpe: None,
                        });
                    }
                }
            }
        }
        None
    }

    fn probe_ftp_service(&self, stream: &mut TcpStream) -> Option<DetectedService> {
        let mut buffer = [0; 1024];
        if let Ok(bytes_read) = stream.read(&mut buffer) {
            let banner = String::from_utf8_lossy(&buffer[..bytes_read]);

            // FTP servers typically send a banner immediately
            if banner.starts_with("220") {
                // Parse FTP banner for version information
                return Some(DetectedService {
                    name: "ftp".to_string(),
                    version: None,
                    product: None,
                    extra_info: Some(banner.trim().to_string()),
                    confidence: 0.8,
                    cpe: None,
                });
            }
        }
        None
    }

    fn probe_ssh_service(&self, stream: &mut TcpStream) -> Option<DetectedService> {
        let mut buffer = [0; 1024];
        if let Ok(bytes_read) = stream.read(&mut buffer) {
            let banner = String::from_utf8_lossy(&buffer[..bytes_read]);

            // SSH servers send version string
            if banner.starts_with("SSH-") {
                let version_parts: Vec<&str> = banner.trim().split('-').collect();
                if version_parts.len() >= 3 {
                    return Some(DetectedService {
                        name: "ssh".to_string(),
                        version: Some(version_parts[1].to_string()),
                        product: Some(version_parts[2].split_whitespace().next()?.to_string()),
                        extra_info: Some(banner.trim().to_string()),
                        confidence: 0.9,
                        cpe: None,
                    });
                }
            }
        }
        None
    }

    fn probe_smtp_service(&self, stream: &mut TcpStream) -> Option<DetectedService> {
        let mut buffer = [0; 1024];
        if let Ok(bytes_read) = stream.read(&mut buffer) {
            let banner = String::from_utf8_lossy(&buffer[..bytes_read]);

            // SMTP servers send greeting
            if banner.starts_with("220") {
                return Some(DetectedService {
                    name: "smtp".to_string(),
                    version: None,
                    product: None,
                    extra_info: Some(banner.trim().to_string()),
                    confidence: 0.8,
                    cpe: None,
                });
            }
        }
        None
    }

    fn probe_generic_service(&self, stream: &mut TcpStream) -> Option<DetectedService> {
        let mut buffer = [0; 1024];
        if let Ok(bytes_read) = stream.read(&mut buffer) {
            if bytes_read > 0 {
                let banner = String::from_utf8_lossy(&buffer[..bytes_read]);
                return Some(DetectedService {
                    name: "unknown".to_string(),
                    version: None,
                    product: None,
                    extra_info: Some(banner.trim().to_string()),
                    confidence: 0.3,
                    cpe: None,
                });
            }
        }
        None
    }

    fn generate_service_fingerprint(&self, _ip: IpAddr, _port: u16) -> Option<ServiceFingerprint> {
        // Generate a basic service fingerprint
        Some(ServiceFingerprint {
            protocol: "tcp".to_string(),
            service_type: "unknown".to_string(),
            banner_pattern: None,
            probe_response: None,
            version_detection: Vec::new(),
        })
    }

    fn perform_os_fingerprinting(&self, host: &mut ScannedHost) -> Result<()> {
        debug!("Performing OS fingerprinting for host: {}", host.ip_address);

        // Simple OS detection based on open ports and TTL values
        let os_fingerprint = self.detect_operating_system(host);
        host.operating_system = os_fingerprint;

        Ok(())
    }

    fn detect_operating_system(&self, host: &ScannedHost) -> Option<OSFingerprint> {
        // Simplified OS detection based on port patterns
        let open_ports: Vec<u16> = host.open_ports.iter().map(|p| p.port).collect();

        let (os_family, os_name, confidence) = if open_ports.contains(&135) && open_ports.contains(&445) {
            ("Windows", "Microsoft Windows", 0.7)
        } else if open_ports.contains(&22) && open_ports.contains(&80) {
            ("Linux", "Linux", 0.6)
        } else if open_ports.contains(&22) {
            ("Unix", "Unix-like", 0.4)
        } else {
            ("Unknown", "Unknown", 0.1)
        };

        Some(OSFingerprint {
            os_family: os_family.to_string(),
            os_name: os_name.to_string(),
            os_version: None,
            device_type: None,
            confidence,
            tcp_fingerprint: None,
            icmp_fingerprint: None,
        })
    }

    fn parse_target_range(&self, target_range: &str) -> Result<Vec<IpAddr>> {
        let mut targets = Vec::new();

        if target_range.contains('/') {
            // CIDR notation
            targets.extend(self.parse_cidr_range(target_range)?);
        } else if target_range.contains('-') {
            // Range notation (e.g., 192.168.1.1-192.168.1.10)
            targets.extend(self.parse_ip_range(target_range)?);
        } else {
            // Single IP
            if let Ok(ip) = target_range.parse::<IpAddr>() {
                targets.push(ip);
            }
        }

        Ok(targets)
    }

    fn parse_cidr_range(&self, cidr: &str) -> Result<Vec<IpAddr>> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid CIDR notation: {}", cidr));
        }

        let base_ip: Ipv4Addr = parts[0].parse()?;
        let prefix_len: u8 = parts[1].parse()?;

        if prefix_len > 32 {
            return Err(anyhow::anyhow!("Invalid prefix length: {}", prefix_len));
        }

        let mut targets = Vec::new();
        let host_bits = 32 - prefix_len;
        let num_hosts = if host_bits >= 31 { 254 } else { (1u32 << host_bits) - 2 }; // Exclude network and broadcast

        let base_addr = u32::from(base_ip);
        let network_addr = base_addr & (!((1u32 << host_bits) - 1));

        for i in 1..=num_hosts.min(254) {
            let host_addr = network_addr + i;
            let ip = Ipv4Addr::try_from(host_addr).unwrap();
            targets.push(IpAddr::V4(ip));
        }

        Ok(targets)
    }

    fn parse_ip_range(&self, range: &str) -> Result<Vec<IpAddr>> {
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid IP range: {}", range));
        }

        let start_ip: Ipv4Addr = parts[0].trim().parse()?;
        let end_ip: Ipv4Addr = parts[1].trim().parse()?;

        let start_addr = u32::from(start_ip);
        let end_addr = u32::from(end_ip);

        let mut targets = Vec::new();
        for addr in start_addr..=end_addr {
            let ip = Ipv4Addr::try_from(addr).unwrap();
            targets.push(IpAddr::V4(ip));
        }

        Ok(targets)
    }

    fn resolve_hostname(ip: IpAddr) -> Option<String> {
        // Simple hostname resolution
        match (ip, 0).to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(_) = addrs.next() {
                    // In a real implementation, you'd do reverse DNS lookup
                    None // Simplified - not implementing reverse DNS
                }
                else { None }
            }
            Err(_) => None,
        }
    }

    fn count_scanned_ports(&self, hosts: &[ScannedHost]) -> usize {
        hosts.iter().map(|h| h.open_ports.len()).sum()
    }

    fn count_identified_services(&self, hosts: &[ScannedHost]) -> usize {
        hosts.iter()
            .map(|h| h.open_ports.iter().filter(|p| p.service.is_some()).count())
            .sum()
    }

    pub fn convert_to_components(&self) -> Vec<Component> {
        let mut components = Vec::new();

        for host in &self.discovered_hosts {
            // Create host component
            let mut host_metadata = serde_json::Map::new();
            host_metadata.insert("ip_address".to_string(), serde_json::Value::String(host.ip_address.to_string()));

            if let Some(hostname) = &host.hostname {
                host_metadata.insert("hostname".to_string(), serde_json::Value::String(hostname.clone()));
            }

            if let Some(mac) = &host.mac_address {
                host_metadata.insert("mac_address".to_string(), serde_json::Value::String(mac.clone()));
            }

            host_metadata.insert("tcp_responsive".to_string(), serde_json::Value::Bool(host.responsive));
            host_metadata.insert("icmp_responsive".to_string(), serde_json::Value::Bool(host.icmp_responsive));
            host_metadata.insert("scan_time".to_string(), serde_json::Value::String(host.scan_time.to_rfc3339()));
            
            // Add analysis-friendly fields
            let overall_responsive = host.responsive || host.icmp_responsive;
            host_metadata.insert("overall_responsive".to_string(), serde_json::Value::Bool(overall_responsive));
            
            // Categorize host responsiveness for analysis
            let responsiveness_category = if host.responsive && host.icmp_responsive {
                "fully_responsive"
            } else if host.responsive && !host.icmp_responsive {
                "tcp_only_responsive"
            } else if !host.responsive && host.icmp_responsive {
                "icmp_only_responsive"
            } else {
                "completely_unresponsive"
            };
            host_metadata.insert("responsiveness_category".to_string(), 
                serde_json::Value::String(responsiveness_category.to_string()));
            
            // Add port count for analysis
            host_metadata.insert("open_port_count".to_string(), 
                serde_json::Value::Number(serde_json::Number::from(host.open_ports.len())));

            if let Some(os) = &host.operating_system {
                host_metadata.insert("operating_system".to_string(), serde_json::Value::String(os.os_name.clone()));
                host_metadata.insert("os_family".to_string(), serde_json::Value::String(os.os_family.clone()));
                host_metadata.insert("os_confidence".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(os.confidence).unwrap()));
            }

            let host_component = Component::with_full_details(
                host.ip_address.to_string(),
                ComponentType::Host,
                host.hostname.clone().unwrap_or_else(|| host.ip_address.to_string()),
                None,
                serde_json::Value::Object(host_metadata),
            );

            components.push(host_component);

            // Create service components for each open port
            for port in &host.open_ports {
                if let Some(service) = &port.service {
                    let mut service_metadata = serde_json::Map::new();
                    service_metadata.insert("port".to_string(), serde_json::Value::Number(serde_json::Number::from(port.port)));
                    service_metadata.insert("protocol".to_string(), serde_json::Value::String(format!("{:?}", port.protocol)));
                    service_metadata.insert("state".to_string(), serde_json::Value::String(format!("{:?}", port.state)));
                    service_metadata.insert("host_ip".to_string(), serde_json::Value::String(host.ip_address.to_string()));

                    if let Some(version) = &service.version {
                        service_metadata.insert("version".to_string(), serde_json::Value::String(version.clone()));
                    }

                    if let Some(product) = &service.product {
                        service_metadata.insert("product".to_string(), serde_json::Value::String(product.clone()));
                    }

                    service_metadata.insert("confidence".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(service.confidence).unwrap()));

                    if let Some(banner) = &port.banner {
                        service_metadata.insert("banner".to_string(), serde_json::Value::String(banner.clone()));
                    }

                    let service_name = if service.name == "unknown" {
                        format!("service-{}", port.port)
                    } else {
                        service.name.clone()
                    };

                    let service_component = Component::with_full_details(
                        format!("{}:{}", host.ip_address, port.port),
                        ComponentType::Process, // Services run as processes
                        service_name,
                        None,
                        serde_json::Value::Object(service_metadata),
                    );

                    components.push(service_component);
                }
            }
        }

        components
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        let default_config = ScanConfig {
            target_ranges: vec!["192.168.1.0/24".to_string()],
            port_ranges: vec![
                PortRange { start_port: 1, end_port: 1000 },
            ],
            scan_type: ScanType::TcpConnect,
            timeout_ms: 200, // 200ms default timeout for faster scans
            max_threads: 50,
            tcp_scan: true,
            icmp_scan: true,
            service_detection: true,
            aggressive_scan: false,
        };

        Self::new(default_config)
    }
}

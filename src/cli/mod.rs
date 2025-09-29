pub mod analyze;
pub mod database;
pub mod visualize;
pub mod dynamic_analysis;
pub mod network_analysis;
pub mod ml_analysis;
pub mod scan;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "component-analyzer")]
#[command(about = "Cyber asset analysis tool for recording and visualizing components")]
#[command(version)]
pub struct Cli {
    #[arg(long, default_value = "analysis.db")]
    #[arg(help = "Path to the SQLite analysis database")]
    pub analysis_data: PathBuf,

    #[arg(short, long)]
    #[arg(help = "Enable verbose logging")]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Analyze binary files and extract components")]
    Analyze {
        #[arg(short, long)]
        #[arg(help = "Input binary file to analyze")]
        input: PathBuf,

        #[arg(long)]
        #[arg(help = "Focus analysis on system calls")]
        focus_syscalls: bool,

        #[arg(long)]
        #[arg(help = "Focus analysis on network capabilities")]
        focus_network: bool,

        #[arg(long)]
        #[arg(help = "Perform deep analysis (slower but more thorough)")]
        deep: bool,
    },

    #[command(about = "Launch interactive visualization")]
    Visualize {
        #[arg(long)]
        #[arg(help = "Filter by component type")]
        component_type: Option<String>,

        #[arg(long)]
        #[arg(help = "Filter by component name pattern")]
        filter: Option<String>,
    },

    #[command(about = "Database operations")]
    Db {
        #[arg(long)]
        #[arg(help = "Export data to JSON file")]
        export: Option<PathBuf>,

        #[arg(long)]
        #[arg(help = "Import data from JSON file")]
        import: Option<PathBuf>,

        #[arg(long)]
        #[arg(help = "Show database statistics")]
        stats: bool,

        #[arg(long)]
        #[arg(help = "Initialize database schema")]
        init: bool,
    },

    #[command(about = "Dynamic analysis using sandboxes")]
    Dynamic {
        #[arg(short, long)]
        #[arg(help = "Component ID to analyze dynamically")]
        component_id: String,

        #[arg(long, default_value = "docker-ubuntu")]
        #[arg(help = "Sandbox environment to use")]
        sandbox: String,

        #[arg(long, default_value = "300")]
        #[arg(help = "Analysis timeout in seconds")]
        timeout: u64,

        #[arg(long)]
        #[arg(help = "List available sandboxes")]
        list_sandboxes: bool,

        #[arg(long)]
        #[arg(help = "Show analysis session status")]
        status: Option<String>,

        #[arg(long)]
        #[arg(help = "Generate report for completed session")]
        report: Option<String>,
    },

    #[command(about = "Network topology analysis and visualization")]
    Network {
        #[arg(long)]
        #[arg(help = "Focus on specific network segment (CIDR notation)")]
        segment: Option<String>,

        #[arg(long)]
        #[arg(help = "Analyze attack paths")]
        attack_paths: bool,

        #[arg(long)]
        #[arg(help = "Detect threat indicators")]
        threats: bool,

        #[arg(long)]
        #[arg(help = "Export network topology to file")]
        export: Option<PathBuf>,

        #[arg(long)]
        #[arg(help = "Generate comprehensive network security report")]
        security_report: bool,

        #[arg(long)]
        #[arg(help = "Show network statistics")]
        stats: bool,
    },

    #[command(about = "Machine learning analysis and classification")]
    Ml {
        #[arg(long, default_value = "malware_classifier")]
        #[arg(help = "Model to use for classification")]
        model: String,

        #[arg(long)]
        #[arg(help = "Component ID or pattern to classify")]
        component: Option<String>,

        #[arg(long)]
        #[arg(help = "Perform anomaly detection")]
        anomaly_detection: bool,

        #[arg(long)]
        #[arg(help = "Predict potential threats")]
        threat_prediction: bool,

        #[arg(long)]
        #[arg(help = "List available models")]
        list_models: bool,

        #[arg(long)]
        #[arg(help = "Generate comprehensive ML analysis report")]
        report: bool,

        #[arg(long)]
        #[arg(help = "Export ML results to file")]
        export: Option<PathBuf>,

        #[arg(long, default_value = "0.5")]
        #[arg(help = "Minimum confidence threshold for predictions")]
        confidence_threshold: f64,
    },

    #[command(about = "Network scanning and service discovery")]
    Scan {
        #[arg(short, long)]
        #[arg(help = "Target IP range to scan (CIDR, range, or single IP)")]
        target: String,

        #[arg(long, default_value = "1-1000")]
        #[arg(help = "Port range to scan (e.g., 1-1000, 80,443,22)")]
        ports: String,

        #[arg(long, default_value = "tcp-connect")]
        #[arg(help = "Scan type: tcp-connect, icmp-ping, comprehensive, service-discovery")]
        scan_type: String,

        #[arg(long, default_value = "1000")]
        #[arg(help = "Timeout per connection in milliseconds")]
        timeout: u64,

        #[arg(long, default_value = "50")]
        #[arg(help = "Maximum concurrent threads")]
        threads: usize,

        #[arg(long)]
        #[arg(help = "Enable service version detection")]
        service_detection: bool,

        #[arg(long)]
        #[arg(help = "Enable aggressive scanning (OS detection, etc.)")]
        aggressive: bool,

        #[arg(long)]
        #[arg(help = "Export scan results to file")]
        export: Option<PathBuf>,

        #[arg(long)]
        #[arg(help = "Save discovered hosts to database")]
        save_to_db: bool,

        #[arg(long)]
        #[arg(help = "Show detailed scan results")]
        verbose_output: bool,
    },
}
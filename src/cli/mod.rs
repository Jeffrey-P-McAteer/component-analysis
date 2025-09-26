pub mod analyze;
pub mod database;
pub mod visualize;
pub mod dynamic_analysis;

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
}
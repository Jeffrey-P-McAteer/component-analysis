mod cli;
mod database;
mod parser;
mod analysis;
mod types;
#[cfg(feature = "gui")]
mod visualization;
#[cfg(feature = "gui")]
mod investigation;
mod performance;
mod dynamic;
mod network;
mod ml;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use log::{info, error};

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    if cli.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    info!("Starting component analyzer");
    info!("Using database: {}", cli.analysis_data.display());

    match &cli.command {
        Commands::Analyze {
            input,
            focus_syscalls,
            focus_network,
            deep,
        } => {
            info!("Analyzing binary: {}", input.display());
            cli::analyze::run(&cli.analysis_data, input, *focus_syscalls, *focus_network, *deep)
        }

        Commands::Visualize {
            component_type,
            filter,
        } => {
            #[cfg(feature = "gui")]
            {
                info!("Starting visualization");
                cli::visualize::run(&cli.analysis_data, component_type.as_deref(), filter.as_deref())
            }
            #[cfg(not(feature = "gui"))]
            {
                error!("GUI support not compiled in. Rebuild with --features gui");
                std::process::exit(1);
            }
        }

        Commands::Db {
            export,
            import,
            stats,
            init,
        } => {
            if *init {
                info!("Initializing database schema");
                cli::database::init(&cli.analysis_data)?;
            }
            if let Some(export_path) = export {
                info!("Exporting data to: {}", export_path.display());
                cli::database::export(&cli.analysis_data, export_path)?;
            }
            if let Some(import_path) = import {
                info!("Importing data from: {}", import_path.display());
                cli::database::import(&cli.analysis_data, import_path)?;
            }
            if *stats {
                info!("Displaying database statistics");
                cli::database::stats(&cli.analysis_data)?;
            }
            Ok(())
        }

        Commands::Dynamic {
            component_id,
            sandbox,
            timeout,
            list_sandboxes,
            status,
            report,
        } => {
            info!("Dynamic analysis command");
            cli::dynamic_analysis::run(
                &cli.analysis_data,
                component_id,
                sandbox,
                *timeout,
                *list_sandboxes,
                status.as_deref(),
                report.as_deref(),
            )
        }

        Commands::Network {
            segment,
            attack_paths,
            threats,
            export,
            security_report,
            stats,
        } => {
            info!("Network topology analysis command");
            cli::network_analysis::run(
                &cli.analysis_data,
                segment.as_deref(),
                *attack_paths,
                *threats,
                export.as_deref(),
                *security_report,
                *stats,
            )
        }

        Commands::Ml {
            model,
            component,
            anomaly_detection,
            threat_prediction,
            list_models,
            report,
            export,
            confidence_threshold,
        } => {
            info!("Machine learning analysis command");
            cli::ml_analysis::run(
                &cli.analysis_data,
                model,
                component.as_deref(),
                *anomaly_detection,
                *threat_prediction,
                *list_models,
                *report,
                export.as_deref(),
                *confidence_threshold,
            )
        }
    }
}

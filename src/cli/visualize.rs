use anyhow::Result;
use log::info;
use std::path::Path;

pub fn run(
    db_path: &Path,
    _component_type: Option<&str>,
    _filter: Option<&str>,
) -> Result<()> {
    #[cfg(feature = "gui")]
    {
        info!("Starting visualization GUI");
        
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([1200.0, 800.0]),
            ..Default::default()
        };

        eframe::run_native(
            "Component Analyzer - Visualization",
            options,
            Box::new(|_cc| {
                Ok(Box::new(crate::visualization::AnalyzerApp::new(db_path)))
            }),
        ).map_err(|e| anyhow::anyhow!("Failed to run GUI: {}", e))?;
    }
    
    #[cfg(not(feature = "gui"))]
    {
        anyhow::bail!("GUI support not compiled in. Rebuild with --features gui");
    }

    Ok(())
}
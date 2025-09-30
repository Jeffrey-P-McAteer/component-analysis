use crate::database::{open_database, ComponentQueries};
use crate::ml::{MachineLearningClassifier, ClassificationResult, AnomalyDetectionResult, ThreatPrediction};
use crate::types::{AnalysisResult, AnalysisType};
use anyhow::Result;
use log::{info, warn};
use std::path::Path;

pub fn run(
    db_path: &Path,
    model_name: &str,
    component_pattern: Option<&str>,
    anomaly_detection: bool,
    threat_prediction: bool,
    list_models: bool,
    generate_report: bool,
    export_path: Option<&Path>,
    confidence_threshold: f64,
) -> Result<()> {
    info!("Starting machine learning analysis");
    
    // Initialize ML classifier
    let ml_classifier = MachineLearningClassifier::new();
    
    if list_models {
        return list_available_models(&ml_classifier);
    }
    
    // Open database and get components
    let db = open_database(db_path)?;
    let conn = db.connection();
    
    let components = if let Some(pattern) = component_pattern {
        // Get specific components matching pattern
        if pattern.contains('-') && pattern.len() == 36 {
            // Looks like UUID, try exact match first
            ComponentQueries::get_by_id_pattern(conn, pattern)?
        } else {
            // Try name pattern match
            ComponentQueries::get_by_name_pattern(conn, pattern)?
        }
    } else {
        // Get all components
        ComponentQueries::get_all(conn)?
    };
    
    info!("Loaded {} components for ML analysis", components.len());
    
    if components.is_empty() {
        warn!("No components found for analysis");
        return Ok(());
    }
    
    // Perform analysis
    let mut classification_results = Vec::new();
    let mut anomaly_results = Vec::new();
    let mut threat_results = Vec::new();
    
    info!("Processing components with model: {}", model_name);
    
    for component in &components {
        // Classification
        if !list_models {
            match ml_classifier.classify_component(component, model_name) {
                Ok(result) => {
                    if result.confidence >= confidence_threshold {
                        classification_results.push((component.clone(), result));
                    }
                }
                Err(e) => {
                    warn!("Classification failed for component {}: {}", component.name, e);
                }
            }
        }
        
        // Anomaly detection
        if anomaly_detection {
            match ml_classifier.detect_anomalies(component) {
                Ok(result) => {
                    if result.is_anomaly {
                        anomaly_results.push((component.clone(), result));
                    }
                }
                Err(e) => {
                    warn!("Anomaly detection failed for component {}: {}", component.name, e);
                }
            }
        }
        
        // Threat prediction
        if threat_prediction {
            match ml_classifier.predict_threats(component) {
                Ok(threats) => {
                    for threat in threats {
                        if threat.probability >= confidence_threshold {
                            threat_results.push((component.clone(), threat));
                        }
                    }
                }
                Err(e) => {
                    warn!("Threat prediction failed for component {}: {}", component.name, e);
                }
            }
        }
    }
    
    // Display results
    if !classification_results.is_empty() {
        display_classification_results(&classification_results);
    }
    
    if !anomaly_results.is_empty() {
        display_anomaly_results(&anomaly_results);
    }
    
    if !threat_results.is_empty() {
        display_threat_predictions(&threat_results);
    }
    
    // Generate comprehensive report
    if generate_report {
        generate_ml_report(&ml_classifier, &components)?;
    }
    
    // Export results
    if let Some(export_file) = export_path {
        export_ml_results(&classification_results, &anomaly_results, &threat_results, export_file)?;
    }
    
    // Store results in database
    store_ml_results(&classification_results, &anomaly_results, &threat_results, conn)?;
    
    // Display summary
    display_analysis_summary(&classification_results, &anomaly_results, &threat_results);
    
    info!("Machine learning analysis completed");
    Ok(())
}

fn list_available_models(ml_classifier: &MachineLearningClassifier) -> Result<()> {
    println!("Available Machine Learning Models");
    println!("=================================");
    
    for (model_id, model) in &ml_classifier.models {
        println!("\nModel ID: {}", model_id);
        println!("Name: {}", model.name);
        println!("Type: {:?}", model.model_type);
        println!("Version: {}", model.version);
        println!("Classes: {}", model.classes.join(", "));
        
        if let Some(accuracy) = model.accuracy {
            println!("Accuracy: {:.2}%", accuracy * 100.0);
        }
        
        println!("Training Samples: {}", model.training_samples);
        
        if let Some(trained_at) = model.trained_at {
            println!("Trained At: {}", trained_at.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        
        println!("Features:");
        for feature in &model.features {
            println!("  - {} ({:?})", feature.name, feature.feature_type);
            if let Some(importance) = feature.importance_score {
                println!("    Importance: {:.2}", importance);
            }
        }
        
        if !model.precision.is_empty() {
            println!("Precision by Class:");
            for (class, precision) in &model.precision {
                println!("  {}: {:.2}%", class, precision * 100.0);
            }
        }
    }
    
    println!("\nFeature Extractors:");
    println!("==================");
    
    for extractor in &ml_classifier.feature_extractors {
        println!("\nExtractor: {}", extractor.name);
        println!("Type: {:?}", extractor.extractor_type);
        println!("Applicable Components: {:?}", extractor.applicable_components);
        println!("Output Features: {}", extractor.output_features.join(", "));
    }
    
    Ok(())
}

fn display_classification_results(results: &[(crate::types::Component, ClassificationResult)]) {
    println!("\nClassification Results");
    println!("=====================");
    
    // Group by predicted class
    let mut class_groups: std::collections::HashMap<String, Vec<&(crate::types::Component, ClassificationResult)>> = std::collections::HashMap::new();
    
    for result in results {
        class_groups.entry(result.1.predicted_class.clone())
            .or_insert_with(Vec::new)
            .push(result);
    }
    
    for (class_name, class_results) in class_groups {
        println!("\n{} ({})", class_name, class_results.len());
        println!("{}", "-".repeat(class_name.len() + 10));
        
        // Sort by confidence descending
        let mut sorted_results = class_results.clone();
        sorted_results.sort_by(|a, b| b.1.confidence.partial_cmp(&a.1.confidence).unwrap());
        
        for (component, result) in sorted_results.iter().take(10) { // Show top 10
            println!("  {} - Confidence: {:.1}%", 
                component.name, 
                result.confidence * 100.0
            );
            
            // Show top contributing features
            let mut feature_vec: Vec<(&String, &f64)> = result.feature_importance.iter().collect();
            feature_vec.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());
            
            if !feature_vec.is_empty() {
                print!("    Key features: ");
                let top_features: Vec<String> = feature_vec.iter()
                    .take(3)
                    .map(|(name, importance)| format!("{}({:.2})", name, importance))
                    .collect();
                println!("{}", top_features.join(", "));
            }
        }
        
        if class_results.len() > 10 {
            println!("  ... and {} more", class_results.len() - 10);
        }
    }
}

fn display_anomaly_results(results: &[(crate::types::Component, AnomalyDetectionResult)]) {
    println!("\nAnomaly Detection Results");
    println!("========================");
    
    // Sort by anomaly score descending
    let mut sorted_results = results.to_vec();
    sorted_results.sort_by(|a, b| b.1.anomaly_score.partial_cmp(&a.1.anomaly_score).unwrap());
    
    // Group by anomaly type
    let mut type_groups: std::collections::HashMap<String, Vec<&(crate::types::Component, AnomalyDetectionResult)>> = std::collections::HashMap::new();
    
    for result in &sorted_results {
        let type_name = format!("{:?}", result.1.anomaly_type);
        type_groups.entry(type_name)
            .or_insert_with(Vec::new)
            .push(result);
    }
    
    for (anomaly_type, anomaly_results) in type_groups {
        println!("\n{} ({})", anomaly_type, anomaly_results.len());
        println!("{}", "-".repeat(anomaly_type.len() + 10));
        
        for (component, result) in anomaly_results.iter().take(5) { // Show top 5 per type
            println!("  {} - Score: {:.2}", component.name, result.anomaly_score);
            println!("    {}", result.explanation);
            
            if !result.contributing_features.is_empty() {
                println!("    Contributing features: {}", result.contributing_features.join(", "));
            }
        }
        
        if anomaly_results.len() > 5 {
            println!("  ... and {} more", anomaly_results.len() - 5);
        }
    }
}

fn display_threat_predictions(results: &[(crate::types::Component, ThreatPrediction)]) {
    println!("\nThreat Predictions");
    println!("=================");
    
    // Group by severity
    let mut critical_threats = Vec::new();
    let mut high_threats = Vec::new();
    let mut medium_threats = Vec::new();
    let mut low_threats = Vec::new();
    
    for result in results {
        match result.1.severity {
            crate::types::RiskLevel::Critical => critical_threats.push(result),
            crate::types::RiskLevel::High => high_threats.push(result),
            crate::types::RiskLevel::Medium => medium_threats.push(result),
            crate::types::RiskLevel::Low => low_threats.push(result),
        }
    }
    
    for (severity_name, threats) in [
        ("CRITICAL", critical_threats),
        ("HIGH", high_threats),
        ("MEDIUM", medium_threats),
        ("LOW", low_threats),
    ] {
        if !threats.is_empty() {
            println!("\n{} Severity Threats ({})", severity_name, threats.len());
            println!("{}", "=".repeat(severity_name.len() + 20));
            
            // Sort by probability descending
            let mut sorted_threats = threats;
            sorted_threats.sort_by(|a, b| b.1.probability.partial_cmp(&a.1.probability).unwrap());
            
            for (component, threat) in sorted_threats.iter().take(5) {
                println!("  Component: {}", component.name);
                println!("  Threat: {}", threat.threat_type);
                println!("  Probability: {:.1}%", threat.probability * 100.0);
                println!("  Model: {}", threat.prediction_model);
                
                if !threat.indicators.is_empty() {
                    println!("  Indicators: {}", threat.indicators.join(", "));
                }
                
                if !threat.recommended_actions.is_empty() {
                    println!("  Recommended Actions:");
                    for action in &threat.recommended_actions {
                        println!("    - {}", action);
                    }
                }
                
                println!();
            }
            
            if sorted_threats.len() > 5 {
                println!("  ... and {} more {} severity threats", 
                    sorted_threats.len() - 5, severity_name.to_lowercase());
            }
        }
    }
}

fn generate_ml_report(ml_classifier: &MachineLearningClassifier, components: &[crate::types::Component]) -> Result<()> {
    println!("\nMachine Learning Analysis Report");
    println!("===============================");
    
    // Generate comprehensive report
    let report = ml_classifier.generate_ml_report(components)?;
    
    println!("Analysis Timestamp: {}", report.analysis_timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("Total Components Analyzed: {}", report.total_components_analyzed);
    
    println!("\nModel Performance Summary:");
    println!("--------------------------");
    for (model_name, accuracy) in &report.accuracy_summary {
        println!("  {}: {:.1}% accuracy", model_name, accuracy * 100.0);
    }
    
    println!("\nClassification Summary:");
    println!("----------------------");
    
    // Group classifications by predicted class
    let mut class_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (_, classification) in &report.classifications {
        *class_counts.entry(classification.predicted_class.clone()).or_insert(0) += 1;
    }
    
    for (class, count) in class_counts {
        println!("  {}: {} components", class, count);
    }
    
    println!("\nAnomaly Detection Summary:");
    println!("-------------------------");
    println!("  Total Anomalies Detected: {}", report.anomalies.len());
    
    // Group anomalies by type
    let mut anomaly_type_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (_, anomaly) in &report.anomalies {
        let type_name = format!("{:?}", anomaly.anomaly_type);
        *anomaly_type_counts.entry(type_name).or_insert(0) += 1;
    }
    
    for (anomaly_type, count) in anomaly_type_counts {
        println!("  {}: {} anomalies", anomaly_type, count);
    }
    
    println!("\nThreat Prediction Summary:");
    println!("-------------------------");
    println!("  Total Threat Predictions: {}", report.threat_predictions.len());
    
    // Group threats by severity
    let mut threat_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (_, threat) in &report.threat_predictions {
        let severity = format!("{:?}", threat.severity);
        *threat_counts.entry(severity).or_insert(0) += 1;
    }
    
    for (severity, count) in threat_counts {
        println!("  {} Severity: {} threats", severity, count);
    }
    
    println!("\nRecommendations:");
    println!("---------------");
    for (i, recommendation) in report.recommendation_summary.iter().enumerate() {
        println!("  {}. {}", i + 1, recommendation);
    }
    
    Ok(())
}

fn export_ml_results(
    classifications: &[(crate::types::Component, ClassificationResult)],
    anomalies: &[(crate::types::Component, AnomalyDetectionResult)],
    threats: &[(crate::types::Component, ThreatPrediction)],
    export_path: &Path,
) -> Result<()> {
    info!("Exporting ML analysis results to: {}", export_path.display());
    
    let export_data = serde_json::json!({
        "export_timestamp": chrono::Utc::now().to_rfc3339(),
        "classifications": classifications.iter().map(|(component, result)| {
            serde_json::json!({
                "component_id": component.id,
                "component_name": component.name,
                "component_type": component.component_type,
                "classification_result": result
            })
        }).collect::<Vec<_>>(),
        "anomalies": anomalies.iter().map(|(component, result)| {
            serde_json::json!({
                "component_id": component.id,
                "component_name": component.name,
                "component_type": component.component_type,
                "anomaly_result": result
            })
        }).collect::<Vec<_>>(),
        "threat_predictions": threats.iter().map(|(component, result)| {
            serde_json::json!({
                "component_id": component.id,
                "component_name": component.name,
                "component_type": component.component_type,
                "threat_prediction": result
            })
        }).collect::<Vec<_>>()
    });
    
    std::fs::write(export_path, serde_json::to_string_pretty(&export_data)?)?;
    info!("ML analysis results exported successfully");
    
    Ok(())
}

fn store_ml_results(
    classifications: &[(crate::types::Component, ClassificationResult)],
    anomalies: &[(crate::types::Component, AnomalyDetectionResult)],
    threats: &[(crate::types::Component, ThreatPrediction)],
    conn: &rusqlite::Connection,
) -> Result<()> {
    info!("Storing ML analysis results in database");
    
    // Store classification results
    for (component, result) in classifications {
        let analysis_result = AnalysisResult::new(
            component.id.clone(),
            AnalysisType::StaticAnalysis, // Using StaticAnalysis as ML analysis type placeholder
            serde_json::json!({
                "analysis_type": "machine_learning_classification",
                "model_used": result.model_used,
                "predicted_class": result.predicted_class,
                "confidence": result.confidence,
                "class_probabilities": result.class_probabilities,
                "feature_importance": result.feature_importance,
                "prediction_timestamp": result.prediction_timestamp
            })
        ).with_confidence(result.confidence);
        
        analysis_result.insert(conn)?;
    }
    
    // Store anomaly detection results
    for (component, result) in anomalies {
        let analysis_result = AnalysisResult::new(
            component.id.clone(),
            AnalysisType::StaticAnalysis,
            serde_json::json!({
                "analysis_type": "anomaly_detection",
                "is_anomaly": result.is_anomaly,
                "anomaly_score": result.anomaly_score,
                "anomaly_type": result.anomaly_type,
                "contributing_features": result.contributing_features,
                "explanation": result.explanation
            })
        ).with_confidence(result.anomaly_score);
        
        analysis_result.insert(conn)?;
    }
    
    // Store threat predictions
    for (component, result) in threats {
        let analysis_result = AnalysisResult::new(
            component.id.clone(),
            AnalysisType::StaticAnalysis,
            serde_json::json!({
                "analysis_type": "threat_prediction",
                "threat_type": result.threat_type,
                "probability": result.probability,
                "severity": result.severity,
                "indicators": result.indicators,
                "recommended_actions": result.recommended_actions,
                "prediction_model": result.prediction_model
            })
        ).with_confidence(result.probability);
        
        analysis_result.insert(conn)?;
    }
    
    info!("ML analysis results stored successfully");
    Ok(())
}

fn display_analysis_summary(
    classifications: &[(crate::types::Component, ClassificationResult)],
    anomalies: &[(crate::types::Component, AnomalyDetectionResult)],
    threats: &[(crate::types::Component, ThreatPrediction)],
) {
    println!("\nML Analysis Summary");
    println!("==================");
    
    if !classifications.is_empty() {
        println!("✓ {} components classified", classifications.len());
        
        let high_confidence_count = classifications.iter()
            .filter(|(_, result)| result.confidence > 0.8)
            .count();
        println!("  {} high-confidence predictions (>80%)", high_confidence_count);
    }
    
    if !anomalies.is_empty() {
        println!("⚠ {} anomalies detected", anomalies.len());
        
        let high_score_anomalies = anomalies.iter()
            .filter(|(_, result)| result.anomaly_score > 0.8)
            .count();
        println!("  {} high-score anomalies (>0.8)", high_score_anomalies);
    }
    
    if !threats.is_empty() {
        println!("[SEARCH] {} threat predictions made", threats.len());
        
        let critical_threats = threats.iter()
            .filter(|(_, threat)| matches!(threat.severity, crate::types::RiskLevel::Critical))
            .count();
        
        let high_threats = threats.iter()
            .filter(|(_, threat)| matches!(threat.severity, crate::types::RiskLevel::High))
            .count();
        
        if critical_threats > 0 {
            println!("  🔴 {} CRITICAL threats identified", critical_threats);
        }
        
        if high_threats > 0 {
            println!("  🔶 {} HIGH severity threats identified", high_threats);
        }
    }
    
    if classifications.is_empty() && anomalies.is_empty() && threats.is_empty() {
        println!("✓ No significant findings detected");
    }
}
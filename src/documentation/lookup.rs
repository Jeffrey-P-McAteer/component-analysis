use crate::types::{DocumentationType, DocumentationLookupConfig, DocumentationSearchResult};
use anyhow::Result;

/// Trait for documentation sources
pub trait DocumentationSource {
    async fn search(
        &self,
        function_name: &str,
        platform: &str,
        config: &DocumentationLookupConfig,
    ) -> Result<Option<DocumentationSearchResult>>;
}


/// HTTP client utilities for documentation lookup
pub struct HttpClient {
    client: reqwest::Client,
    config: DocumentationLookupConfig,
}

impl HttpClient {
    pub fn new(config: DocumentationLookupConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_seconds))
            .user_agent(&config.user_agent)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { client, config }
    }

    pub async fn get_text(&self, url: &str) -> Result<String> {
        let mut last_error = None;

        for attempt in 1..=self.config.max_retries {
            match self.client.get(url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.text().await {
                            Ok(text) => return Ok(text),
                            Err(e) => last_error = Some(anyhow::anyhow!("Failed to read response text: {}", e)),
                        }
                    } else {
                        last_error = Some(anyhow::anyhow!("HTTP error: {}", response.status()));
                    }
                }
                Err(e) => {
                    last_error = Some(anyhow::anyhow!("Request failed: {}", e));
                }
            }

            if attempt < self.config.max_retries {
                tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Unknown error during HTTP request")))
    }

}

/// Text processing utilities for extracting function information
pub struct TextProcessor;

impl TextProcessor {
    /// Extract function header from documentation text
    pub fn extract_function_header(text: &str, function_name: &str) -> Option<String> {
        let lines: Vec<&str> = text.lines().collect();
        
        // Look for C-style function declarations
        for (i, line) in lines.iter().enumerate() {
            if line.contains(function_name) && (line.contains('(') || line.contains(';')) {
                // Check if this looks like a function declaration
                if Self::is_function_declaration(line, function_name) {
                    // Try to get the complete declaration (might span multiple lines)
                    return Self::extract_complete_declaration(&lines, i, function_name);
                }
            }
        }

        None
    }

    fn is_function_declaration(line: &str, function_name: &str) -> bool {
        // Basic heuristics for function declarations
        let trimmed = line.trim();
        
        // Check for common patterns
        let has_return_type = trimmed.starts_with("int ") || trimmed.starts_with("void ") || 
                             trimmed.starts_with("char ") || trimmed.starts_with("size_t ") ||
                             trimmed.starts_with("BOOL ") || trimmed.starts_with("HANDLE ") ||
                             trimmed.starts_with("NTSTATUS ");
        
        let has_function_name = trimmed.contains(function_name);
        let has_parentheses = trimmed.contains('(');
        
        has_return_type && has_function_name && has_parentheses
    }

    fn extract_complete_declaration(lines: &[&str], start_idx: usize, function_name: &str) -> Option<String> {
        let mut declaration = String::new();
        let mut paren_count = 0;
        let mut found_semicolon = false;

        for (i, line) in lines.iter().enumerate().skip(start_idx) {
            let trimmed = line.trim();
            declaration.push_str(trimmed);
            
            // Count parentheses to handle multi-line declarations
            paren_count += trimmed.chars().filter(|&c| c == '(').count() as i32;
            paren_count -= trimmed.chars().filter(|&c| c == ')').count() as i32;
            
            if trimmed.contains(';') {
                found_semicolon = true;
            }

            // Stop when we have a complete declaration
            if paren_count == 0 && (found_semicolon || i == lines.len() - 1) {
                break;
            }

            declaration.push(' ');
        }

        if !declaration.is_empty() && declaration.contains(function_name) {
            Some(Self::clean_declaration(&declaration))
        } else {
            None
        }
    }

    fn clean_declaration(declaration: &str) -> String {
        declaration
            .replace('\n', " ")
            .replace('\t', " ")
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ")
    }

    /// Extract description from documentation text
    pub fn extract_description(text: &str, function_name: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();
        let mut description = String::new();
        let mut in_description = false;
        let mut found_function = false;

        for line in lines {
            let trimmed = line.trim();
            
            // Look for the function name to start extraction
            if !found_function && trimmed.contains(function_name) {
                found_function = true;
                continue;
            }

            if found_function {
                // Skip empty lines and headers
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("NAME") {
                    continue;
                }

                // Stop at certain sections
                if trimmed.starts_with("SYNOPSIS") || trimmed.starts_with("PARAMETERS") || 
                   trimmed.starts_with("RETURN") || trimmed.starts_with("SEE ALSO") {
                    if !description.is_empty() {
                        break;
                    }
                    continue;
                }

                // Start collecting description
                if !in_description && !trimmed.is_empty() {
                    in_description = true;
                }

                if in_description {
                    if !description.is_empty() {
                        description.push(' ');
                    }
                    description.push_str(trimmed);

                    // Stop after a reasonable amount of text
                    if description.len() > 500 {
                        break;
                    }
                }
            }
        }

        if description.is_empty() {
            format!("No description available for {}", function_name)
        } else {
            description
        }
    }

    /// Calculate a quality score for documentation
    pub fn calculate_quality_score(
        header: &Option<String>,
        description: &str,
        source_url: &str,
        doc_type: &DocumentationType,
    ) -> f64 {
        let mut score: f64 = 0.0;

        // Base score by documentation type
        score += match doc_type {
            DocumentationType::Official => 0.9,
            DocumentationType::StandardLibrary => 0.8,
            DocumentationType::WindowsAPI => 0.8,
            DocumentationType::LinuxAPI => 0.8,
            DocumentationType::POSIX => 0.7,
            DocumentationType::Manual => 0.6,
            DocumentationType::StackOverflow => 0.3,
        };

        // Bonus for having function header
        if header.is_some() && !header.as_ref().unwrap().is_empty() {
            score += 0.1;
        }

        // Bonus for description quality
        if description.len() > 100 {
            score += 0.1;
        }
        if description.len() > 300 {
            score += 0.1;
        }

        // Bonus for reputable sources
        if source_url.contains("microsoft.com") || source_url.contains("man7.org") || 
           source_url.contains("kernel.org") || source_url.contains("opengroup.org") {
            score += 0.1;
        }

        score.min(1.0)
    }
}
pub mod lookup;
pub mod sources;
pub mod syntax;

pub use sources::*;
pub use syntax::*;

use crate::types::{FunctionDocumentation, DocumentationType, DocumentationSearchResult};
use crate::documentation::lookup::DocumentationSource;
use crate::database::FunctionDocumentationQueries;
use anyhow::Result;

/// Documentation service that manages lookup and caching
#[derive(Clone)]
pub struct DocumentationService {
    #[allow(dead_code)]
    config: crate::types::DocumentationLookupConfig,
}

impl DocumentationService {
    pub fn new() -> Self {
        Self {
            config: crate::types::DocumentationLookupConfig::default(),
        }
    }

    pub fn with_config(config: crate::types::DocumentationLookupConfig) -> Self {
        Self { config }
    }

    /// Get documentation for a function, checking cache first, then performing lookup
    pub async fn get_function_documentation(
        &self,
        db_conn: &rusqlite::Connection,
        function_name: &str,
        platform_hint: Option<&str>,
    ) -> Result<Option<FunctionDocumentation>> {
        
        log::info!("Looking up documentation for function: {} (platform: {:?})", function_name, platform_hint);

        // First check cache
        log::debug!("Checking cache for function: {}", function_name);
        if let Some(cached) = self.check_cache(db_conn, function_name, platform_hint)? {
            log::info!("Found cached documentation for function: {}", function_name);
            return Ok(Some(cached));
        }

        log::info!("No cached documentation found, performing online lookup for: {}", function_name);
        
        // If not in cache or stale, perform lookup
        if let Some(result) = self.lookup_documentation(function_name, platform_hint).await? {
            log::info!("Successfully found documentation for {} from source: {:?}", function_name, result.documentation_type);
            
            // Convert search result to function documentation
            let doc = FunctionDocumentation::new(
                result.function_name,
                result.platform,
                result.description,
                result.documentation_type,
            )
            .with_header(result.header.unwrap_or_default())
            .with_source_url(result.source_url)
            .with_quality_score(result.quality_score);

            // Cache the result
            log::debug!("Caching documentation for function: {}", function_name);
            doc.insert(db_conn)?;

            Ok(Some(doc))
        } else {
            log::warn!("No documentation found for function: {}", function_name);
            Ok(None)
        }
    }

    /// Check if we have fresh documentation in cache
    fn check_cache(
        &self,
        db_conn: &rusqlite::Connection,
        function_name: &str,
        platform_hint: Option<&str>,
    ) -> Result<Option<FunctionDocumentation>> {

        // Check if we have fresh documentation
        if !FunctionDocumentationQueries::is_fresh(db_conn, function_name, self.config.cache_duration_hours)? {
            return Ok(None);
        }

        // Get the best documentation entry
        if let Some(platform) = platform_hint {
            // Try platform-specific first
            if let Some(doc) = FunctionDocumentationQueries::get_by_function_and_platform(db_conn, function_name, platform)? {
                return Ok(Some(doc));
            }
        }

        // Fall back to best general match
        FunctionDocumentationQueries::get_by_function_name(db_conn, function_name)
    }

    /// Perform online lookup for function documentation
    async fn lookup_documentation(
        &self,
        function_name: &str,
        platform_hint: Option<&str>,
    ) -> Result<Option<DocumentationSearchResult>> {
        let platform = platform_hint.unwrap_or("generic");
        
        log::info!("Starting online lookup for function: {} on platform: {}", function_name, platform);
        log::debug!("Trying {} documentation sources in order", self.config.preferred_sources.len());
        
        // Try different sources in order of preference
        for (i, doc_type) in self.config.preferred_sources.iter().enumerate() {
            log::debug!("Trying source {} of {}: {:?}", i + 1, self.config.preferred_sources.len(), doc_type);
            
            match self.try_source(function_name, platform, doc_type).await {
                Ok(Some(result)) => {
                    log::info!("Successfully found documentation from source: {:?}", doc_type);
                    return Ok(Some(result));
                },
                Ok(None) => {
                    log::debug!("No results from source: {:?}", doc_type);
                },
                Err(e) => {
                    log::warn!("Error searching source {:?}: {}", doc_type, e);
                }
            }
        }

        log::warn!("All documentation sources exhausted for function: {}", function_name);
        Ok(None)
    }

    /// Try a specific documentation source
    async fn try_source(
        &self,
        function_name: &str,
        platform: &str,
        doc_type: &DocumentationType,
    ) -> Result<Option<DocumentationSearchResult>> {
        match doc_type {
            DocumentationType::StandardLibrary => {
                StandardLibrarySource.search(function_name, platform, &self.config).await
            }
            DocumentationType::WindowsAPI => {
                WindowsAPISource.search(function_name, platform, &self.config).await
            }
            DocumentationType::LinuxAPI => {
                LinuxAPISource.search(function_name, platform, &self.config).await
            }
            DocumentationType::POSIX => {
                POSIXSource.search(function_name, platform, &self.config).await
            }
            DocumentationType::Manual => {
                ManualPageSource.search(function_name, platform, &self.config).await
            }
            _ => Ok(None), // Skip other sources for now
        }
    }
}

impl Default for DocumentationService {
    fn default() -> Self {
        Self::new()
    }
}
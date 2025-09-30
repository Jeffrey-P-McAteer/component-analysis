use crate::documentation::lookup::{DocumentationSource, HttpClient, TextProcessor};
use crate::types::{DocumentationSearchResult, DocumentationType, DocumentationLookupConfig};
use anyhow::Result;

/// Standard C library documentation source
pub struct StandardLibrarySource;

impl DocumentationSource for StandardLibrarySource {
    async fn search(
        function_name: &str,
        platform: &str,
        config: &DocumentationLookupConfig,
    ) -> Result<Option<DocumentationSearchResult>> {
        log::debug!("StandardLibrarySource: Searching for function '{}'", function_name);
        let client = HttpClient::new(config.clone());
        
        // Try cppreference.com first
        let url = format!("https://en.cppreference.com/w/c/{}", function_name);
        log::debug!("StandardLibrarySource: Trying cppreference.com URL: {}", url);
        
        match client.get_text(&url).await {
            Ok(html) => {
                log::info!("StandardLibrarySource: Successfully fetched HTML from cppreference.com for '{}'", function_name);
                log::debug!("StandardLibrarySource: HTML content length: {} characters", html.len());
                
                let description = Self::parse_cppreference_html(&html, function_name);
                let header = TextProcessor::extract_function_header(&html, function_name);
                
                log::debug!("StandardLibrarySource: Extracted description length: {} chars", description.len());
                log::debug!("StandardLibrarySource: Extracted header: {:?}", header);
                
                let quality_score = TextProcessor::calculate_quality_score(
                    &header,
                    &description,
                    &url,
                    &DocumentationType::StandardLibrary,
                );
                
                log::info!("StandardLibrarySource: Generated documentation for '{}' with quality score: {:.2}", function_name, quality_score);

                Ok(Some(DocumentationSearchResult {
                    function_name: function_name.to_string(),
                    header,
                    description,
                    source_url: url,
                    documentation_type: DocumentationType::StandardLibrary,
                    quality_score,
                    platform: platform.to_string(),
                }))
            }
            Err(e) => {
                log::warn!("StandardLibrarySource: Failed to fetch from cppreference.com: {}", e);
                log::debug!("StandardLibrarySource: Falling back to man7.org for '{}'", function_name);
                // Fallback to man7.org
                Self::try_man7_org(function_name, platform, config).await
            }
        }
    }
}

impl StandardLibrarySource {
    async fn try_man7_org(
        function_name: &str,
        platform: &str,
        config: &DocumentationLookupConfig,
    ) -> Result<Option<DocumentationSearchResult>> {
        let client = HttpClient::new(config.clone());
        let url = format!("https://man7.org/linux/man-pages/man3/{}.3.html", function_name);
        log::debug!("StandardLibrarySource: Trying man7.org URL: {}", url);
        
        match client.get_text(&url).await {
            Ok(html) => {
                log::info!("StandardLibrarySource: Successfully fetched HTML from man7.org for '{}'", function_name);
                log::debug!("StandardLibrarySource: man7.org HTML content length: {} characters", html.len());
                
                let description = Self::parse_man_page_html(&html, function_name);
                let header = TextProcessor::extract_function_header(&html, function_name);
                
                log::debug!("StandardLibrarySource: man7.org extracted description length: {} chars", description.len());
                log::debug!("StandardLibrarySource: man7.org extracted header: {:?}", header);
                
                let quality_score = TextProcessor::calculate_quality_score(
                    &header,
                    &description,
                    &url,
                    &DocumentationType::StandardLibrary,
                );
                
                log::info!("StandardLibrarySource: man7.org generated documentation for '{}' with quality score: {:.2}", function_name, quality_score);

                Ok(Some(DocumentationSearchResult {
                    function_name: function_name.to_string(),
                    header,
                    description,
                    source_url: url,
                    documentation_type: DocumentationType::StandardLibrary,
                    quality_score,
                    platform: platform.to_string(),
                }))
            }
            Err(e) => {
                log::warn!("StandardLibrarySource: Failed to fetch from man7.org: {}", e);
                Ok(None)
            },
        }
    }

    fn parse_cppreference_html(html: &str, function_name: &str) -> String {
        // Simple HTML parsing to extract description
        // In a real implementation, you'd use a proper HTML parser
        let text = html
            .replace("<br>", "\n")
            .replace("<p>", "\n")
            .replace("</p>", "\n");
        
        TextProcessor::extract_description(&text, function_name)
    }

    fn parse_man_page_html(html: &str, function_name: &str) -> String {
        // Simple HTML parsing for man pages
        let text = html
            .replace("<br>", "\n")
            .replace("<p>", "\n")
            .replace("</p>", "\n");
        
        TextProcessor::extract_description(&text, function_name)
    }
}

/// Windows API documentation source
pub struct WindowsAPISource;

impl DocumentationSource for WindowsAPISource {
    async fn search(
        function_name: &str,
        platform: &str,
        config: &DocumentationLookupConfig,
    ) -> Result<Option<DocumentationSearchResult>> {
        let client = HttpClient::new(config.clone());
        
        // Microsoft Docs API
        let url = format!("https://docs.microsoft.com/en-us/windows/win32/api/search?term={}", function_name);
        
        match client.get_text(&url).await {
            Ok(html) => {
                let description = Self::parse_microsoft_docs(&html, function_name);
                let header = TextProcessor::extract_function_header(&html, function_name);
                
                let quality_score = TextProcessor::calculate_quality_score(
                    &header,
                    &description,
                    &url,
                    &DocumentationType::WindowsAPI,
                );

                Ok(Some(DocumentationSearchResult {
                    function_name: function_name.to_string(),
                    header,
                    description,
                    source_url: url,
                    documentation_type: DocumentationType::WindowsAPI,
                    quality_score,
                    platform: platform.to_string(),
                }))
            }
            Err(_) => Ok(None),
        }
    }
}

impl WindowsAPISource {
    fn parse_microsoft_docs(html: &str, function_name: &str) -> String {
        let text = html
            .replace("<br>", "\n")
            .replace("<p>", "\n")
            .replace("</p>", "\n");
        
        TextProcessor::extract_description(&text, function_name)
    }
}

/// Linux API documentation source
pub struct LinuxAPISource;

impl DocumentationSource for LinuxAPISource {
    async fn search(
        function_name: &str,
        platform: &str,
        config: &DocumentationLookupConfig,
    ) -> Result<Option<DocumentationSearchResult>> {
        let client = HttpClient::new(config.clone());
        
        // Try kernel.org documentation
        let url = format!("https://www.kernel.org/doc/html/latest/userspace-api/index.html#{}", function_name);
        
        match client.get_text(&url).await {
            Ok(html) => {
                let description = Self::parse_kernel_docs(&html, function_name);
                let header = TextProcessor::extract_function_header(&html, function_name);
                
                let quality_score = TextProcessor::calculate_quality_score(
                    &header,
                    &description,
                    &url,
                    &DocumentationType::LinuxAPI,
                );

                Ok(Some(DocumentationSearchResult {
                    function_name: function_name.to_string(),
                    header,
                    description,
                    source_url: url,
                    documentation_type: DocumentationType::LinuxAPI,
                    quality_score,
                    platform: platform.to_string(),
                }))
            }
            Err(_) => Ok(None),
        }
    }
}

impl LinuxAPISource {
    fn parse_kernel_docs(html: &str, function_name: &str) -> String {
        let text = html
            .replace("<br>", "\n")
            .replace("<p>", "\n")
            .replace("</p>", "\n");
        
        TextProcessor::extract_description(&text, function_name)
    }
}

/// POSIX documentation source
pub struct POSIXSource;

impl DocumentationSource for POSIXSource {
    async fn search(
        function_name: &str,
        platform: &str,
        config: &DocumentationLookupConfig,
    ) -> Result<Option<DocumentationSearchResult>> {
        let client = HttpClient::new(config.clone());
        
        // Try OpenGroup POSIX documentation
        let url = format!("https://pubs.opengroup.org/onlinepubs/9699919799/functions/{}.html", function_name);
        
        match client.get_text(&url).await {
            Ok(html) => {
                let description = Self::parse_posix_docs(&html, function_name);
                let header = TextProcessor::extract_function_header(&html, function_name);
                
                let quality_score = TextProcessor::calculate_quality_score(
                    &header,
                    &description,
                    &url,
                    &DocumentationType::POSIX,
                );

                Ok(Some(DocumentationSearchResult {
                    function_name: function_name.to_string(),
                    header,
                    description,
                    source_url: url,
                    documentation_type: DocumentationType::POSIX,
                    quality_score,
                    platform: platform.to_string(),
                }))
            }
            Err(_) => Ok(None),
        }
    }
}

impl POSIXSource {
    fn parse_posix_docs(html: &str, function_name: &str) -> String {
        let text = html
            .replace("<br>", "\n")
            .replace("<p>", "\n")
            .replace("</p>", "\n");
        
        TextProcessor::extract_description(&text, function_name)
    }
}

/// Manual page source
pub struct ManualPageSource;

impl DocumentationSource for ManualPageSource {
    async fn search(
        function_name: &str,
        platform: &str,
        config: &DocumentationLookupConfig,
    ) -> Result<Option<DocumentationSearchResult>> {
        let client = HttpClient::new(config.clone());
        
        // Try man7.org for manual pages
        let url = format!("https://man7.org/linux/man-pages/man2/{}.2.html", function_name);
        
        match client.get_text(&url).await {
            Ok(html) => {
                let description = Self::parse_man_page(&html, function_name);
                let header = TextProcessor::extract_function_header(&html, function_name);
                
                let quality_score = TextProcessor::calculate_quality_score(
                    &header,
                    &description,
                    &url,
                    &DocumentationType::Manual,
                );

                Ok(Some(DocumentationSearchResult {
                    function_name: function_name.to_string(),
                    header,
                    description,
                    source_url: url,
                    documentation_type: DocumentationType::Manual,
                    quality_score,
                    platform: platform.to_string(),
                }))
            }
            Err(_) => {
                // Try section 3 (library functions)
                Self::try_section_3(function_name, platform, config).await
            }
        }
    }
}

impl ManualPageSource {
    async fn try_section_3(
        function_name: &str,
        platform: &str,
        config: &DocumentationLookupConfig,
    ) -> Result<Option<DocumentationSearchResult>> {
        let client = HttpClient::new(config.clone());
        let url = format!("https://man7.org/linux/man-pages/man3/{}.3.html", function_name);
        
        match client.get_text(&url).await {
            Ok(html) => {
                let description = Self::parse_man_page(&html, function_name);
                let header = TextProcessor::extract_function_header(&html, function_name);
                
                let quality_score = TextProcessor::calculate_quality_score(
                    &header,
                    &description,
                    &url,
                    &DocumentationType::Manual,
                );

                Ok(Some(DocumentationSearchResult {
                    function_name: function_name.to_string(),
                    header,
                    description,
                    source_url: url,
                    documentation_type: DocumentationType::Manual,
                    quality_score,
                    platform: platform.to_string(),
                }))
            }
            Err(_) => Ok(None),
        }
    }

    fn parse_man_page(html: &str, function_name: &str) -> String {
        let text = html
            .replace("<br>", "\n")
            .replace("<p>", "\n")
            .replace("</p>", "\n")
            .replace("<pre>", "\n")
            .replace("</pre>", "\n");
        
        TextProcessor::extract_description(&text, function_name)
    }
}
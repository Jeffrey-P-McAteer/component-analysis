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
        
        // Try cppreference.com with different URL patterns
        let cppreference_urls = vec![
            format!("https://en.cppreference.com/w/c/string/byte/{}", function_name),
            format!("https://en.cppreference.com/w/c/memory/{}", function_name),
            format!("https://en.cppreference.com/w/c/io/{}", function_name),
            format!("https://en.cppreference.com/w/c/numeric/math/{}", function_name),
            format!("https://en.cppreference.com/w/c/{}", function_name),
        ];
        
        for url in &cppreference_urls {
            log::debug!("StandardLibrarySource: Trying cppreference.com URL: {}", url);
            
            match client.get_text(url).await {
                Ok(html) => {
                    if !html.contains("404") && !html.contains("not found") && html.len() > 1000 {
                        log::info!("StandardLibrarySource: Successfully fetched HTML from cppreference.com for '{}'", function_name);
                        log::debug!("StandardLibrarySource: HTML content length: {} characters", html.len());
                        
                        let description = Self::parse_cppreference_html(&html, function_name);
                        let header = TextProcessor::extract_function_header(&html, function_name);
                        
                        if !description.is_empty() {
                            log::debug!("StandardLibrarySource: Extracted description length: {} chars", description.len());
                            log::debug!("StandardLibrarySource: Extracted header: {:?}", header);
                            
                            let quality_score = TextProcessor::calculate_quality_score(
                                &header,
                                &description,
                                url,
                                &DocumentationType::StandardLibrary,
                            );
                            
                            log::info!("StandardLibrarySource: Generated documentation for '{}' with quality score: {:.2}", function_name, quality_score);

                            return Ok(Some(DocumentationSearchResult {
                                function_name: function_name.to_string(),
                                header,
                                description,
                                source_url: url.clone(),
                                documentation_type: DocumentationType::StandardLibrary,
                                quality_score,
                                platform: platform.to_string(),
                            }));
                        }
                    }
                }
                Err(e) => {
                    log::debug!("StandardLibrarySource: Failed to fetch from cppreference.com {}: {}", url, e);
                }
            }
        }
        
        log::debug!("StandardLibrarySource: Falling back to man7.org for '{}'", function_name);
        // Fallback to man7.org
        Self::try_man7_org(function_name, platform, config).await
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
        log::debug!("WindowsAPISource: Searching for function '{}'", function_name);
        let client = HttpClient::new(config.clone());
        
        // Try Microsoft Learn with correct function URL pattern
        // Most Win32 functions are documented at learn.microsoft.com/en-us/windows/win32/api/{dll}/{function}
        // Let's try common DLLs first
        let common_dlls = ["kernel32", "user32", "advapi32", "ntdll", "wininet", "ws2_32"];
        
        for dll in &common_dlls {
            let direct_url = format!("https://learn.microsoft.com/en-us/windows/win32/api/{}/{}", dll, function_name.to_lowercase());
            log::debug!("WindowsAPISource: Trying Microsoft Learn URL with {}: {}", dll, direct_url);
            
            match client.get_text(&direct_url).await {
                Ok(html) => {
                    if !html.contains("404") && !html.contains("not found") && html.len() > 1000 {
                        let description = Self::parse_microsoft_learn(&html, function_name);
                        let header = Self::extract_windows_function_header(&html, function_name);
                        
                        if !description.is_empty() {
                            let quality_score = TextProcessor::calculate_quality_score(
                                &header,
                                &description,
                                &direct_url,
                                &DocumentationType::WindowsAPI,
                            );

                            log::info!("WindowsAPISource: Found documentation from Microsoft Learn for '{}'", function_name);
                            return Ok(Some(DocumentationSearchResult {
                                function_name: function_name.to_string(),
                                header,
                                description,
                                source_url: direct_url,
                                documentation_type: DocumentationType::WindowsAPI,
                                quality_score,
                                platform: platform.to_string(),
                            }));
                        }
                    }
                }
                Err(e) => {
                    log::debug!("WindowsAPISource: Failed to fetch from {}: {}", dll, e);
                }
            }
        }
        
        // Try generic Microsoft Learn search
        let search_url = format!("https://learn.microsoft.com/en-us/search/?terms={}", function_name);
        log::debug!("WindowsAPISource: Trying Microsoft Learn search: {}", search_url);
        
        match client.get_text(&search_url).await {
            Ok(html) => {
                if !html.contains("404") && !html.contains("not found") && html.len() > 1000 {
                    let description = Self::parse_microsoft_search(&html, function_name);
                    let header = Self::extract_windows_function_header(&html, function_name);
                    
                    if !description.is_empty() {
                        let quality_score = TextProcessor::calculate_quality_score(
                            &header,
                            &description,
                            &search_url,
                            &DocumentationType::WindowsAPI,
                        );

                        log::info!("WindowsAPISource: Found documentation from Microsoft Learn search for '{}'", function_name);
                        return Ok(Some(DocumentationSearchResult {
                            function_name: function_name.to_string(),
                            header,
                            description,
                            source_url: search_url,
                            documentation_type: DocumentationType::WindowsAPI,
                            quality_score: quality_score * 0.9, // Slightly lower quality for search results
                            platform: platform.to_string(),
                        }));
                    }
                }
            }
            Err(e) => {
                log::debug!("WindowsAPISource: Failed to fetch search URL: {}", e);
            }
        }
        
        // Try MSDN documentation
        let msdn_url = format!("https://docs.microsoft.com/en-us/previous-versions/windows/desktop/api/{}", function_name.to_lowercase());
        log::debug!("WindowsAPISource: Trying MSDN URL: {}", msdn_url);
        
        match client.get_text(&msdn_url).await {
            Ok(html) => {
                let description = Self::parse_microsoft_docs(&html, function_name);
                let header = Self::extract_windows_function_header(&html, function_name);
                
                if !description.is_empty() {
                    let quality_score = TextProcessor::calculate_quality_score(
                        &header,
                        &description,
                        &msdn_url,
                        &DocumentationType::WindowsAPI,
                    );

                    log::info!("WindowsAPISource: Found documentation from MSDN for '{}'", function_name);
                    return Ok(Some(DocumentationSearchResult {
                        function_name: function_name.to_string(),
                        header,
                        description,
                        source_url: msdn_url,
                        documentation_type: DocumentationType::WindowsAPI,
                        quality_score,
                        platform: platform.to_string(),
                    }));
                }
            }
            Err(e) => {
                log::debug!("WindowsAPISource: Failed to fetch MSDN URL: {}", e);
            }
        }
        
        // Try pinvoke.net as fallback for Windows API functions
        if let Some(result) = Self::try_pinvoke_net(function_name, platform, config).await? {
            return Ok(Some(result));
        }
        
        // Try undocumented/ntapi sources for NT functions
        if function_name.starts_with("Nt") || function_name.starts_with("Zw") {
            Self::try_ntapi_documentation(function_name, platform, config).await
        } else {
            Ok(None)
        }
    }
}

impl WindowsAPISource {
    async fn try_pinvoke_net(
        function_name: &str,
        platform: &str,
        config: &DocumentationLookupConfig,
    ) -> Result<Option<DocumentationSearchResult>> {
        let client = HttpClient::new(config.clone());
        let url = format!("https://pinvoke.net/{}", function_name);
        log::debug!("WindowsAPISource: Trying pinvoke.net URL: {}", url);
        
        match client.get_text(&url).await {
            Ok(html) => {
                if html.contains("not found") || html.len() < 500 {
                    log::debug!("WindowsAPISource: Function not found on pinvoke.net");
                    return Ok(None);
                }
                
                let description = Self::parse_pinvoke_net(&html, function_name);
                let header = Self::extract_pinvoke_signature(&html, function_name);
                
                if !description.is_empty() {
                    let quality_score = TextProcessor::calculate_quality_score(
                        &header,
                        &description,
                        &url,
                        &DocumentationType::WindowsAPI,
                    );

                    log::info!("WindowsAPISource: Found documentation from pinvoke.net for '{}'", function_name);
                    return Ok(Some(DocumentationSearchResult {
                        function_name: function_name.to_string(),
                        header,
                        description,
                        source_url: url,
                        documentation_type: DocumentationType::WindowsAPI,
                        quality_score: quality_score * 0.8, // Lower quality score for pinvoke.net
                        platform: platform.to_string(),
                    }));
                }
            }
            Err(e) => {
                log::debug!("WindowsAPISource: Failed to fetch pinvoke.net: {}", e);
            }
        }
        
        Ok(None)
    }
    
    async fn try_ntapi_documentation(
        function_name: &str,
        platform: &str,
        config: &DocumentationLookupConfig,
    ) -> Result<Option<DocumentationSearchResult>> {
        let client = HttpClient::new(config.clone());
        
        // Try multiple NT API documentation sources
        let sources = vec![
            format!("https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/{}", function_name.to_lowercase()),
            format!("https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/{}", function_name.to_lowercase()),
            format!("https://undocumented.ntinternals.net/{}", function_name),
        ];
        
        for url in sources {
            log::debug!("WindowsAPISource: Trying NT API URL: {}", url);
            
            match client.get_text(&url).await {
                Ok(html) => {
                    if html.contains("404") || html.contains("not found") || html.len() < 1000 {
                        continue;
                    }
                    
                    let description = Self::parse_nt_api_docs(&html, function_name);
                    let header = Self::extract_nt_function_header(&html, function_name);
                    
                    if !description.is_empty() {
                        let quality_score = TextProcessor::calculate_quality_score(
                            &header,
                            &description,
                            &url,
                            &DocumentationType::WindowsAPI,
                        );

                        log::info!("WindowsAPISource: Found NT API documentation for '{}'", function_name);
                        let final_quality_score = if url.contains("microsoft.com") { quality_score } else { quality_score * 0.7 };
                        return Ok(Some(DocumentationSearchResult {
                            function_name: function_name.to_string(),
                            header,
                            description,
                            source_url: url,
                            documentation_type: DocumentationType::WindowsAPI,
                            quality_score: final_quality_score,
                            platform: platform.to_string(),
                        }));
                    }
                }
                Err(e) => {
                    log::debug!("WindowsAPISource: Failed to fetch NT API URL: {}", e);
                }
            }
        }
        
        // If no NT API docs found, try to provide basic information for common functions
        Self::provide_builtin_nt_documentation(function_name, platform)
    }
    
    fn provide_builtin_nt_documentation(
        function_name: &str,
        platform: &str,
    ) -> Result<Option<DocumentationSearchResult>> {
        let (header, description) = match function_name {
            "NtDeviceIoControlFile" => (
                "NTSTATUS NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)".to_string(),
                "The NtDeviceIoControlFile routine sends a control code directly to a specified device driver, causing the corresponding driver to perform the specified operation. This is the native NT API equivalent of DeviceIoControl.".to_string()
            ),
            "NtCreateFile" => (
                "NTSTATUS NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)".to_string(),
                "The NtCreateFile routine creates a new file or opens an existing file. This is the native NT API equivalent of CreateFile.".to_string()
            ),
            "NtReadFile" => (
                "NTSTATUS NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)".to_string(),
                "The NtReadFile routine reads data from an open file. This is the native NT API equivalent of ReadFile.".to_string()
            ),
            "NtWriteFile" => (
                "NTSTATUS NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)".to_string(),
                "The NtWriteFile routine writes data to an open file. This is the native NT API equivalent of WriteFile.".to_string()
            ),
            "NtClose" => (
                "NTSTATUS NtClose(HANDLE Handle)".to_string(),
                "The NtClose routine closes an object handle. This is the native NT API equivalent of CloseHandle.".to_string()
            ),
            "ZwQueryInformationProcess" => (
                "NTSTATUS ZwQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)".to_string(),
                "The ZwQueryInformationProcess routine retrieves information about the specified process. This function provides access to process information that is not readily available through other mechanisms.".to_string()
            ),
            _ => return Ok(None),
        };
        
        let quality_score = 0.6; // Built-in documentation has moderate quality
        
        log::info!("WindowsAPISource: Using built-in documentation for '{}'", function_name);
        Ok(Some(DocumentationSearchResult {
            function_name: function_name.to_string(),
            header: Some(header),
            description,
            source_url: "Built-in documentation".to_string(),
            documentation_type: DocumentationType::WindowsAPI,
            quality_score,
            platform: platform.to_string(),
        }))
    }
    
    fn parse_nt_api_docs(html: &str, function_name: &str) -> String {
        // Parse Microsoft driver documentation format
        if let Some(start) = html.find("## Syntax") {
            if let Some(end) = html[start..].find("## Parameters") {
                let _syntax_section = &html[start..start + end];
                if let Some(desc_start) = html.find("## Remarks") {
                    if let Some(desc_end) = html[desc_start..].find("## Requirements") {
                        let remarks = &html[desc_start..desc_start + desc_end];
                        return Self::clean_html_text(remarks);
                    }
                }
            }
        }
        
        Self::parse_microsoft_docs(html, function_name)
    }
    
    fn extract_nt_function_header(html: &str, function_name: &str) -> Option<String> {
        // Look for syntax blocks in driver documentation
        if let Some(start) = html.find("```cpp") {
            if let Some(end) = html[start..].find("```") {
                let code_block = &html[start + 6..start + end];
                if code_block.contains(function_name) {
                    return Some(Self::clean_html_text(code_block));
                }
            }
        }
        
        Self::extract_windows_function_header(html, function_name)
    }

    fn parse_microsoft_docs(html: &str, function_name: &str) -> String {
        // Look for specific Microsoft documentation patterns
        if let Some(start) = html.find("<!-- content -->") {
            if let Some(end) = html[start..].find("<!-- /content -->") {
                let content = &html[start..start + end];
                return Self::extract_description_from_content(content, function_name);
            }
        }
        
        // Fallback to basic parsing
        let text = html
            .replace("<br>", "\n")
            .replace("<p>", "\n")
            .replace("</p>", "\n")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&");
        
        TextProcessor::extract_description(&text, function_name)
    }
    
    fn parse_microsoft_learn(html: &str, function_name: &str) -> String {
        // Look for Microsoft Learn specific patterns
        if let Some(start) = html.find(r#"<div class="content">"#) {
            if let Some(end) = html[start..].find("</div>") {
                let content = &html[start..start + end];
                return Self::extract_description_from_content(content, function_name);
            }
        }
        
        // Look for main content area
        if let Some(start) = html.find(r#"<main"#) {
            if let Some(end) = html[start..].find("</main>") {
                let content = &html[start..start + end];
                return Self::extract_description_from_content(content, function_name);
            }
        }
        
        Self::parse_microsoft_docs(html, function_name)
    }
    
    fn parse_microsoft_search(html: &str, function_name: &str) -> String {
        // Parse Microsoft Learn search results
        if let Some(start) = html.find(r#"<div class="search-results">"#) {
            if let Some(end) = html[start..].find("</div>") {
                let content = &html[start..start + end];
                return Self::extract_description_from_content(content, function_name);
            }
        }
        
        // Look for any content that mentions the function
        if html.to_lowercase().contains(&function_name.to_lowercase()) {
            // Extract a reasonable snippet around the function name
            if let Some(pos) = html.to_lowercase().find(&function_name.to_lowercase()) {
                let start = pos.saturating_sub(200);
                let end = (pos + 500).min(html.len());
                let snippet = &html[start..end];
                return Self::clean_html_text(snippet);
            }
        }
        
        String::new()
    }
    
    fn parse_pinvoke_net(html: &str, function_name: &str) -> String {
        // Extract description from pinvoke.net structure
        if let Some(start) = html.find(r#"<div class="summary">"#) {
            if let Some(end) = html[start..].find("</div>") {
                let content = &html[start..start + end];
                let text = content
                    .replace("<br>", "\n")
                    .replace("<p>", "\n")
                    .replace("</p>", "\n");
                return Self::clean_html_text(&text);
            }
        }
        
        // Fallback extraction
        let text = html
            .replace("<br>", "\n")
            .replace("<p>", "\n")
            .replace("</p>", "\n");
        
        TextProcessor::extract_description(&text, function_name)
    }
    
    fn extract_windows_function_header(html: &str, function_name: &str) -> Option<String> {
        // Look for function signatures in various formats
        let patterns = vec![
            format!(r#"<code[^>]*>([^<]*{}[^<]*)</code>"#, function_name),
            format!(r#"<pre[^>]*>([^<]*{}[^<]*)</pre>"#, function_name),
            format!(r#"{}[\s]*\([^)]*\)"#, function_name),
        ];
        
        for pattern in patterns {
            if let Ok(regex) = regex::Regex::new(&pattern) {
                if let Some(captures) = regex.captures(html) {
                    if let Some(header) = captures.get(1) {
                        return Some(Self::clean_html_text(header.as_str()));
                    }
                }
            }
        }
        
        TextProcessor::extract_function_header(html, function_name)
    }
    
    fn extract_pinvoke_signature(html: &str, function_name: &str) -> Option<String> {
        // Extract C# P/Invoke signature and convert to C-style
        if let Some(start) = html.find("[DllImport") {
            if let Some(end) = html[start..].find(";") {
                let signature_block = &html[start..start + end];
                if signature_block.contains(function_name) {
                    // Extract the actual function declaration
                    let lines: Vec<&str> = signature_block.lines().collect();
                    for line in lines {
                        if line.contains(function_name) && line.contains("(") {
                            return Some(Self::convert_pinvoke_to_c_signature(line, function_name));
                        }
                    }
                }
            }
        }
        
        None
    }
    
    fn convert_pinvoke_to_c_signature(pinvoke_line: &str, _function_name: &str) -> String {
        // Basic conversion from C# P/Invoke to C signature
        let cleaned = pinvoke_line
            .replace("public static extern ", "")
            .replace("static extern ", "")
            .replace("IntPtr", "HANDLE")
            .replace("string", "LPCSTR")
            .replace("uint", "DWORD")
            .replace("int", "INT")
            .replace("bool", "BOOL");
        
        Self::clean_html_text(&cleaned)
    }
    
    fn extract_description_from_content(content: &str, _function_name: &str) -> String {
        // Extract meaningful description from content div
        let text = content
            .replace("<br>", "\n")
            .replace("<p>", "\n")
            .replace("</p>", "\n")
            .replace("<li>", "- ")
            .replace("</li>", "\n");
        
        Self::clean_html_text(&text)
    }
    
    fn clean_html_text(text: &str) -> String {
        // Remove HTML tags and clean up text
        let without_tags = regex::Regex::new(r"<[^>]*>")
            .unwrap()
            .replace_all(text, " ");
        
        without_tags
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DocumentationLookupConfig, DocumentationType};
    use tokio::runtime::Runtime;
    
    // Helper function to create a test config
    fn test_config() -> DocumentationLookupConfig {
        DocumentationLookupConfig {
            user_agent: "component-analyzer-test/0.1.0".to_string(),
            timeout_seconds: 30,
            max_retries: 2,
            cache_duration_hours: 1,
            preferred_sources: vec![
                DocumentationType::WindowsAPI,
                DocumentationType::StandardLibrary,
                DocumentationType::LinuxAPI,
            ],
        }
    }
    
    #[test]
    fn test_win32_function_createfile() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let config = test_config();
            let result = WindowsAPISource::search("CreateFile", "windows", &config).await;
            
            match result {
                Ok(Some(doc)) => {
                    println!("✅ CreateFile documentation found:");
                    println!("Header: {:?}", doc.header);
                    println!("Description length: {} chars", doc.description.len());
                    println!("Source: {}", doc.source_url);
                    println!("Quality: {:.2}", doc.quality_score);
                    
                    assert!(!doc.description.is_empty(), "Description should not be empty");
                    assert!(doc.function_name == "CreateFile", "Function name should match");
                    assert!(doc.documentation_type == DocumentationType::WindowsAPI, "Should be Windows API type");
                }
                Ok(None) => {
                    panic!("❌ No documentation found for CreateFile");
                }
                Err(e) => {
                    panic!("❌ Error looking up CreateFile: {}", e);
                }
            }
        });
    }
    
    #[test]
    fn test_win32_function_virtualprotect() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let config = test_config();
            let result = WindowsAPISource::search("VirtualProtect", "windows", &config).await;
            
            match result {
                Ok(Some(doc)) => {
                    println!("✅ VirtualProtect documentation found:");
                    println!("Header: {:?}", doc.header);
                    println!("Description length: {} chars", doc.description.len());
                    println!("Source: {}", doc.source_url);
                    println!("Quality: {:.2}", doc.quality_score);
                    
                    assert!(!doc.description.is_empty(), "Description should not be empty");
                    assert!(doc.function_name == "VirtualProtect", "Function name should match");
                    assert!(doc.documentation_type == DocumentationType::WindowsAPI, "Should be Windows API type");
                }
                Ok(None) => {
                    panic!("❌ No documentation found for VirtualProtect");
                }
                Err(e) => {
                    panic!("❌ Error looking up VirtualProtect: {}", e);
                }
            }
        });
    }
    
    #[test]
    fn test_win32_function_readfile() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let config = test_config();
            let result = WindowsAPISource::search("ReadFile", "windows", &config).await;
            
            match result {
                Ok(Some(doc)) => {
                    println!("✅ ReadFile documentation found:");
                    println!("Header: {:?}", doc.header);
                    println!("Description length: {} chars", doc.description.len());
                    println!("Source: {}", doc.source_url);
                    println!("Quality: {:.2}", doc.quality_score);
                    
                    assert!(!doc.description.is_empty(), "Description should not be empty");
                    assert!(doc.function_name == "ReadFile", "Function name should match");
                    assert!(doc.documentation_type == DocumentationType::WindowsAPI, "Should be Windows API type");
                }
                Ok(None) => {
                    panic!("❌ No documentation found for ReadFile");
                }
                Err(e) => {
                    panic!("❌ Error looking up ReadFile: {}", e);
                }
            }
        });
    }
    
    #[test]
    fn test_libc_function_strlen() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let config = test_config();
            let result = StandardLibrarySource::search("strlen", "generic", &config).await;
            
            match result {
                Ok(Some(doc)) => {
                    println!("✅ strlen documentation found:");
                    println!("Header: {:?}", doc.header);
                    println!("Description length: {} chars", doc.description.len());
                    println!("Source: {}", doc.source_url);
                    println!("Quality: {:.2}", doc.quality_score);
                    
                    assert!(!doc.description.is_empty(), "Description should not be empty");
                    assert!(doc.function_name == "strlen", "Function name should match");
                    assert!(doc.documentation_type == DocumentationType::StandardLibrary, "Should be Standard Library type");
                }
                Ok(None) => {
                    panic!("❌ No documentation found for strlen");
                }
                Err(e) => {
                    panic!("❌ Error looking up strlen: {}", e);
                }
            }
        });
    }
    
    #[test]
    fn test_libc_function_malloc() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let config = test_config();
            let result = StandardLibrarySource::search("malloc", "generic", &config).await;
            
            match result {
                Ok(Some(doc)) => {
                    println!("✅ malloc documentation found:");
                    println!("Header: {:?}", doc.header);
                    println!("Description length: {} chars", doc.description.len());
                    println!("Source: {}", doc.source_url);
                    println!("Quality: {:.2}", doc.quality_score);
                    
                    assert!(!doc.description.is_empty(), "Description should not be empty");
                    assert!(doc.function_name == "malloc", "Function name should match");
                    assert!(doc.documentation_type == DocumentationType::StandardLibrary, "Should be Standard Library type");
                }
                Ok(None) => {
                    panic!("❌ No documentation found for malloc");
                }
                Err(e) => {
                    panic!("❌ Error looking up malloc: {}", e);
                }
            }
        });
    }
    
    #[test]
    fn test_libc_function_printf() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let config = test_config();
            let result = StandardLibrarySource::search("printf", "generic", &config).await;
            
            match result {
                Ok(Some(doc)) => {
                    println!("✅ printf documentation found:");
                    println!("Header: {:?}", doc.header);
                    println!("Description length: {} chars", doc.description.len());
                    println!("Source: {}", doc.source_url);
                    println!("Quality: {:.2}", doc.quality_score);
                    
                    assert!(!doc.description.is_empty(), "Description should not be empty");
                    assert!(doc.function_name == "printf", "Function name should match");
                    assert!(doc.documentation_type == DocumentationType::StandardLibrary, "Should be Standard Library type");
                }
                Ok(None) => {
                    panic!("❌ No documentation found for printf");
                }
                Err(e) => {
                    panic!("❌ Error looking up printf: {}", e);
                }
            }
        });
    }
    
    #[test]
    fn test_cppreference_direct_access() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let config = test_config();
            let client = HttpClient::new(config);
            
            // Test direct access to a known cppreference page
            let url = "https://en.cppreference.com/w/c/string/byte/strlen";
            match client.get_text(url).await {
                Ok(html) => {
                    println!("✅ Successfully fetched cppreference strlen page");
                    println!("Content length: {} chars", html.len());
                    assert!(html.contains("strlen"), "Page should contain 'strlen'");
                    assert!(html.len() > 1000, "Page should have substantial content");
                    
                    // Test parsing
                    let description = StandardLibrarySource::parse_cppreference_html(&html, "strlen");
                    println!("Parsed description length: {} chars", description.len());
                    if !description.is_empty() {
                        println!("✅ Successfully parsed description from cppreference");
                    } else {
                        println!("⚠️  Parsing needs improvement - no description extracted");
                    }
                }
                Err(e) => {
                    println!("⚠️  Failed to access cppreference directly: {}", e);
                }
            }
        });
    }
    
    #[test]
    fn test_microsoft_learn_direct_access() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let config = test_config();
            let client = HttpClient::new(config);
            
            // Test direct access to a known Microsoft Learn page
            let url = "https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea";
            match client.get_text(url).await {
                Ok(html) => {
                    println!("✅ Successfully fetched Microsoft Learn CreateFileA page");
                    println!("Content length: {} chars", html.len());
                    assert!(html.to_lowercase().contains("createfile"), "Page should contain 'createfile'");
                    assert!(html.len() > 1000, "Page should have substantial content");
                    
                    // Test parsing
                    let description = WindowsAPISource::parse_microsoft_learn(&html, "CreateFileA");
                    println!("Parsed description length: {} chars", description.len());
                    if !description.is_empty() {
                        println!("✅ Successfully parsed description from Microsoft Learn");
                    } else {
                        println!("⚠️  Parsing needs improvement - no description extracted");
                    }
                }
                Err(e) => {
                    println!("⚠️  Failed to access Microsoft Learn directly: {}", e);
                }
            }
        });
    }
}
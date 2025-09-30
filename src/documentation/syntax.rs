#[cfg(feature = "gui")]
use syntect::easy::HighlightLines;
#[cfg(feature = "gui")]
use syntect::highlighting::{ThemeSet, Style};
#[cfg(feature = "gui")]
use syntect::parsing::SyntaxSet;
#[cfg(feature = "gui")]
use syntect::util::{as_24_bit_terminal_escaped, LinesWithEndings};

#[cfg(feature = "gui")]
use egui::{Color32, RichText};

/// Syntax highlighter for function headers and code snippets
#[cfg(feature = "gui")]
pub struct SyntaxHighlighter {
    syntax_set: SyntaxSet,
    theme_set: ThemeSet,
}

#[cfg(feature = "gui")]
impl SyntaxHighlighter {
    pub fn new() -> Self {
        Self {
            syntax_set: SyntaxSet::load_defaults_newlines(),
            theme_set: ThemeSet::load_defaults(),
        }
    }

    /// Highlight a C function header
    pub fn highlight_c_header(&self, header: &str) -> Vec<(String, Color32)> {
        self.highlight_code(header, "C")
    }

    /// Highlight code with the specified language
    pub fn highlight_code(&self, code: &str, language: &str) -> Vec<(String, Color32)> {
        let syntax = self.syntax_set
            .find_syntax_by_name(language)
            .or_else(|| self.syntax_set.find_syntax_by_extension("c"))
            .unwrap_or_else(|| self.syntax_set.find_syntax_plain_text());

        let theme = &self.theme_set.themes["base16-ocean.dark"];
        let mut highlighter = HighlightLines::new(syntax, theme);

        let mut highlighted_parts = Vec::new();

        for line in LinesWithEndings::from(code) {
            let ranges = highlighter.highlight_line(line, &self.syntax_set).unwrap_or_default();
            
            for (style, text) in ranges {
                let color = Self::style_to_color32(style);
                highlighted_parts.push((text.to_string(), color));
            }
        }

        highlighted_parts
    }

    /// Convert syntect Style to egui Color32
    fn style_to_color32(style: Style) -> Color32 {
        Color32::from_rgb(
            style.foreground.r,
            style.foreground.g,
            style.foreground.b,
        )
    }

    /// Create a highlighted RichText for egui
    pub fn create_rich_text(&self, code: &str, language: &str) -> Vec<RichText> {
        let highlighted = self.highlight_code(code, language);
        highlighted
            .into_iter()
            .map(|(text, color)| RichText::new(text).color(color))
            .collect()
    }

    /// Format function header with basic highlighting (fallback without syntect)
    pub fn format_header_basic(header: &str) -> Vec<(String, Color32)> {
        let mut parts = Vec::new();
        let tokens: Vec<&str> = header.split_whitespace().collect();

        for (i, token) in tokens.iter().enumerate() {
            let color = match *token {
                // Return types
                t if t.starts_with("int") || t.starts_with("void") || t.starts_with("char") || 
                     t.starts_with("size_t") || t.starts_with("BOOL") || t.starts_with("HANDLE") ||
                     t.starts_with("NTSTATUS") || t.starts_with("DWORD") => Color32::LIGHT_BLUE,
                
                // Keywords
                "const" | "static" | "extern" | "inline" => Color32::from_rgb(255, 128, 0), // Orange
                
                // Function name (usually after return type)
                t if i > 0 && t.contains('(') => Color32::from_rgb(255, 255, 128), // Light yellow
                
                // Parameters and other tokens
                _ => Color32::WHITE,
            };

            parts.push((token.to_string(), color));
            
            // Add space between tokens except for the last one
            if i < tokens.len() - 1 {
                parts.push((" ".to_string(), Color32::WHITE));
            }
        }

        parts
    }
}

#[cfg(feature = "gui")]
impl Default for SyntaxHighlighter {
    fn default() -> Self {
        Self::new()
    }
}

// Fallback implementations when GUI feature is not enabled
#[cfg(not(feature = "gui"))]
pub struct SyntaxHighlighter;

#[cfg(not(feature = "gui"))]
impl SyntaxHighlighter {
    pub fn new() -> Self {
        Self
    }

    pub fn highlight_c_header(&self, _header: &str) -> Vec<(String, ())> {
        vec![]
    }

    pub fn highlight_code(&self, _code: &str, _language: &str) -> Vec<(String, ())> {
        vec![]
    }

    pub fn format_header_basic(header: &str) -> Vec<(String, ())> {
        vec![(header.to_string(), ())]
    }
}

#[cfg(not(feature = "gui"))]
impl Default for SyntaxHighlighter {
    fn default() -> Self {
        Self::new()
    }
}
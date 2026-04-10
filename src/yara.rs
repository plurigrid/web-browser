//! Pre-render content scanning via magic bytes and pattern matching.
//!
//! Lightweight YARA-style rules without the YARA dependency.
//! Checks magic bytes, polyglot detection, and suspicious patterns
//! on reassembled QUIC stream content before rendering.

use crate::greywall::Verdict;

/// Known magic byte signatures.
const MAGIC: &[(&str, &[u8])] = &[
    ("PDF", b"%PDF"),
    ("PNG", &[0x89, 0x50, 0x4E, 0x47]),
    ("JPEG", &[0xFF, 0xD8, 0xFF]),
    ("GIF", b"GIF8"),
    ("ZIP", &[0x50, 0x4B, 0x03, 0x04]),
    ("GZIP", &[0x1F, 0x8B]),
    ("ELF", &[0x7F, 0x45, 0x4C, 0x46]),
    ("PE/MZ", &[0x4D, 0x5A]),
    ("Mach-O 64", &[0xCF, 0xFA, 0xED, 0xFE]),
    ("Mach-O 32", &[0xFE, 0xED, 0xFA, 0xCE]),
    ("WASM", &[0x00, 0x61, 0x73, 0x6D]),
];

/// Suspicious patterns in text/HTML content.
const SUSPICIOUS_PATTERNS: &[(&str, &str)] = &[
    ("javascript eval", "eval("),
    ("base64 data URI", "data:application/octet-stream;base64"),
    ("LD_PRELOAD", "LD_PRELOAD"),
    ("shell injection", "/bin/sh"),
    ("powershell encoded", "-EncodedCommand"),
    ("iframe hidden", "iframe style=\"display:none"),
    ("crypto miner", "coinhive"),
];

/// Executable file types that should never render as HTML.
const EXECUTABLE_MAGIC: &[&str] = &["ELF", "PE/MZ", "Mach-O 64", "Mach-O 32"];

/// Detect file type from magic bytes.
pub fn detect_type(content: &[u8]) -> Option<&'static str> {
    for (name, magic) in MAGIC {
        if content.len() >= magic.len() && &content[..magic.len()] == *magic {
            return Some(name);
        }
    }
    None
}

/// Check for polyglot files (valid as multiple types simultaneously).
fn check_polyglot(content: &[u8], declared_mime: &str) -> Option<String> {
    let detected = detect_type(content);

    match (detected, declared_mime) {
        // Image magic bytes but declared as HTML — classic polyglot attack
        (Some("JPEG" | "PNG" | "GIF"), mime) if mime.contains("html") => {
            Some(format!("polyglot: image magic bytes with {}", mime))
        }
        // Executable magic bytes with any web MIME type
        (Some(exe_type), mime)
            if EXECUTABLE_MAGIC.contains(&exe_type)
                && (mime.contains("html") || mime.contains("javascript") || mime.contains("text")) =>
        {
            Some(format!("executable {} disguised as {}", exe_type, mime))
        }
        // ZIP inside something declared as text
        (Some("ZIP"), mime) if mime.contains("text") || mime.contains("html") => {
            Some(format!("ZIP archive disguised as {}", mime))
        }
        _ => None,
    }
}

/// Scan text content for suspicious patterns.
fn scan_patterns(content: &str) -> Vec<String> {
    let lower = content.to_lowercase();
    SUSPICIOUS_PATTERNS
        .iter()
        .filter(|(_, pattern)| lower.contains(&pattern.to_lowercase()))
        .map(|(name, _)| name.to_string())
        .collect()
}

/// Full content scan pipeline. Returns a verdict.
pub fn scan(content: &[u8], declared_mime: &str) -> Verdict {
    // 1. Polyglot detection (MIME vs magic bytes mismatch)
    if let Some(reason) = check_polyglot(content, declared_mime) {
        return Verdict::Malicious(reason);
    }

    // 2. Executable delivered as web content
    if let Some(file_type) = detect_type(content) {
        if EXECUTABLE_MAGIC.contains(&file_type) && !declared_mime.contains("octet-stream") {
            return Verdict::Malicious(format!(
                "executable {} not declared as octet-stream",
                file_type
            ));
        }
    }

    // 3. Pattern scan on text content
    if declared_mime.contains("text") || declared_mime.contains("html") || declared_mime.contains("javascript") {
        if let Ok(text) = std::str::from_utf8(content) {
            let hits = scan_patterns(text);
            if !hits.is_empty() {
                return Verdict::Suspicious(format!("patterns: {}", hits.join(", ")));
            }
        }
    }

    Verdict::Clean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_png() {
        let content = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A];
        assert_eq!(detect_type(&content), Some("PNG"));
    }

    #[test]
    fn detects_polyglot_jpeg_html() {
        let mut content = vec![0xFF, 0xD8, 0xFF, 0xE0];
        content.extend_from_slice(b"<html>");
        let v = scan(&content, "text/html");
        assert!(matches!(v, Verdict::Malicious(_)));
    }

    #[test]
    fn clean_html_passes() {
        let content = b"<html><body>hello</body></html>";
        let v = scan(content, "text/html");
        assert_eq!(v, Verdict::Clean);
    }

    #[test]
    fn suspicious_eval_flagged() {
        let content = b"<script>eval(atob('...'))</script>";
        let v = scan(content, "text/html");
        assert!(matches!(v, Verdict::Suspicious(_)));
    }

    #[test]
    fn elf_as_html_blocked() {
        let content = [0x7F, 0x45, 0x4C, 0x46, 0x02];
        let v = scan(&content, "text/html");
        assert!(matches!(v, Verdict::Malicious(_)));
    }
}

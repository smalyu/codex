use codex_utils_string::take_bytes_at_char_boundary;

#[derive(Clone, Copy)]
pub(crate) struct TruncationConfig {
    pub max_bytes: usize,
    pub max_lines: usize,
    pub truncation_notice: &'static str,
}

pub(crate) const CONTEXT_OUTPUT_MAX_BYTES: usize = 8 * 1024; // 8 KiB
pub(crate) const CONTEXT_OUTPUT_MAX_LINES: usize = 256;
pub(crate) const CONTEXT_OUTPUT_TRUNCATION_NOTICE: &str = "[... output truncated ...]";

pub(crate) const CONTEXT_OUTPUT_TRUNCATION: TruncationConfig = TruncationConfig {
    max_bytes: CONTEXT_OUTPUT_MAX_BYTES,
    max_lines: CONTEXT_OUTPUT_MAX_LINES,
    truncation_notice: CONTEXT_OUTPUT_TRUNCATION_NOTICE,
};

pub(crate) fn truncate_with_config(content: &str, config: TruncationConfig) -> String {
    let TruncationConfig {
        max_bytes,
        max_lines,
        truncation_notice,
    } = config;

    let truncated_slice = take_bytes_at_char_boundary(content, max_bytes);
    let truncated_by_bytes = truncated_slice.len() < content.len();

    let mut preview = String::new();
    let mut lines_iter = truncated_slice.lines();
    for idx in 0..max_lines {
        match lines_iter.next() {
            Some(line) => {
                if idx > 0 {
                    preview.push('\n');
                }
                preview.push_str(line);
            }
            None => break,
        }
    }
    let truncated_by_lines = lines_iter.next().is_some();

    if !truncated_by_bytes && !truncated_by_lines {
        return content.to_string();
    }

    if preview.len() < truncated_slice.len()
        && truncated_slice
            .as_bytes()
            .get(preview.len())
            .is_some_and(|byte| *byte == b'\n')
    {
        preview.push('\n');
    }

    if !preview.is_empty() && !preview.ends_with('\n') {
        preview.push('\n');
    }

    preview.push_str(truncation_notice);
    preview
}

pub(crate) fn truncate_context_output(content: &str) -> String {
    truncate_with_config(content, CONTEXT_OUTPUT_TRUNCATION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn truncate_with_config_returns_original_within_limits() {
        let content = "short output";
        let config = TruncationConfig {
            max_bytes: 64,
            max_lines: 5,
            truncation_notice: "[notice]",
        };
        assert_eq!(truncate_with_config(content, config), content);
    }

    #[test]
    fn truncate_with_config_truncates_by_bytes() {
        let config = TruncationConfig {
            max_bytes: 16,
            max_lines: 10,
            truncation_notice: "[notice]",
        };
        let content = "abcdefghijklmnopqrstuvwxyz";
        let truncated = truncate_with_config(content, config);
        assert!(truncated.contains("[notice]"));
    }

    #[test]
    fn truncate_with_config_truncates_by_lines() {
        let config = TruncationConfig {
            max_bytes: 1024,
            max_lines: 2,
            truncation_notice: "[notice]",
        };
        let content = "l1\nl2\nl3\nl4";
        let truncated = truncate_with_config(content, config);
        assert!(truncated.lines().count() <= 3);
        assert!(truncated.contains("[notice]"));
    }
}

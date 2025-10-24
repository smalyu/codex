use codex_utils_string::take_bytes_at_char_boundary;

#[derive(Clone, Copy)]
pub(crate) struct TruncationConfig {
    pub max_bytes: usize,
    pub max_lines: usize,
    pub truncation_notice: &'static str,
}

// Telemetry preview limits: keep log events smaller than model budgets.
pub(crate) const TELEMETRY_PREVIEW_MAX_BYTES: usize = 2 * 1024; // 2 KiB
pub(crate) const TELEMETRY_PREVIEW_MAX_LINES: usize = 64; // lines
pub(crate) const TELEMETRY_PREVIEW_TRUNCATION_NOTICE: &str =
    "[... telemetry preview truncated ...]";

pub(crate) const CONTEXT_OUTPUT_TRUNCATION: TruncationConfig = TruncationConfig {
    max_bytes: TELEMETRY_PREVIEW_MAX_BYTES,
    max_lines: TELEMETRY_PREVIEW_MAX_LINES,
    truncation_notice: TELEMETRY_PREVIEW_TRUNCATION_NOTICE,
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

    #[test]
    fn telemetry_preview_returns_original_within_limits() {
        let content = "short output";
        let config = TruncationConfig {
            max_bytes: TELEMETRY_PREVIEW_MAX_BYTES,
            max_lines: TELEMETRY_PREVIEW_MAX_LINES,
            truncation_notice: TELEMETRY_PREVIEW_TRUNCATION_NOTICE,
        };
        assert_eq!(truncate_with_config(content, config), content);
    }

    #[test]
    fn telemetry_preview_truncates_by_bytes() {
        let config = TruncationConfig {
            max_bytes: TELEMETRY_PREVIEW_MAX_BYTES,
            max_lines: TELEMETRY_PREVIEW_MAX_LINES,
            truncation_notice: TELEMETRY_PREVIEW_TRUNCATION_NOTICE,
        };
        let content = "x".repeat(TELEMETRY_PREVIEW_MAX_BYTES + 8);
        let preview = truncate_with_config(&content, config);

        assert!(preview.contains(TELEMETRY_PREVIEW_TRUNCATION_NOTICE));
        assert!(
            preview.len()
                <= TELEMETRY_PREVIEW_MAX_BYTES + TELEMETRY_PREVIEW_TRUNCATION_NOTICE.len() + 1
        );
    }

    #[test]
    fn telemetry_preview_truncates_by_lines() {
        let config = TruncationConfig {
            max_bytes: TELEMETRY_PREVIEW_MAX_BYTES,
            max_lines: TELEMETRY_PREVIEW_MAX_LINES,
            truncation_notice: TELEMETRY_PREVIEW_TRUNCATION_NOTICE,
        };
        let content = (0..(TELEMETRY_PREVIEW_MAX_LINES + 5))
            .map(|idx| format!("line {idx}"))
            .collect::<Vec<_>>()
            .join("\n");

        let preview = truncate_with_config(&content, config);
        let lines: Vec<&str> = preview.lines().collect();

        assert!(lines.len() <= TELEMETRY_PREVIEW_MAX_LINES + 1);
        assert_eq!(lines.last(), Some(&TELEMETRY_PREVIEW_TRUNCATION_NOTICE));
    }
}

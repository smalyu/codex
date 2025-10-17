fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

pub(crate) fn build_report_html(title: &str, markdown: &str) -> String {
    let escaped_title = escape_html(title);
    let escaped_markdown = escape_html(markdown);
    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{escaped_title}</title></head>\
         <body><pre>{escaped_markdown}</pre></body></html>"
    )
}

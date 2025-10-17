const REPORT_STYLES: &str = include_str!("security_report_assets/styles.css");
const REPORT_SCRIPT: &str = include_str!("security_report_assets/script.js");

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
    let report_payload = serde_json::to_string(markdown).unwrap_or_else(|_| "\"\"".to_string());
    let styles = REPORT_STYLES;
    let script = REPORT_SCRIPT;
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{escaped_title}</title>
    <style>{styles}</style>
  </head>
  <body>
    <header class="topbar">
      <div class="brand">
        <div class="site-path" id="site-path">/ Report / {escaped_title}</div>
      </div>
      <div class="top-actions">
        <button id="shareBtn" class="btn primary">Share</button>
        <button id="editToggle" class="btn" aria-pressed="false" title="Toggle edit mode">Edit</button>
        <label class="file-btn btn" for="fileInput">Open</label>
        <input id="fileInput" type="file" accept=".md,.markdown,.txt" hidden />
        <button id="themeToggle" class="icon-btn" title="Toggle dark mode" aria-label="Toggle dark mode">
          <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
            <path id="themeIcon" fill="currentColor" d="M21.64 13a1 1 0 0 0-1.11-.27 8 8 0 0 1-10.26-10.26 1 1 0 0 0-1.38-1.26 10 10 0 1 0 13 13 1 1 0 0 0-.25-1.21Z"/>
          </svg>
        </button>
      </div>
    </header>

    <div class="drop-overlay" id="dropOverlay" aria-hidden="true">
      <div class="drop-message">
        Drop a .md file to load
      </div>
    </div>

    <main class="layout">
      <article class="content" id="content">
      </article>
      <aside class="sidebar right" id="rightToc" aria-label="Table of contents">
        <div class="toc-inner">
          <div class="nav-title" style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
            <span>Outline</span>
            <button id="navToggle" class="icon-btn nav-toggle" aria-pressed="false" aria-label="Collapse sidebar" title="Collapse sidebar">
              <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
                <path id="navIcon" fill="currentColor" d="M9 6l6 6-6 6"/>
              </svg>
            </button>
          </div>
          <div class="toc-search">
            <input id="sectionSearch" class="search-input" type="search" placeholder="Jump to section" aria-label="Jump to section" />
          </div>
          <div id="jobProgressHost"></div>
          <nav id="tocList"></nav>
        </div>
      </aside>
    </main>

    <footer class="footer">
      <div>Drag & drop a Markdown file anywhere, or use Open.</div>
    </footer>

    <script>window.REPORT_MD = {report_payload};</script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/marked/12.0.2/marked.min.js" integrity="sha512-34C8F1MjeV8ie9mZ3Ky2CkLq0xJQbrV8ipkTA2sLQoFE3U8g9Tz6tERx2B4f+0vtoTz0xJ9vC8vI5I3w1lMqDA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js" integrity="sha512-oV9EIt4K+YIjWh1fH2gdJELQ7dC2mCZkMql4aO8D5mBVYIvXcSDCDY7ZZfW4s8l9bGQZ5w0mJ6R1r5gE9c6o8w==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script>{script}</script>
  </body>
</html>
"#
    )
}

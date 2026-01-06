// workbench/export.rs
// Beautiful export - PDF, HTML, Markdown

use super::document::Document;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    Pdf,
    Html,
    Markdown,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportOptions {
    pub format: ExportFormat,
    pub include_summary: bool,
    pub include_timeline: bool,
    pub include_technique: bool,
    pub include_impact: bool,
    pub include_evidence: bool,
    pub include_raw_events: bool,
    pub include_custom_sections: bool,
    pub theme: ExportTheme,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            format: ExportFormat::Html,
            include_summary: true,
            include_timeline: true,
            include_technique: true,
            include_impact: true,
            include_evidence: true,
            include_raw_events: false,
            include_custom_sections: true,
            theme: ExportTheme::Professional,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportTheme {
    Professional, // Clean, corporate
    Dark,         // Dark mode
    Minimal,      // Simple, less styling
    Technical,    // More detailed, monospace
}

pub struct Exporter;

impl Exporter {
    /// Export document to HTML
    pub fn to_html(doc: &Document, options: &ExportOptions) -> String {
        let theme_css = Self::get_theme_css(options.theme);

        let mut html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}</title>
    <style>
{}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{}</h1>
            <div class="meta">
                <span class="date">Generated: {}</span>
                {}
            </div>
        </header>
"#,
            Self::escape_html(&doc.title),
            theme_css,
            Self::escape_html(&doc.title),
            Self::format_timestamp_dt(doc.created_at),
            doc.author
                .as_ref()
                .map(|a| format!(
                    r#"<span class="author">Author: {}</span>"#,
                    Self::escape_html(a)
                ))
                .unwrap_or_default()
        );

        // Summary
        if options.include_summary && !doc.summary.content.is_empty() {
            html.push_str(&format!(
                r#"
        <section class="summary">
            <h2>{}</h2>
            <div class="content">{}</div>
        </section>
"#,
                Self::escape_html(&doc.summary.heading),
                Self::markdown_to_html(&doc.summary.content)
            ));
        }

        // Technique
        if options.include_technique && doc.technique.technique_id.is_some() {
            let tech = &doc.technique;
            html.push_str(&format!(
                r#"
        <section class="technique">
            <h2>MITRE ATT&CK Technique</h2>
            <div class="technique-card">
                <div class="technique-id">{}</div>
                <div class="technique-name">{}</div>
                {}
                {}
            </div>
        </section>
"#,
                tech.technique_id.as_deref().unwrap_or("Unknown"),
                tech.technique_name
                    .as_deref()
                    .unwrap_or("Unknown Technique"),
                tech.tactic
                    .as_ref()
                    .map(|t| format!(
                        r#"<div class="tactic">Tactic: {}</div>"#,
                        Self::escape_html(t)
                    ))
                    .unwrap_or_default(),
                tech.confidence
                    .as_ref()
                    .map(|c| format!(
                        r#"<div class="confidence confidence-{}">Confidence: {}</div>"#,
                        c.to_lowercase(),
                        c
                    ))
                    .unwrap_or_default()
            ));
        }

        // Timeline
        if options.include_timeline && !doc.timeline.entries.is_empty() {
            html.push_str(
                r#"
        <section class="timeline">
            <h2>Attack Timeline</h2>
            <div class="timeline-container">
"#,
            );

            for entry in &doc.timeline.entries {
                if !entry.included {
                    continue;
                }

                let star = if entry.starred {
                    r#"<span class="star">⭐</span>"#
                } else {
                    ""
                };
                let annotation = entry
                    .annotation
                    .as_ref()
                    .map(|a| format!(r#"<div class="annotation">{}</div>"#, Self::escape_html(a)))
                    .unwrap_or_default();

                html.push_str(&format!(
                    r#"
                <div class="timeline-entry{}">
                    <div class="timeline-time">{}</div>
                    <div class="timeline-dot"></div>
                    <div class="timeline-content">
                        <div class="timeline-title">{} {}</div>
                        <div class="timeline-description">{}</div>
                        {}
                        <div class="timeline-type">{}</div>
                    </div>
                </div>
"#,
                    if entry.starred { " starred" } else { "" },
                    Self::format_timestamp(entry.timestamp),
                    Self::escape_html(&entry.title),
                    star,
                    Self::escape_html(&entry.description),
                    annotation,
                    Self::escape_html(&entry.event_type)
                ));
            }

            html.push_str(
                r#"
            </div>
        </section>
"#,
            );
        }

        // Impact
        if options.include_impact && !doc.impact.content.is_empty() {
            html.push_str(&format!(
                r#"
        <section class="impact">
            <h2>{}</h2>
            <div class="content">{}</div>
        </section>
"#,
                Self::escape_html(&doc.impact.heading),
                Self::markdown_to_html(&doc.impact.content)
            ));
        }

        // Evidence
        if options.include_evidence && !doc.evidence.events.is_empty() {
            html.push_str(
                r#"
        <section class="evidence">
            <h2>Evidence</h2>
            <div class="evidence-list">
"#,
            );

            for event in &doc.evidence.events {
                if !event.selected {
                    continue;
                }

                let annotation = event
                    .annotation
                    .as_ref()
                    .map(|a| {
                        format!(
                            r#"<div class="annotation">{}</div>"#,
                            Self::escape_html(&a.text)
                        )
                    })
                    .unwrap_or_default();

                html.push_str(&format!(
                    r#"
                <div class="evidence-item{}">
                    <div class="evidence-header">
                        <span class="evidence-time">{}</span>
                        <span class="evidence-type">{}</span>
                        {}
                    </div>
                    <div class="evidence-title">{}</div>
                    {}
"#,
                    if event.starred { " starred" } else { "" },
                    Self::escape_html(&event.display_time),
                    Self::escape_html(&event.display_type),
                    if event.starred {
                        r#"<span class="star">⭐</span>"#
                    } else {
                        ""
                    },
                    Self::escape_html(&event.display_title),
                    annotation
                ));

                // Raw details if requested
                if options.include_raw_events && !event.display_details.is_empty() {
                    html.push_str(
                        r#"                    <details class="raw-details">
                        <summary>Raw Event Data</summary>
                        <pre>"#,
                    );
                    if let Ok(json) = serde_json::to_string_pretty(&event.display_details) {
                        html.push_str(&Self::escape_html(&json));
                    }
                    html.push_str(
                        r#"</pre>
                    </details>
"#,
                    );
                }

                html.push_str("                </div>\n");
            }

            html.push_str(
                r#"
            </div>
        </section>
"#,
            );
        }

        // Custom sections
        if options.include_custom_sections {
            for section in &doc.custom_sections {
                html.push_str(&format!(
                    r#"
        <section class="custom-section">
            <h2>{}</h2>
            <div class="content">{}</div>
        </section>
"#,
                    Self::escape_html(&section.heading),
                    Self::markdown_to_html(&section.content)
                ));
            }
        }

        // Tags
        if !doc.tags.is_empty() {
            html.push_str(
                r#"
        <section class="tags">
            <div class="tag-list">
"#,
            );
            for tag in &doc.tags {
                html.push_str(&format!(
                    r#"                <span class="tag">{}</span>
"#,
                    Self::escape_html(tag)
                ));
            }
            html.push_str(
                r#"            </div>
        </section>
"#,
            );
        }

        html.push_str(
            r#"
    </div>
</body>
</html>"#,
        );

        html
    }

    /// Export document to Markdown
    pub fn to_markdown(doc: &Document, options: &ExportOptions) -> String {
        let mut md = format!("# {}\n\n", doc.title);

        if let Some(author) = &doc.author {
            md.push_str(&format!("*Author: {}*\n\n", author));
        }
        md.push_str(&format!(
            "*Generated: {}*\n\n",
            Self::format_timestamp_dt(doc.created_at)
        ));

        md.push_str("---\n\n");

        // Summary
        if options.include_summary && !doc.summary.content.is_empty() {
            md.push_str(&format!(
                "## {}\n\n{}\n\n",
                doc.summary.heading, doc.summary.content
            ));
        }

        // Technique
        if options.include_technique && doc.technique.technique_id.is_some() {
            let tech = &doc.technique;
            md.push_str("## MITRE ATT&CK Technique\n\n");
            md.push_str(&format!(
                "**{}** - {}\n\n",
                tech.technique_id.as_deref().unwrap_or("Unknown"),
                tech.technique_name.as_deref().unwrap_or("Unknown")
            ));
            if let Some(tactic) = &tech.tactic {
                md.push_str(&format!("*Tactic: {}*\n\n", tactic));
            }
        }

        // Timeline
        if options.include_timeline && !doc.timeline.entries.is_empty() {
            md.push_str("## Timeline\n\n");
            md.push_str("| Time | Event | Details |\n");
            md.push_str("|------|-------|--------|\n");

            for entry in &doc.timeline.entries {
                if !entry.included {
                    continue;
                }
                let star = if entry.starred { " ⭐" } else { "" };
                md.push_str(&format!(
                    "| {} | {}{} | {} |\n",
                    Self::format_timestamp(entry.timestamp),
                    entry.title,
                    star,
                    entry.description
                ));
            }
            md.push('\n');
        }

        // Impact
        if options.include_impact && !doc.impact.content.is_empty() {
            md.push_str(&format!(
                "## {}\n\n{}\n\n",
                doc.impact.heading, doc.impact.content
            ));
        }

        // Evidence
        if options.include_evidence && !doc.evidence.events.is_empty() {
            md.push_str("## Evidence\n\n");
            for event in &doc.evidence.events {
                if !event.selected {
                    continue;
                }
                let star = if event.starred { " ⭐" } else { "" };
                md.push_str(&format!("### {}{}\n\n", event.display_title, star));
                md.push_str(&format!(
                    "*{}* | `{}`\n\n",
                    event.display_time, event.display_type
                ));

                if let Some(annotation) = &event.annotation {
                    md.push_str(&format!("> {}\n\n", annotation.text));
                }

                if options.include_raw_events && !event.display_details.is_empty() {
                    md.push_str("<details>\n<summary>Raw Event Data</summary>\n\n```json\n");
                    if let Ok(json) = serde_json::to_string_pretty(&event.display_details) {
                        md.push_str(&json);
                    }
                    md.push_str("\n```\n</details>\n\n");
                }
            }
        }

        // Custom sections
        if options.include_custom_sections {
            for section in &doc.custom_sections {
                md.push_str(&format!(
                    "## {}\n\n{}\n\n",
                    section.heading, section.content
                ));
            }
        }

        // Tags
        if !doc.tags.is_empty() {
            md.push_str("---\n\n");
            md.push_str("**Tags:** ");
            md.push_str(
                &doc.tags
                    .iter()
                    .map(|t| format!("`{}`", t))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            md.push('\n');
        }

        md
    }

    /// Export document to JSON (for re-import or API)
    pub fn to_json(doc: &Document) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(doc)
    }

    fn escape_html(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
    }

    fn markdown_to_html(md: &str) -> String {
        // Simple markdown conversion - in production, use a proper markdown parser
        let html = md.replace("\n\n", "</p><p>").replace("\n", "<br>");
        format!("<p>{}</p>", html)
    }

    fn format_timestamp_dt(ts: chrono::DateTime<chrono::Utc>) -> String {
        ts.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    }

    fn format_timestamp(ts: u64) -> String {
        use chrono::{TimeZone, Utc};
        Utc.timestamp_millis_opt(ts as i64)
            .single()
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| format!("{}ms", ts))
    }

    fn get_theme_css(theme: ExportTheme) -> &'static str {
        match theme {
            ExportTheme::Professional => THEME_PROFESSIONAL,
            ExportTheme::Dark => THEME_DARK,
            ExportTheme::Minimal => THEME_MINIMAL,
            ExportTheme::Technical => THEME_TECHNICAL,
        }
    }
}

const THEME_PROFESSIONAL: &str = r#"
        :root {
            --primary: #2563eb;
            --secondary: #64748b;
            --accent: #f59e0b;
            --bg: #ffffff;
            --text: #1e293b;
            --border: #e2e8f0;
            --card-bg: #f8fafc;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: var(--text);
            background: var(--bg);
            padding: 2rem;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
        }
        
        header {
            border-bottom: 3px solid var(--primary);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }
        
        h1 {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary);
            margin-bottom: 0.5rem;
        }
        
        .meta {
            color: var(--secondary);
            font-size: 0.9rem;
        }
        
        .meta span { margin-right: 1.5rem; }
        
        section {
            margin-bottom: 2.5rem;
        }
        
        h2 {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--text);
            border-bottom: 2px solid var(--border);
            padding-bottom: 0.5rem;
            margin-bottom: 1rem;
        }
        
        .content p {
            margin-bottom: 1rem;
        }
        
        /* Technique Card */
        .technique-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            border-left: 4px solid var(--primary);
        }
        
        .technique-id {
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--primary);
        }
        
        .technique-name {
            font-size: 1.1rem;
            margin: 0.25rem 0;
        }
        
        .tactic, .confidence {
            font-size: 0.9rem;
            color: var(--secondary);
        }
        
        .confidence-high { color: #dc2626; }
        .confidence-medium { color: #f59e0b; }
        .confidence-low { color: #22c55e; }
        
        /* Timeline */
        .timeline-container {
            position: relative;
            padding-left: 2rem;
        }
        
        .timeline-container::before {
            content: '';
            position: absolute;
            left: 6px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: var(--border);
        }
        
        .timeline-entry {
            position: relative;
            padding-bottom: 1.5rem;
        }
        
        .timeline-entry.starred {
            background: #fef3c7;
            margin: -0.5rem;
            padding: 0.5rem;
            padding-left: 2.5rem;
            border-radius: 8px;
        }
        
        .timeline-dot {
            position: absolute;
            left: -1.75rem;
            top: 0.25rem;
            width: 12px;
            height: 12px;
            background: var(--primary);
            border-radius: 50%;
            border: 2px solid var(--bg);
        }
        
        .timeline-time {
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.8rem;
            color: var(--secondary);
        }
        
        .timeline-title {
            font-weight: 600;
            margin: 0.25rem 0;
        }
        
        .timeline-description {
            color: var(--secondary);
        }
        
        .timeline-type {
            display: inline-block;
            font-size: 0.75rem;
            background: var(--border);
            padding: 0.125rem 0.5rem;
            border-radius: 4px;
            margin-top: 0.5rem;
        }
        
        .annotation {
            background: #dbeafe;
            border-left: 3px solid var(--primary);
            padding: 0.5rem 0.75rem;
            margin: 0.5rem 0;
            font-style: italic;
            border-radius: 0 4px 4px 0;
        }
        
        .star { margin-left: 0.25rem; }
        
        /* Evidence */
        .evidence-item {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        
        .evidence-item.starred {
            border-color: var(--accent);
            background: #fffbeb;
        }
        
        .evidence-header {
            display: flex;
            gap: 1rem;
            font-size: 0.85rem;
            color: var(--secondary);
            margin-bottom: 0.5rem;
        }
        
        .evidence-title {
            font-weight: 600;
        }
        
        .raw-details {
            margin-top: 0.75rem;
        }
        
        .raw-details summary {
            cursor: pointer;
            font-size: 0.85rem;
            color: var(--secondary);
        }
        
        .raw-details pre {
            background: #1e293b;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 0.8rem;
            margin-top: 0.5rem;
        }
        
        /* Tags */
        .tag-list {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        
        .tag {
            background: var(--primary);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.8rem;
        }
        
        @media print {
            body { padding: 0; }
            .raw-details { display: none; }
        }
"#;

const THEME_DARK: &str = r#"
        :root {
            --primary: #60a5fa;
            --secondary: #94a3b8;
            --accent: #fbbf24;
            --bg: #0f172a;
            --text: #e2e8f0;
            --border: #334155;
            --card-bg: #1e293b;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: var(--text);
            background: var(--bg);
            padding: 2rem;
        }
        
        .container { max-width: 900px; margin: 0 auto; }
        
        header { border-bottom: 3px solid var(--primary); padding-bottom: 1.5rem; margin-bottom: 2rem; }
        h1 { font-size: 2.5rem; font-weight: 700; color: var(--primary); margin-bottom: 0.5rem; }
        .meta { color: var(--secondary); font-size: 0.9rem; }
        .meta span { margin-right: 1.5rem; }
        
        section { margin-bottom: 2.5rem; }
        h2 { font-size: 1.5rem; font-weight: 600; border-bottom: 2px solid var(--border); padding-bottom: 0.5rem; margin-bottom: 1rem; }
        .content p { margin-bottom: 1rem; }
        
        .technique-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; border-left: 4px solid var(--primary); }
        .technique-id { font-family: monospace; font-size: 1.25rem; font-weight: 700; color: var(--primary); }
        .technique-name { font-size: 1.1rem; margin: 0.25rem 0; }
        
        .timeline-container { position: relative; padding-left: 2rem; }
        .timeline-container::before { content: ''; position: absolute; left: 6px; top: 0; bottom: 0; width: 2px; background: var(--border); }
        .timeline-entry { position: relative; padding-bottom: 1.5rem; }
        .timeline-entry.starred { background: #422006; margin: -0.5rem; padding: 0.5rem; padding-left: 2.5rem; border-radius: 8px; }
        .timeline-dot { position: absolute; left: -1.75rem; top: 0.25rem; width: 12px; height: 12px; background: var(--primary); border-radius: 50%; }
        .timeline-time { font-family: monospace; font-size: 0.8rem; color: var(--secondary); }
        .timeline-title { font-weight: 600; margin: 0.25rem 0; }
        .timeline-type { display: inline-block; font-size: 0.75rem; background: var(--border); padding: 0.125rem 0.5rem; border-radius: 4px; margin-top: 0.5rem; }
        
        .annotation { background: #1e3a5f; border-left: 3px solid var(--primary); padding: 0.5rem 0.75rem; margin: 0.5rem 0; font-style: italic; border-radius: 0 4px 4px 0; }
        
        .evidence-item { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
        .evidence-item.starred { border-color: var(--accent); }
        .evidence-header { display: flex; gap: 1rem; font-size: 0.85rem; color: var(--secondary); margin-bottom: 0.5rem; }
        .evidence-title { font-weight: 600; }
        
        .raw-details pre { background: #000; color: #22d3ee; padding: 1rem; border-radius: 4px; overflow-x: auto; font-size: 0.8rem; }
        
        .tag { background: var(--primary); color: #0f172a; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.8rem; }
"#;

const THEME_MINIMAL: &str = r#"
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: Georgia, serif; line-height: 1.8; color: #333; background: #fff; padding: 2rem; max-width: 700px; margin: 0 auto; }
        header { margin-bottom: 2rem; }
        h1 { font-size: 2rem; font-weight: normal; margin-bottom: 0.5rem; }
        .meta { color: #666; font-size: 0.9rem; }
        section { margin-bottom: 2rem; }
        h2 { font-size: 1.25rem; font-weight: normal; border-bottom: 1px solid #ddd; padding-bottom: 0.25rem; margin-bottom: 1rem; }
        .technique-card { padding: 1rem; border: 1px solid #ddd; }
        .technique-id { font-family: monospace; }
        .timeline-entry { padding: 0.5rem 0; border-bottom: 1px dotted #ddd; }
        .timeline-time { font-family: monospace; font-size: 0.85rem; color: #666; }
        .annotation { padding-left: 1rem; border-left: 2px solid #ddd; font-style: italic; color: #666; }
        .evidence-item { padding: 0.75rem 0; border-bottom: 1px solid #eee; }
        .tag { background: #eee; padding: 0.125rem 0.5rem; margin-right: 0.25rem; font-size: 0.8rem; }
"#;

const THEME_TECHNICAL: &str = r#"
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'SF Mono', Monaco, 'Consolas', monospace; font-size: 14px; line-height: 1.5; color: #24292f; background: #f6f8fa; padding: 1.5rem; }
        .container { max-width: 1000px; margin: 0 auto; background: #fff; border: 1px solid #d0d7de; border-radius: 6px; padding: 1.5rem; }
        header { border-bottom: 1px solid #d0d7de; padding-bottom: 1rem; margin-bottom: 1.5rem; }
        h1 { font-size: 1.5rem; font-weight: 600; }
        .meta { color: #57606a; font-size: 0.85rem; margin-top: 0.5rem; }
        section { margin-bottom: 1.5rem; }
        h2 { font-size: 1.1rem; font-weight: 600; background: #f6f8fa; padding: 0.5rem; margin: 0 -1.5rem; padding-left: 1.5rem; margin-bottom: 1rem; }
        .technique-card { background: #f6f8fa; border: 1px solid #d0d7de; padding: 1rem; border-radius: 4px; }
        .technique-id { color: #0550ae; font-weight: 600; }
        .timeline-entry { padding: 0.75rem; background: #f6f8fa; margin-bottom: 0.5rem; border-radius: 4px; }
        .timeline-entry.starred { background: #fff8c5; border: 1px solid #d4a72c; }
        .timeline-time { color: #57606a; }
        .annotation { background: #ddf4ff; border: 1px solid #54aeff; padding: 0.5rem; border-radius: 4px; margin: 0.5rem 0; }
        .evidence-item { border: 1px solid #d0d7de; padding: 0.75rem; margin-bottom: 0.5rem; border-radius: 4px; }
        .evidence-item.starred { border-color: #d4a72c; background: #fff8c5; }
        .raw-details pre { background: #24292f; color: #c9d1d9; padding: 1rem; border-radius: 4px; overflow-x: auto; }
        .tag { background: #ddf4ff; color: #0550ae; padding: 0.125rem 0.5rem; border-radius: 4px; font-size: 0.8rem; margin-right: 0.25rem; }
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::*;

    #[test]
    fn test_html_export() {
        let mut doc = Document::new("Test Attack Report", "Tester");
        doc.summary.edit("This is a test attack summary.");
        doc.technique.technique_id = Some("T1003.001".to_string());
        doc.technique.technique_name = Some("LSASS Memory".to_string());

        let mut entry = TimelineEntry::from_event(1000, "mimikatz started", "process_exec");
        entry.description = "Attacker launched mimikatz".to_string();
        entry.starred = true;
        doc.timeline.add_entry(entry);

        let html = Exporter::to_html(&doc, &ExportOptions::default());

        assert!(html.contains("Test Attack Report"));
        assert!(html.contains("T1003.001"));
        assert!(html.contains("mimikatz started"));
        assert!(html.contains("⭐"));
    }

    #[test]
    fn test_markdown_export() {
        let mut doc = Document::new("Credential Theft", "Tester");
        doc.summary.edit("Credentials were stolen.");

        let md = Exporter::to_markdown(&doc, &ExportOptions::default());

        assert!(md.contains("# Credential Theft"));
        assert!(md.contains("Credentials were stolen"));
    }
}

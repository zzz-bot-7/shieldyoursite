use maud::{html, Markup, PreEscaped, DOCTYPE};
use shield_scanner_core::{HeaderAssessment, RuleStatus, ScanResult};
use url::Url;

const STYLES: &str = r#"
:root {
  color-scheme: light;
  --ink: #172033;
  --muted: #657085;
  --line: #dfe4ec;
  --paper: #ffffff;
  --canvas: #f4f6f9;
  --pass: #18794e;
  --warn: #9a6700;
  --fail: #c93c37;
  --info: #53657d;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  color: var(--ink);
  background: var(--canvas);
  font: 14px/1.5 ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
main {
  width: min(960px, calc(100% - 32px));
  margin: 32px auto;
  background: var(--paper);
  border: 1px solid var(--line);
  border-radius: 12px;
  overflow: hidden;
}
header { padding: 32px; border-bottom: 1px solid var(--line); }
h1, h2 { margin: 0; }
h1 { font-size: 24px; overflow-wrap: anywhere; }
h2 { margin-bottom: 16px; font-size: 17px; }
.eyebrow { margin-bottom: 6px; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
.hero { display: flex; justify-content: space-between; gap: 24px; align-items: center; }
.grade { font-size: 48px; font-weight: 800; line-height: 1; text-align: right; }
.score { margin-top: 5px; color: var(--muted); text-align: right; }
.meta { margin-top: 16px; color: var(--muted); font-size: 13px; }
section { padding: 26px 32px; border-bottom: 1px solid var(--line); }
.summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
.metric { padding: 14px; border: 1px solid var(--line); border-radius: 8px; }
.metric strong { display: block; font-size: 22px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 12px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .06em; }
.status { font-weight: 700; text-transform: uppercase; font-size: 11px; }
.pass { color: var(--pass); }
.warning { color: var(--warn); }
.fail { color: var(--fail); }
.info { color: var(--info); }
.value { max-width: 430px; overflow-wrap: anywhere; color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
.recommendation { margin-top: 4px; color: var(--muted); }
.resource { display: flex; justify-content: space-between; gap: 20px; padding: 9px 0; border-bottom: 1px solid var(--line); }
.resource:last-child { border-bottom: 0; }
.empty, .note { color: var(--muted); }
.actions { display: flex; justify-content: space-between; align-items: center; gap: 20px; }
button {
  border: 0;
  border-radius: 7px;
  padding: 10px 14px;
  color: white;
  background: var(--ink);
  cursor: pointer;
}
footer { padding: 22px 32px; color: var(--muted); font-size: 12px; }
@media (max-width: 650px) {
  .hero, .actions { align-items: flex-start; flex-direction: column; }
  .grade, .score { text-align: left; }
  .summary { grid-template-columns: repeat(2, 1fr); }
  section, header, footer { padding-left: 20px; padding-right: 20px; }
  table, thead, tbody, tr, th, td { display: block; }
  thead { display: none; }
  td { border-bottom: 0; padding: 5px 0; }
  tr { padding: 14px 0; border-bottom: 1px solid var(--line); }
}
@media print {
  body { background: white; }
  main { width: 100%; margin: 0; border: 0; }
  .print-hide { display: none; }
  section, tr { break-inside: avoid; }
}
"#;

#[must_use]
pub fn render_html(scan: &ScanResult) -> String {
    let target = display_target(scan);
    let document = html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Security report | " (target) }
                style { (PreEscaped(STYLES)) }
            }
            body {
                main {
                    (report_header(scan, &target))
                    (summary_section(scan))
                    (findings_section(scan))
                    (environment_section(scan))
                    (resources_section(scan))
                    (report_actions())
                    (report_footer())
                }
            }
        }
    };
    document.into_string()
}

#[must_use]
pub fn default_report_filename(scan: &ScanResult) -> String {
    let host = Url::parse(&scan.final_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "shield".to_owned());
    let safe_host: String = host
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect();
    format!("{safe_host}-security-report.html")
}

fn display_target(scan: &ScanResult) -> String {
    Url::parse(&scan.final_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| scan.final_url.clone())
}

fn report_header(scan: &ScanResult, target: &str) -> Markup {
    html! {
        header {
            div class="hero" {
                div {
                    div class="eyebrow" { "Shield security report" }
                    h1 { (target) }
                    div class="meta" {
                        (scan.final_url)
                        " · "
                        (scan.scanned_at.format("%Y-%m-%d %H:%M UTC"))
                    }
                }
                div {
                    div class="grade" { (scan.grade) }
                    div class="score" { (scan.score) "/100" }
                }
            }
        }
    }
}

fn summary_section(scan: &ScanResult) -> Markup {
    html! {
        section {
            h2 { "Summary" }
            div class="summary" {
                (metric("Pass", scan.summary.passed, "pass"))
                (metric("Warning", scan.summary.warnings, "warning"))
                (metric("Fail", scan.summary.failed, "fail"))
                (metric("Info", scan.summary.informational, "info"))
            }
        }
    }
}

fn findings_section(scan: &ScanResult) -> Markup {
    html! {
        section {
            h2 { "Header findings" }
            table {
                thead {
                    tr {
                        th { "Status" }
                        th { "Control" }
                        th { "Finding" }
                        th { "Value" }
                    }
                }
                tbody {
                    @for assessment in &scan.headers {
                        (finding_row(assessment))
                    }
                }
            }
        }
    }
}

fn environment_section(scan: &ScanResult) -> Markup {
    html! {
        section {
            h2 { "Environment" }
            table {
                tbody {
                    tr {
                        th { "Platform" }
                        td { (scan.platform.platform) }
                        td colspan="2" class="value" {
                            @if scan.platform.evidence.is_empty() {
                                "No platform evidence"
                            } @else {
                                (scan.platform.evidence.join(", "))
                                " · "
                                (scan.platform.confidence)
                                "%"
                            }
                        }
                    }
                    tr {
                        th { "HTTP" }
                        td { (scan.response.status) }
                        td colspan="2" class="value" {
                            (scan.response.content_type.as_deref().unwrap_or("unknown"))
                        }
                    }
                    tr {
                        th { "Body" }
                        td { (scan.response.body_bytes) " bytes" }
                        td colspan="2" class="value" {
                            @if scan.response.body_truncated {
                                "Truncated at safety limit"
                            } @else {
                                "Complete within safety limit"
                            }
                        }
                    }
                }
            }
        }
    }
}

fn resources_section(scan: &ScanResult) -> Markup {
    html! {
        section {
            h2 { "Known third-party resources" }
            @if scan.resources.is_empty() {
                p class="empty" { "None detected in the fetched HTML." }
            } @else {
                @for resource in &scan.resources {
                    div class="resource" {
                        div {
                            strong { (resource.name) }
                            div class="note" { (resource.category) }
                        }
                        div class="value" { (resource.hosts.join(", ")) }
                    }
                }
            }
        }
    }
}

fn report_actions() -> Markup {
    html! {
        section class="print-hide" {
            div class="actions" {
                div class="note" { "Use the browser print dialog to save PDF." }
                button type="button" onclick="window.print()" { "Print / PDF" }
            }
        }
    }
}

fn report_footer() -> Markup {
    html! {
        footer {
            "This report evaluates HTTP response headers using the documented Shield policy. "
            "It is not a penetration test or compliance certification."
        }
    }
}

fn metric(label: &str, value: u16, class: &str) -> Markup {
    html! {
        div class="metric" {
            strong class=(class) { (value) }
            span { (label) }
        }
    }
}

fn finding_row(assessment: &HeaderAssessment) -> Markup {
    html! {
        tr {
            td class=(format!("status {}", status_class(assessment.status))) {
                (assessment.status)
            }
            td {
                strong { (assessment.header) }
                @if assessment.weight > 0 {
                    div class="note" { (assessment.earned) "/" (assessment.weight) " points" }
                } @else {
                    div class="note" { "Contextual" }
                }
            }
            td {
                (assessment.summary)
                @if let Some(recommendation) = &assessment.recommendation {
                    div class="recommendation" { (recommendation) }
                }
            }
            td class="value" {
                (assessment.value.as_deref().unwrap_or("Not present"))
            }
        }
    }
}

const fn status_class(status: RuleStatus) -> &'static str {
    match status {
        RuleStatus::Pass => "pass",
        RuleStatus::Warning => "warning",
        RuleStatus::Fail => "fail",
        RuleStatus::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use shield_scanner_core::{
        Grade, HeaderAssessment, Platform, PlatformDetection, ResponseMetadata, RuleStatus,
        ScanResult, ScanSummary,
    };

    use super::*;

    fn sample_scan() -> ScanResult {
        ScanResult {
            schema_version: 1,
            requested_url: "https://example.com/".to_owned(),
            final_url: "https://example.com/".to_owned(),
            scanned_at: Utc::now(),
            duration_ms: 10,
            grade: Grade::B,
            score: 82,
            summary: ScanSummary {
                passed: 1,
                warnings: 0,
                failed: 0,
                informational: 0,
            },
            headers: vec![HeaderAssessment {
                id: "content-type-options".to_owned(),
                header: "X-Content-Type-Options".to_owned(),
                status: RuleStatus::Pass,
                value: Some("nosniff".to_owned()),
                summary: "MIME sniffing is disabled.".to_owned(),
                recommendation: None,
                weight: 15,
                earned: 15.0,
            }],
            platform: PlatformDetection {
                platform: Platform::Unknown,
                confidence: 0,
                evidence: Vec::new(),
            },
            resources: Vec::new(),
            response: ResponseMetadata {
                status: 200,
                content_type: Some("text/html".to_owned()),
                body_bytes: 100,
                body_truncated: false,
            },
        }
    }

    #[test]
    fn report_contains_scan_result_and_print_action() {
        let html = render_html(&sample_scan());
        assert!(html.contains("example.com"));
        assert!(html.contains("82/100"));
        assert!(html.contains("Print / PDF"));
        assert!(html.contains("X-Content-Type-Options"));
    }

    #[test]
    fn report_escapes_scan_values() {
        let mut scan = sample_scan();
        scan.headers[0].value = Some("<script>alert(1)</script>".to_owned());
        let html = render_html(&scan);
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn filename_uses_final_host() {
        assert_eq!(
            default_report_filename(&sample_scan()),
            "example.com-security-report.html"
        );
    }
}

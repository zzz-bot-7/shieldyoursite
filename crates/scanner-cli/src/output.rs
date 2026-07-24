use std::fmt::{self, Write as _};
use std::io::{self, Write};
use std::path::Path;

use shield_scanner_core::{RuleStatus, ScanResult};

use crate::commands::CliError;

pub(crate) fn scan(scan: &ScanResult, json: bool, quiet: bool) -> Result<(), CliError> {
    if quiet {
        return Ok(());
    }

    let stdout = io::stdout();
    let mut output = stdout.lock();
    if json {
        serde_json::to_writer(&mut output, scan).map_err(|_| CliError::Output)?;
        writeln!(output).map_err(|_| CliError::Output)
    } else {
        output
            .write_all(render_terminal(scan).as_bytes())
            .map_err(|_| CliError::Output)
    }
}

pub(crate) fn report(path: &Path) -> Result<(), CliError> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{}", path.display()).map_err(|_| CliError::Output)
}

fn render_terminal(scan: &ScanResult) -> String {
    let mut output = String::new();
    write_line(
        &mut output,
        format_args!("{} {}/100", scan.grade, scan.score),
    );
    write_line(&mut output, format_args!("{}", scan.final_url));
    write_line(
        &mut output,
        format_args!("{}", scan.scanned_at.format("%Y-%m-%d %H:%M UTC")),
    );
    output.push('\n');

    write_summary(&mut output, scan);
    write_findings(&mut output, scan);
    write_environment(&mut output, scan);
    write_resources(&mut output, scan);
    write_line(
        &mut output,
        format_args!("Headers only. Not pentest/compliance."),
    );
    write_line(&mut output, format_args!("Report: shield report"));
    output
}

fn write_summary(output: &mut String, scan: &ScanResult) {
    write_line(output, format_args!("SUMMARY"));
    write_line(
        output,
        format_args!(
            "Pass {}  Warn {}  Fail {}  Info {}",
            scan.summary.passed,
            scan.summary.warnings,
            scan.summary.failed,
            scan.summary.informational
        ),
    );
    output.push('\n');
}

fn write_findings(output: &mut String, scan: &ScanResult) {
    write_line(output, format_args!("HEADERS"));
    write_line(output, format_args!("STATUS PTS HEADER | FINDING | VALUE"));
    for finding in &scan.headers {
        let points = if finding.weight == 0 {
            "-".to_owned()
        } else {
            format!("{}/{}", finding.earned, finding.weight)
        };
        write_line(
            output,
            format_args!(
                "{:<4} {points:>5} {} | {} | {}",
                status_label(finding.status),
                finding.header,
                finding.summary,
                finding.value.as_deref().unwrap_or("-")
            ),
        );
        if let Some(recommendation) = &finding.recommendation {
            write_line(output, format_args!("  Fix: {recommendation}"));
        }
    }
    output.push('\n');
}

fn write_environment(output: &mut String, scan: &ScanResult) {
    write_line(output, format_args!("ENVIRONMENT"));
    write_line(
        output,
        format_args!(
            "Platform: {} {}% | {}",
            scan.platform.platform,
            scan.platform.confidence,
            if scan.platform.evidence.is_empty() {
                "none".to_owned()
            } else {
                scan.platform.evidence.join(", ")
            }
        ),
    );
    write_line(
        output,
        format_args!(
            "HTTP: {} {}",
            scan.response.status,
            scan.response.content_type.as_deref().unwrap_or("unknown")
        ),
    );
    write_line(
        output,
        format_args!(
            "Body: {} bytes {}",
            scan.response.body_bytes,
            if scan.response.body_truncated {
                "truncated"
            } else {
                "complete"
            }
        ),
    );
    output.push('\n');
}

fn write_resources(output: &mut String, scan: &ScanResult) {
    write_line(output, format_args!("RESOURCES"));
    if scan.resources.is_empty() {
        write_line(output, format_args!("None"));
    } else {
        for resource in &scan.resources {
            write_line(
                output,
                format_args!(
                    "{} | {} | {}",
                    resource.category,
                    resource.name,
                    resource.hosts.join(", ")
                ),
            );
        }
    }
    output.push('\n');
}

fn write_line(output: &mut String, arguments: fmt::Arguments<'_>) {
    output
        .write_fmt(arguments)
        .expect("writing to a String cannot fail");
    output.push('\n');
}

const fn status_label(status: RuleStatus) -> &'static str {
    match status {
        RuleStatus::Pass => "PASS",
        RuleStatus::Warning => "WARN",
        RuleStatus::Fail => "FAIL",
        RuleStatus::Info => "INFO",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn sample_scan() -> ScanResult {
        serde_json::from_value(json!({
            "schema_version": 1,
            "requested_url": "https://example.com/",
            "final_url": "https://example.com/",
            "scanned_at": "2026-07-24T12:00:00Z",
            "duration_ms": 10,
            "grade": "B",
            "score": 82,
            "summary": {
                "passed": 1,
                "warnings": 2,
                "failed": 3,
                "informational": 4
            },
            "headers": [{
                "id": "hsts",
                "header": "Strict-Transport-Security",
                "status": "fail",
                "value": "max-age=0",
                "summary": "HSTS is disabled.",
                "recommendation": "Use a positive max-age.",
                "weight": 20,
                "earned": 0
            }],
            "platform": {
                "platform": "cloudflare",
                "confidence": 70,
                "evidence": ["cf-ray"]
            },
            "resources": [{
                "category": "payment",
                "name": "Stripe",
                "hosts": ["js.stripe.com"]
            }],
            "response": {
                "status": 200,
                "content_type": "text/html",
                "body_bytes": 100,
                "body_truncated": false
            }
        }))
        .expect("sample scan should deserialize")
    }

    #[test]
    fn terminal_report_is_result_first_and_complete() {
        assert_eq!(
            render_terminal(&sample_scan()),
            concat!(
                "B 82/100\n",
                "https://example.com/\n",
                "2026-07-24 12:00 UTC\n",
                "\n",
                "SUMMARY\n",
                "Pass 1  Warn 2  Fail 3  Info 4\n",
                "\n",
                "HEADERS\n",
                "STATUS PTS HEADER | FINDING | VALUE\n",
                "FAIL  0/20 Strict-Transport-Security | HSTS is disabled. | max-age=0\n",
                "  Fix: Use a positive max-age.\n",
                "\n",
                "ENVIRONMENT\n",
                "Platform: Cloudflare 70% | cf-ray\n",
                "HTTP: 200 text/html\n",
                "Body: 100 bytes complete\n",
                "\n",
                "RESOURCES\n",
                "Payment | Stripe | js.stripe.com\n",
                "\n",
                "Headers only. Not pentest/compliance.\n",
                "Report: shield report\n",
            )
        );
    }
}

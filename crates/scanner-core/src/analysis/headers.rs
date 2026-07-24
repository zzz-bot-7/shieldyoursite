use reqwest::header::HeaderMap;
use url::{Host, Url};

use crate::model::{HeaderAssessment, RuleStatus};

pub(crate) fn evaluate_headers(headers: &HeaderMap, final_url: &Url) -> Vec<HeaderAssessment> {
    vec![
        evaluate_hsts(headers, final_url),
        evaluate_csp(headers),
        evaluate_frame_protection(headers),
        evaluate_content_type_options(headers),
        evaluate_referrer_policy(headers),
        evaluate_permissions_policy(headers),
        evaluate_xss_protection(headers),
        contextual_header(
            headers,
            "cache-control",
            "Cache-Control",
            "Caching requirements depend on the response.",
        ),
        contextual_header(
            headers,
            "cross-origin-embedder-policy",
            "Cross-Origin-Embedder-Policy",
            "COEP is required only for applications using cross-origin isolation.",
        ),
        contextual_header(
            headers,
            "cross-origin-opener-policy",
            "Cross-Origin-Opener-Policy",
            "COOP requirements depend on window and isolation behavior.",
        ),
        contextual_header(
            headers,
            "cross-origin-resource-policy",
            "Cross-Origin-Resource-Policy",
            "CORP requirements depend on how this resource is embedded.",
        ),
        contextual_header(
            headers,
            "x-permitted-cross-domain-policies",
            "X-Permitted-Cross-Domain-Policies",
            "This legacy plugin policy is defense in depth.",
        ),
    ]
}

fn evaluate_hsts(headers: &HeaderMap, final_url: &Url) -> HeaderAssessment {
    const WEIGHT: u8 = 20;
    let value = header_value(headers, "strict-transport-security");

    if final_url.scheme() != "https" {
        return assessment(
            "hsts",
            "Strict-Transport-Security",
            RuleStatus::Fail,
            value,
            "The final response is not HTTPS.",
            Some("Serve the site over HTTPS before enabling HSTS."),
            WEIGHT,
        );
    }

    if matches!(final_url.host(), Some(Host::Ipv4(_) | Host::Ipv6(_))) {
        return assessment(
            "hsts",
            "Strict-Transport-Security",
            RuleStatus::Info,
            value,
            "HSTS does not apply to IP-literal hosts.",
            None,
            0,
        );
    }

    let Some(raw_value) = value else {
        return assessment(
            "hsts",
            "Strict-Transport-Security",
            RuleStatus::Fail,
            None,
            "HSTS is missing.",
            Some("Add Strict-Transport-Security with a tested positive max-age."),
            WEIGHT,
        );
    };

    let max_age = raw_value
        .split([';', ','])
        .map(str::trim)
        .find_map(|directive| {
            let (name, value) = directive.split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("max-age")
                .then(|| value.trim().trim_matches('"').parse::<u64>().ok())?
        });

    match max_age {
        Some(0) => assessment(
            "hsts",
            "Strict-Transport-Security",
            RuleStatus::Fail,
            Some(raw_value),
            "HSTS is disabled by max-age=0.",
            Some("Use a positive max-age after validating HTTPS on the domain."),
            WEIGHT,
        ),
        Some(seconds) if seconds < 31_536_000 => assessment(
            "hsts",
            "Strict-Transport-Security",
            RuleStatus::Warning,
            Some(raw_value),
            "HSTS is active for less than one year.",
            Some("Increase max-age after validating the deployment."),
            WEIGHT,
        ),
        Some(_) => assessment(
            "hsts",
            "Strict-Transport-Security",
            RuleStatus::Pass,
            Some(raw_value),
            "HSTS is active.",
            None,
            WEIGHT,
        ),
        None => assessment(
            "hsts",
            "Strict-Transport-Security",
            RuleStatus::Fail,
            Some(raw_value),
            "HSTS has no valid max-age.",
            Some("Set max-age to a nonnegative integer."),
            WEIGHT,
        ),
    }
}

fn evaluate_csp(headers: &HeaderMap) -> HeaderAssessment {
    const WEIGHT: u8 = 25;
    let value = header_value(headers, "content-security-policy");
    let Some(raw_value) = value else {
        let report_only = header_value(headers, "content-security-policy-report-only");
        return if report_only.is_some() {
            assessment(
                "csp",
                "Content-Security-Policy",
                RuleStatus::Warning,
                report_only,
                "CSP is report-only.",
                Some("Deploy a tested enforcing Content-Security-Policy."),
                WEIGHT,
            )
        } else {
            assessment(
                "csp",
                "Content-Security-Policy",
                RuleStatus::Fail,
                None,
                "CSP is missing.",
                Some("Deploy a tested enforcing Content-Security-Policy."),
                WEIGHT,
            )
        };
    };

    let lower = raw_value.to_ascii_lowercase();
    let script_policy = csp_directive(&lower, "script-src-elem")
        .or_else(|| csp_directive(&lower, "script-src"))
        .or_else(|| csp_directive(&lower, "default-src"));
    if script_policy.is_none() {
        return assessment(
            "csp",
            "Content-Security-Policy",
            RuleStatus::Warning,
            Some(raw_value),
            "CSP does not control script sources.",
            Some("Add script-src or default-src after testing the application."),
            WEIGHT,
        );
    }

    let script_policy = script_policy.unwrap_or_default();
    let attribute_policy = csp_directive(&lower, "script-src-attr");
    if script_policy_is_high_risk(script_policy)
        || attribute_policy.is_some_and(|policy| {
            script_policy_is_high_risk(policy)
                || policy
                    .split_whitespace()
                    .any(|token| token == "'unsafe-inline'")
        })
    {
        return assessment(
            "csp",
            "Content-Security-Policy",
            RuleStatus::Warning,
            Some(raw_value),
            "CSP permits a high-risk script source.",
            Some("Remove broad script sources after testing nonces or hashes."),
            WEIGHT,
        );
    }

    assessment(
        "csp",
        "Content-Security-Policy",
        RuleStatus::Pass,
        Some(raw_value),
        "CSP controls script sources.",
        None,
        WEIGHT,
    )
}

fn script_policy_is_high_risk(policy: &str) -> bool {
    let tokens: Vec<&str> = policy.split_whitespace().collect();
    let has_broad_source = tokens.iter().any(|token| {
        matches!(
            *token,
            "*" | "http:" | "https:" | "data:" | "blob:" | "filesystem:"
        ) || token.starts_with("*.")
            || token.contains("://*.")
    });
    let has_unsafe_eval = tokens
        .iter()
        .any(|token| matches!(*token, "'unsafe-eval'" | "'wasm-unsafe-eval'"));
    let has_unsafe_inline = tokens.contains(&"'unsafe-inline'");
    let has_strong_inline_control = tokens.iter().any(|token| {
        token.starts_with("'nonce-")
            || token.starts_with("'sha256-")
            || token.starts_with("'sha384-")
            || token.starts_with("'sha512-")
            || *token == "'strict-dynamic'"
    });

    has_broad_source || has_unsafe_eval || (has_unsafe_inline && !has_strong_inline_control)
}

fn evaluate_frame_protection(headers: &HeaderMap) -> HeaderAssessment {
    const WEIGHT: u8 = 15;
    let csp = header_value(headers, "content-security-policy");
    if let Some(csp_value) = csp.as_deref() {
        if let Some(frame_ancestors) =
            csp_directive(&csp_value.to_ascii_lowercase(), "frame-ancestors")
        {
            let broad_source = frame_ancestors.split_whitespace().any(|source| {
                matches!(
                    source,
                    "*" | "http:" | "https:" | "data:" | "blob:" | "filesystem:"
                ) || source.starts_with("*.")
                    || source.contains("://*.")
            });
            return assessment(
                "frame-protection",
                "Frame protection",
                if broad_source {
                    RuleStatus::Warning
                } else {
                    RuleStatus::Pass
                },
                Some(format!("frame-ancestors {frame_ancestors}")),
                if broad_source {
                    "CSP permits framing from a broad source."
                } else {
                    "CSP restricts framing."
                },
                broad_source
                    .then_some("Restrict frame-ancestors to 'none', 'self', or explicit origins."),
                WEIGHT,
            );
        }
    }

    let value = header_value(headers, "x-frame-options");
    match value.as_deref().map(str::trim) {
        Some(value)
            if value.eq_ignore_ascii_case("deny") || value.eq_ignore_ascii_case("sameorigin") =>
        {
            assessment(
                "frame-protection",
                "Frame protection",
                RuleStatus::Pass,
                Some(value.to_owned()),
                "X-Frame-Options restricts framing.",
                None,
                WEIGHT,
            )
        }
        Some(_) => assessment(
            "frame-protection",
            "Frame protection",
            RuleStatus::Fail,
            value,
            "Frame protection is invalid or ineffective.",
            Some("Use CSP frame-ancestors, with X-Frame-Options for legacy coverage."),
            WEIGHT,
        ),
        None => assessment(
            "frame-protection",
            "Frame protection",
            RuleStatus::Fail,
            None,
            "Frame protection is missing.",
            Some("Use CSP frame-ancestors, with X-Frame-Options for legacy coverage."),
            WEIGHT,
        ),
    }
}

fn evaluate_content_type_options(headers: &HeaderMap) -> HeaderAssessment {
    const WEIGHT: u8 = 15;
    let value = header_value(headers, "x-content-type-options");
    match value.as_deref().map(str::trim) {
        Some(value) if value.eq_ignore_ascii_case("nosniff") => assessment(
            "content-type-options",
            "X-Content-Type-Options",
            RuleStatus::Pass,
            Some(value.to_owned()),
            "MIME sniffing is disabled.",
            None,
            WEIGHT,
        ),
        Some(_) => assessment(
            "content-type-options",
            "X-Content-Type-Options",
            RuleStatus::Fail,
            value,
            "X-Content-Type-Options is invalid.",
            Some("Set X-Content-Type-Options to nosniff."),
            WEIGHT,
        ),
        None => assessment(
            "content-type-options",
            "X-Content-Type-Options",
            RuleStatus::Fail,
            None,
            "X-Content-Type-Options is missing.",
            Some("Set X-Content-Type-Options to nosniff."),
            WEIGHT,
        ),
    }
}

fn evaluate_referrer_policy(headers: &HeaderMap) -> HeaderAssessment {
    const WEIGHT: u8 = 10;
    let value = header_value(headers, "referrer-policy");
    let Some(raw_value) = value else {
        return assessment(
            "referrer-policy",
            "Referrer-Policy",
            RuleStatus::Fail,
            None,
            "Referrer-Policy is missing.",
            Some("Set a policy appropriate for the application's privacy needs."),
            WEIGHT,
        );
    };

    let policy = raw_value
        .split(',')
        .map(str::trim)
        .rfind(|token| !token.is_empty())
        .unwrap_or_default()
        .to_ascii_lowercase();

    let (status, summary, recommendation) = match policy.as_str() {
        "no-referrer" | "same-origin" | "strict-origin" | "strict-origin-when-cross-origin" => {
            (RuleStatus::Pass, "Referrer disclosure is restricted.", None)
        }
        "origin" | "origin-when-cross-origin" | "no-referrer-when-downgrade" => (
            RuleStatus::Warning,
            "The policy can disclose more referrer information.",
            Some("Consider strict-origin-when-cross-origin or a stricter policy."),
        ),
        "unsafe-url" => (
            RuleStatus::Fail,
            "The policy sends full referrer URLs.",
            Some("Replace unsafe-url with a privacy-preserving policy."),
        ),
        _ => (
            RuleStatus::Fail,
            "Referrer-Policy is invalid.",
            Some("Use a policy token defined by the Referrer Policy specification."),
        ),
    };

    assessment(
        "referrer-policy",
        "Referrer-Policy",
        status,
        Some(raw_value),
        summary,
        recommendation,
        WEIGHT,
    )
}

fn evaluate_permissions_policy(headers: &HeaderMap) -> HeaderAssessment {
    const WEIGHT: u8 = 10;
    let value = header_value(headers, "permissions-policy");
    let Some(raw_value) = value else {
        return assessment(
            "permissions-policy",
            "Permissions-Policy",
            RuleStatus::Warning,
            None,
            "Permissions-Policy is missing.",
            Some("Restrict browser features the application does not use."),
            WEIGHT,
        );
    };

    let directives: Vec<&str> = raw_value.split(',').collect();
    let valid = !directives.is_empty()
        && directives.iter().all(|directive| {
            let Some((feature, allowlist)) = directive.trim().split_once('=') else {
                return false;
            };
            !feature.trim().is_empty()
                && feature
                    .trim()
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
                && allowlist.trim().len() >= 2
                && allowlist.trim().starts_with('(')
                && allowlist.trim().ends_with(')')
        });

    if !valid {
        return assessment(
            "permissions-policy",
            "Permissions-Policy",
            RuleStatus::Fail,
            Some(raw_value),
            "Permissions-Policy has invalid syntax.",
            Some("Use feature=(allowlist) directives separated by commas."),
            WEIGHT,
        );
    }

    let has_unrestricted_feature = directives.iter().any(|directive| {
        let allowlist = directive
            .trim()
            .split_once('=')
            .map(|(_, allowlist)| allowlist.trim())
            .unwrap_or_default();
        allowlist[1..allowlist.len() - 1]
            .split_whitespace()
            .any(|source| source == "*")
    });
    if has_unrestricted_feature {
        assessment(
            "permissions-policy",
            "Permissions-Policy",
            RuleStatus::Warning,
            Some(raw_value),
            "Permissions-Policy leaves at least one feature unrestricted.",
            Some("Replace wildcard allowlists with empty, self, or explicit-origin allowlists."),
            WEIGHT,
        )
    } else {
        assessment(
            "permissions-policy",
            "Permissions-Policy",
            RuleStatus::Pass,
            Some(raw_value),
            "Permissions-Policy restricts declared browser features.",
            None,
            WEIGHT,
        )
    }
}

fn evaluate_xss_protection(headers: &HeaderMap) -> HeaderAssessment {
    const WEIGHT: u8 = 5;
    let value = header_value(headers, "x-xss-protection");
    match value.as_deref().map(str::trim) {
        None => assessment(
            "xss-protection",
            "X-XSS-Protection",
            RuleStatus::Pass,
            None,
            "The deprecated header is absent.",
            None,
            WEIGHT,
        ),
        Some("0") => assessment(
            "xss-protection",
            "X-XSS-Protection",
            RuleStatus::Pass,
            value,
            "The deprecated browser filter is disabled.",
            None,
            WEIGHT,
        ),
        Some(_) => assessment(
            "xss-protection",
            "X-XSS-Protection",
            RuleStatus::Warning,
            value,
            "The deprecated browser filter is enabled.",
            Some("Remove the header or set it to 0; use CSP for XSS mitigation."),
            WEIGHT,
        ),
    }
}

fn contextual_header(
    headers: &HeaderMap,
    name: &str,
    display_name: &str,
    missing_summary: &str,
) -> HeaderAssessment {
    let value = header_value(headers, name);
    let summary = if value.is_some() {
        format!("{display_name} is present; validate it for this response.")
    } else {
        missing_summary.to_owned()
    };
    assessment(
        name,
        display_name,
        RuleStatus::Info,
        value,
        &summary,
        None,
        0,
    )
}

fn assessment(
    id: &str,
    header: &str,
    status: RuleStatus,
    value: Option<String>,
    summary: &str,
    recommendation: Option<&str>,
    weight: u8,
) -> HeaderAssessment {
    let earned = match status {
        RuleStatus::Pass => weight,
        RuleStatus::Warning => weight / 2,
        RuleStatus::Fail | RuleStatus::Info => 0,
    };

    HeaderAssessment {
        id: id.to_owned(),
        header: header.to_owned(),
        status,
        value,
        summary: summary.to_owned(),
        recommendation: recommendation.map(str::to_owned),
        weight,
        earned,
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    if !headers.contains_key(name) {
        return None;
    }

    let values: Vec<&str> = headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    Some(if values.is_empty() {
        "<invalid bytes>".to_owned()
    } else {
        values.join(", ")
    })
}

fn csp_directive<'a>(policy: &'a str, name: &str) -> Option<&'a str> {
    policy.split([';', ',']).find_map(|directive| {
        let directive = directive.trim();
        let (directive_name, sources) = directive
            .split_once(char::is_whitespace)
            .unwrap_or((directive, ""));
        directive_name
            .eq_ignore_ascii_case(name)
            .then_some(sources.trim())
    })
}

#[cfg(test)]
mod tests {
    use reqwest::header::{HeaderName, HeaderValue};

    use super::*;

    fn https_url() -> Url {
        Url::parse("https://example.com").expect("test URL must parse")
    }

    fn insert(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }

    fn status<'a>(assessments: &'a [HeaderAssessment], id: &str) -> &'a HeaderAssessment {
        assessments
            .iter()
            .find(|assessment| assessment.id == id)
            .expect("assessment must exist")
    }

    #[test]
    fn secure_baseline_scores_one_hundred() {
        let mut headers = HeaderMap::new();
        insert(
            &mut headers,
            "strict-transport-security",
            "max-age=31536000",
        );
        insert(
            &mut headers,
            "content-security-policy",
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
        );
        insert(&mut headers, "x-content-type-options", "nosniff");
        insert(
            &mut headers,
            "referrer-policy",
            "strict-origin-when-cross-origin",
        );
        insert(&mut headers, "permissions-policy", "geolocation=()");

        let assessments = evaluate_headers(&headers, &https_url());
        let score: u8 = assessments.iter().map(|item| item.earned).sum();
        assert_eq!(score, 100);
    }

    #[test]
    fn hsts_zero_fails() {
        let mut headers = HeaderMap::new();
        insert(&mut headers, "strict-transport-security", "max-age=0");
        let assessments = evaluate_headers(&headers, &https_url());
        assert_eq!(status(&assessments, "hsts").status, RuleStatus::Fail);
    }

    #[test]
    fn hsts_is_not_applicable_to_ip_literals() {
        let mut headers = HeaderMap::new();
        insert(
            &mut headers,
            "strict-transport-security",
            "max-age=31536000",
        );
        let url = Url::parse("https://192.0.2.1").expect("test URL must parse");
        let assessments = evaluate_headers(&headers, &url);
        let hsts = status(&assessments, "hsts");

        assert_eq!(hsts.status, RuleStatus::Info);
        assert_eq!(hsts.weight, 0);
    }

    #[test]
    fn plain_http_ip_literal_still_fails_transport_check() {
        let headers = HeaderMap::new();
        let url = Url::parse("http://192.0.2.1").expect("test URL must parse");
        let assessments = evaluate_headers(&headers, &url);

        assert_eq!(status(&assessments, "hsts").status, RuleStatus::Fail);
    }

    #[test]
    fn header_presence_without_valid_value_fails() {
        let mut headers = HeaderMap::new();
        insert(&mut headers, "x-content-type-options", "invalid");
        let assessments = evaluate_headers(&headers, &https_url());
        assert_eq!(
            status(&assessments, "content-type-options").status,
            RuleStatus::Fail
        );
    }

    #[test]
    fn report_only_csp_warns() {
        let mut headers = HeaderMap::new();
        insert(
            &mut headers,
            "content-security-policy-report-only",
            "default-src 'self'",
        );
        let assessments = evaluate_headers(&headers, &https_url());
        assert_eq!(status(&assessments, "csp").status, RuleStatus::Warning);
    }

    #[test]
    fn broad_script_sources_warn() {
        for policy in [
            "script-src https:",
            "script-src data:",
            "script-src https://*.example.com",
            "script-src 'self'; script-src-elem blob:",
            "script-src 'nonce-safe'; script-src-attr 'unsafe-inline' 'nonce-ignored'",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "content-security-policy",
                HeaderValue::from_str(policy).expect("test policy must be a header value"),
            );

            let assessments = evaluate_headers(&headers, &https_url());
            assert_eq!(
                status(&assessments, "csp").status,
                RuleStatus::Warning,
                "{policy} should warn"
            );
        }
    }

    #[test]
    fn broad_frame_ancestors_warns() {
        let mut headers = HeaderMap::new();
        insert(
            &mut headers,
            "content-security-policy",
            "default-src 'self'; frame-ancestors https:",
        );
        insert(&mut headers, "x-frame-options", "deny");

        let assessments = evaluate_headers(&headers, &https_url());
        assert_eq!(
            status(&assessments, "frame-protection").status,
            RuleStatus::Warning
        );
    }

    #[test]
    fn explicit_frame_ancestor_passes() {
        let mut headers = HeaderMap::new();
        insert(
            &mut headers,
            "content-security-policy",
            "default-src 'self'; frame-ancestors https://portal.example.com",
        );

        let assessments = evaluate_headers(&headers, &https_url());
        assert_eq!(
            status(&assessments, "frame-protection").status,
            RuleStatus::Pass
        );
    }

    #[test]
    fn any_unrestricted_permissions_feature_warns() {
        let mut headers = HeaderMap::new();
        insert(
            &mut headers,
            "permissions-policy",
            "geolocation=(), camera=(*)",
        );

        let assessments = evaluate_headers(&headers, &https_url());
        assert_eq!(
            status(&assessments, "permissions-policy").status,
            RuleStatus::Warning
        );
    }

    #[test]
    fn malformed_permissions_allowlist_fails_without_panicking() {
        let mut headers = HeaderMap::new();
        insert(&mut headers, "permissions-policy", "geolocation=(");

        let assessments = evaluate_headers(&headers, &https_url());
        assert_eq!(
            status(&assessments, "permissions-policy").status,
            RuleStatus::Fail
        );
    }

    #[test]
    fn deprecated_xss_header_warns_when_enabled() {
        let mut headers = HeaderMap::new();
        insert(&mut headers, "x-xss-protection", "1; mode=block");
        let assessments = evaluate_headers(&headers, &https_url());
        assert_eq!(
            status(&assessments, "xss-protection").status,
            RuleStatus::Warning
        );
    }
}

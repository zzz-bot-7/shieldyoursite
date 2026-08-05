use std::time::Instant;

use chrono::Utc;

use crate::analysis::{detect_platform, detect_resources, evaluate_headers};
use crate::model::{Grade, ResponseMetadata, ScanResult, ScanSummary};
use crate::network::{
    build_client, fetch_page, normalize_target, ScanError, DEFAULT_MAX_BODY_BYTES,
};

#[derive(Debug, Clone)]
pub struct Scanner {
    client: reqwest::Client,
    max_body_bytes: usize,
}

impl Scanner {
    /// Creates a scanner with the default network and resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`ScanError::Client`] when the HTTP client cannot be built.
    pub fn new() -> Result<Self, ScanError> {
        Ok(Self {
            client: build_client()?,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        })
    }

    /// Scans one public HTTP or HTTPS target.
    ///
    /// # Errors
    ///
    /// Returns a [`ScanError`] when validation, DNS resolution, redirects, or
    /// the HTTP request fail.
    pub async fn scan(&self, target: &str) -> Result<ScanResult, ScanError> {
        let requested_url = normalize_target(target)?;
        let started = Instant::now();
        let page = fetch_page(&self.client, requested_url.clone(), self.max_body_bytes).await?;

        let headers = evaluate_headers(&page.headers, &page.final_url);
        let score = normalized_score(&headers);
        let summary = ScanSummary::from_assessments(&headers);
        let platform = detect_platform(&page.headers);
        let resources = detect_resources(&page.body, &page.final_url);

        Ok(ScanResult {
            schema_version: 2,
            requested_url: requested_url.to_string(),
            final_url: page.final_url.to_string(),
            scanned_at: Utc::now(),
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            grade: Grade::from_score(score),
            score,
            summary,
            headers,
            platform,
            resources,
            response: ResponseMetadata {
                status: page.status,
                content_type: page.content_type,
                body_bytes: page.body_bytes,
                body_truncated: page.body_truncated,
            },
        })
    }
}

fn normalized_score(headers: &[crate::model::HeaderAssessment]) -> u8 {
    let earned_half_points = headers
        .iter()
        .map(|assessment| assessment.status.earned_half_points(assessment.weight))
        .sum::<u16>();
    let available_half_points = headers
        .iter()
        .map(|assessment| u16::from(assessment.weight) * 2)
        .sum::<u16>();

    if available_half_points == 0 {
        return 0;
    }

    u8::try_from(((earned_half_points * 100) + (available_half_points / 2)) / available_half_points)
        .unwrap_or(100)
        .min(100)
}

#[cfg(test)]
mod tests {
    use crate::model::{HeaderAssessment, RuleStatus};

    use super::normalized_score;

    fn assessment(status: RuleStatus, weight: u8, earned: f32) -> HeaderAssessment {
        HeaderAssessment {
            id: String::new(),
            header: String::new(),
            status,
            value: None,
            summary: String::new(),
            recommendation: None,
            weight,
            earned,
        }
    }

    #[test]
    fn score_normalizes_when_a_control_is_not_applicable() {
        let assessments = [
            assessment(RuleStatus::Info, 0, 0.0),
            assessment(RuleStatus::Pass, 40, 40.0),
            assessment(RuleStatus::Warning, 40, 20.0),
        ];

        assert_eq!(normalized_score(&assessments), 75);
    }

    #[test]
    fn score_keeps_half_points_until_final_rounding() {
        let assessments = [
            assessment(RuleStatus::Pass, 80, 80.0),
            assessment(RuleStatus::Warning, 15, 7.5),
            assessment(RuleStatus::Warning, 5, 2.5),
        ];

        assert_eq!(normalized_score(&assessments), 90);
    }
}

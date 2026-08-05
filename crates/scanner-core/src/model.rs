use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grade {
    #[serde(rename = "A+")]
    APlus,
    A,
    B,
    C,
    D,
    E,
    F,
}

impl Grade {
    #[must_use]
    pub const fn from_score(score: u8) -> Self {
        match score {
            100 => Self::APlus,
            90..=99 => Self::A,
            80..=89 => Self::B,
            70..=79 => Self::C,
            60..=69 => Self::D,
            40..=59 => Self::E,
            _ => Self::F,
        }
    }
}

impl fmt::Display for Grade {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::APlus => "A+",
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
            Self::E => "E",
            Self::F => "F",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleStatus {
    Pass,
    Warning,
    Fail,
    Info,
}

impl fmt::Display for RuleStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pass => "pass",
            Self::Warning => "warning",
            Self::Fail => "fail",
            Self::Info => "info",
        })
    }
}

impl RuleStatus {
    pub(crate) const fn earned_half_points(self, weight: u8) -> u16 {
        match self {
            Self::Pass => weight as u16 * 2,
            Self::Warning => weight as u16,
            Self::Fail | Self::Info => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeaderAssessment {
    pub id: String,
    pub header: String,
    pub status: RuleStatus,
    pub value: Option<String>,
    pub summary: String,
    pub recommendation: Option<String>,
    pub weight: u8,
    pub earned: f32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSummary {
    pub passed: u16,
    pub warnings: u16,
    pub failed: u16,
    pub informational: u16,
}

impl ScanSummary {
    #[must_use]
    pub fn from_assessments(assessments: &[HeaderAssessment]) -> Self {
        let mut summary = Self::default();
        for assessment in assessments {
            match assessment.status {
                RuleStatus::Pass => summary.passed += 1,
                RuleStatus::Warning => summary.warnings += 1,
                RuleStatus::Fail => summary.failed += 1,
                RuleStatus::Info => summary.informational += 1,
            }
        }
        summary
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Apache,
    AwsCloudFront,
    Cloudflare,
    Gcp,
    Netlify,
    Nginx,
    Unknown,
    Vercel,
}

impl fmt::Display for Platform {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Apache => "Apache",
            Self::AwsCloudFront => "AWS CloudFront",
            Self::Cloudflare => "Cloudflare",
            Self::Gcp => "Google Cloud",
            Self::Netlify => "Netlify",
            Self::Nginx => "Nginx",
            Self::Unknown => "Unknown",
            Self::Vercel => "Vercel",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformDetection {
    pub platform: Platform,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceCategory {
    Advertising,
    Analytics,
    Cdn,
    Chat,
    Fonts,
    Maps,
    Payment,
    Social,
    Video,
}

impl fmt::Display for ResourceCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Advertising => "Advertising",
            Self::Analytics => "Analytics",
            Self::Cdn => "CDN",
            Self::Chat => "Chat",
            Self::Fonts => "Fonts",
            Self::Maps => "Maps",
            Self::Payment => "Payment",
            Self::Social => "Social",
            Self::Video => "Video",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedResource {
    pub category: ResourceCategory,
    pub name: String,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseMetadata {
    pub status: u16,
    pub content_type: Option<String>,
    pub body_bytes: usize,
    pub body_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    pub schema_version: u16,
    pub requested_url: String,
    pub final_url: String,
    pub scanned_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub grade: Grade,
    pub score: u8,
    pub summary: ScanSummary,
    pub headers: Vec<HeaderAssessment>,
    pub platform: PlatformDetection,
    pub resources: Vec<DetectedResource>,
    pub response: ResponseMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grades_cover_every_score() {
        assert_eq!(Grade::from_score(100), Grade::APlus);
        assert_eq!(Grade::from_score(99), Grade::A);
        assert_eq!(Grade::from_score(80), Grade::B);
        assert_eq!(Grade::from_score(70), Grade::C);
        assert_eq!(Grade::from_score(60), Grade::D);
        assert_eq!(Grade::from_score(40), Grade::E);
        assert_eq!(Grade::from_score(39), Grade::F);
    }
}

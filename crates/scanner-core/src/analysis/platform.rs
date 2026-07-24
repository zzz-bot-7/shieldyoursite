use reqwest::header::HeaderMap;

use crate::model::{Platform, PlatformDetection};

pub(crate) fn detect_platform(headers: &HeaderMap) -> PlatformDetection {
    let server = header_text(headers, "server").to_ascii_lowercase();
    let google_header = headers
        .keys()
        .find(|name| name.as_str().starts_with("x-goog-"))
        .map(|name| name.as_str().to_owned());
    let candidates = [
        candidate(
            Platform::Cloudflare,
            [
                evidence(headers.contains_key("cf-ray"), 70, "cf-ray"),
                evidence(
                    headers.contains_key("cf-cache-status"),
                    50,
                    "cf-cache-status",
                ),
                evidence(server.contains("cloudflare"), 40, "server: cloudflare"),
            ],
        ),
        candidate(
            Platform::Vercel,
            [
                evidence(headers.contains_key("x-vercel-id"), 70, "x-vercel-id"),
                evidence(headers.contains_key("x-vercel-cache"), 50, "x-vercel-cache"),
                evidence(server.contains("vercel"), 40, "server: vercel"),
            ],
        ),
        candidate(
            Platform::Netlify,
            [
                evidence(
                    headers.contains_key("x-nf-request-id"),
                    70,
                    "x-nf-request-id",
                ),
                evidence(headers.contains_key("x-nf-country"), 30, "x-nf-country"),
                evidence(server.contains("netlify"), 40, "server: netlify"),
            ],
        ),
        candidate(
            Platform::AwsCloudFront,
            [
                evidence(headers.contains_key("x-amz-cf-id"), 70, "x-amz-cf-id"),
                evidence(headers.contains_key("x-amz-cf-pop"), 60, "x-amz-cf-pop"),
                evidence(
                    header_text(headers, "x-cache")
                        .to_ascii_lowercase()
                        .contains("cloudfront"),
                    40,
                    "x-cache: cloudfront",
                ),
            ],
        ),
        candidate(
            Platform::Gcp,
            [
                google_header.map(|name| (70, name)),
                evidence(
                    header_text(headers, "via")
                        .to_ascii_lowercase()
                        .contains("google"),
                    40,
                    "via: google",
                ),
                None,
            ],
        ),
        candidate(
            Platform::Apache,
            [
                evidence(server.contains("apache"), 40, "server: apache"),
                None,
                None,
            ],
        ),
        candidate(
            Platform::Nginx,
            [
                evidence(server.contains("nginx"), 40, "server: nginx"),
                None,
                None,
            ],
        ),
    ];

    let mut best = PlatformDetection {
        platform: Platform::Unknown,
        confidence: 0,
        evidence: Vec::new(),
    };
    for detection in candidates {
        if detection.confidence > best.confidence {
            best = detection;
        }
    }
    best
}

fn candidate<const N: usize>(
    platform: Platform,
    evidence_items: [Option<(u8, String)>; N],
) -> PlatformDetection {
    let mut confidence = 0_u8;
    let mut evidence = Vec::new();
    for (weight, item) in evidence_items.into_iter().flatten() {
        confidence = confidence.saturating_add(weight).min(100);
        evidence.push(item);
    }
    evidence.sort();
    PlatformDetection {
        platform,
        confidence,
        evidence,
    }
}

fn evidence(condition: bool, weight: u8, name: &str) -> Option<(u8, String)> {
    condition.then(|| (weight, name.to_owned()))
}

fn header_text(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use reqwest::header::{HeaderName, HeaderValue};

    use super::*;

    #[test]
    fn strong_edge_signal_beats_server_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("server"),
            HeaderValue::from_static("nginx"),
        );
        headers.insert(
            HeaderName::from_static("cf-ray"),
            HeaderValue::from_static("abc"),
        );

        let detection = detect_platform(&headers);
        assert_eq!(detection.platform, Platform::Cloudflare);
        assert_eq!(detection.confidence, 70);
    }

    #[test]
    fn multiple_signals_cap_confidence() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("cf-ray"),
            HeaderValue::from_static("abc"),
        );
        headers.insert(
            HeaderName::from_static("cf-cache-status"),
            HeaderValue::from_static("HIT"),
        );
        headers.insert(
            HeaderName::from_static("server"),
            HeaderValue::from_static("cloudflare"),
        );

        assert_eq!(detect_platform(&headers).confidence, 100);
    }
}

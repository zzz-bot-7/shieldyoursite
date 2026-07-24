use std::collections::{BTreeMap, BTreeSet};

use scraper::{Html, Selector};
use url::Url;

use crate::model::{DetectedResource, ResourceCategory};

struct ResourcePattern {
    domain: &'static str,
    name: &'static str,
    category: ResourceCategory,
}

const RESOURCE_PATTERNS: &[ResourcePattern] = &[
    ResourcePattern {
        domain: "stripe.com",
        name: "Stripe",
        category: ResourceCategory::Payment,
    },
    ResourcePattern {
        domain: "paypal.com",
        name: "PayPal",
        category: ResourceCategory::Payment,
    },
    ResourcePattern {
        domain: "paypalobjects.com",
        name: "PayPal",
        category: ResourceCategory::Payment,
    },
    ResourcePattern {
        domain: "google-analytics.com",
        name: "Google Analytics",
        category: ResourceCategory::Analytics,
    },
    ResourcePattern {
        domain: "googletagmanager.com",
        name: "Google Tag Manager",
        category: ResourceCategory::Analytics,
    },
    ResourcePattern {
        domain: "hotjar.com",
        name: "Hotjar",
        category: ResourceCategory::Analytics,
    },
    ResourcePattern {
        domain: "mixpanel.com",
        name: "Mixpanel",
        category: ResourceCategory::Analytics,
    },
    ResourcePattern {
        domain: "googleapis.com",
        name: "Google Fonts",
        category: ResourceCategory::Fonts,
    },
    ResourcePattern {
        domain: "gstatic.com",
        name: "Google Fonts",
        category: ResourceCategory::Fonts,
    },
    ResourcePattern {
        domain: "typekit.net",
        name: "Adobe Fonts",
        category: ResourceCategory::Fonts,
    },
    ResourcePattern {
        domain: "cloudflare.com",
        name: "Cloudflare CDN",
        category: ResourceCategory::Cdn,
    },
    ResourcePattern {
        domain: "jsdelivr.net",
        name: "jsDelivr",
        category: ResourceCategory::Cdn,
    },
    ResourcePattern {
        domain: "unpkg.com",
        name: "unpkg",
        category: ResourceCategory::Cdn,
    },
    ResourcePattern {
        domain: "intercom.io",
        name: "Intercom",
        category: ResourceCategory::Chat,
    },
    ResourcePattern {
        domain: "tawk.to",
        name: "Tawk",
        category: ResourceCategory::Chat,
    },
    ResourcePattern {
        domain: "youtube.com",
        name: "YouTube",
        category: ResourceCategory::Video,
    },
    ResourcePattern {
        domain: "youtube-nocookie.com",
        name: "YouTube",
        category: ResourceCategory::Video,
    },
    ResourcePattern {
        domain: "vimeo.com",
        name: "Vimeo",
        category: ResourceCategory::Video,
    },
    ResourcePattern {
        domain: "facebook.net",
        name: "Meta",
        category: ResourceCategory::Social,
    },
    ResourcePattern {
        domain: "twitter.com",
        name: "X",
        category: ResourceCategory::Social,
    },
    ResourcePattern {
        domain: "googlesyndication.com",
        name: "Google Ads",
        category: ResourceCategory::Advertising,
    },
    ResourcePattern {
        domain: "googleadservices.com",
        name: "Google Ads",
        category: ResourceCategory::Advertising,
    },
    ResourcePattern {
        domain: "google.com",
        name: "Google Maps",
        category: ResourceCategory::Maps,
    },
];

pub(crate) fn detect_resources(html: &str, base_url: &Url) -> Vec<DetectedResource> {
    if html.is_empty() {
        return Vec::new();
    }

    let document = Html::parse_document(html);
    let selectors = [
        ("script[src]", "src"),
        ("link[href]", "href"),
        ("iframe[src]", "src"),
        ("img[src]", "src"),
    ];
    let mut grouped: BTreeMap<String, (ResourceCategory, BTreeSet<String>)> = BTreeMap::new();

    for (selector_text, attribute) in selectors {
        let selector = Selector::parse(selector_text).expect("static selector must parse");
        for element in document.select(&selector) {
            let Some(reference) = element.value().attr(attribute) else {
                continue;
            };
            let Ok(url) = base_url.join(reference) else {
                continue;
            };
            if !matches!(url.scheme(), "http" | "https") {
                continue;
            }
            let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
                continue;
            };
            if base_url
                .host_str()
                .is_some_and(|base_host| host.eq_ignore_ascii_case(base_host))
            {
                continue;
            }

            if let Some(pattern) = RESOURCE_PATTERNS
                .iter()
                .find(|pattern| host_matches(&host, pattern.domain))
            {
                let entry = grouped
                    .entry(pattern.name.to_owned())
                    .or_insert_with(|| (pattern.category.clone(), BTreeSet::new()));
                entry.1.insert(host);
            }
        }
    }

    grouped
        .into_iter()
        .map(|(name, (category, hosts))| DetectedResource {
            category,
            name,
            hosts: hosts.into_iter().collect(),
        })
        .collect()
}

fn host_matches(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_url() -> Url {
        Url::parse("https://example.com").expect("test URL must parse")
    }

    #[test]
    fn detects_known_external_hosts() {
        let html = r#"
            <script src="https://js.stripe.com/v3/"></script>
            <link href="https://fonts.googleapis.com/css2?family=Inter">
            <iframe src="https://www.youtube-nocookie.com/embed/id"></iframe>
        "#;
        let resources = detect_resources(html, &base_url());
        let names: Vec<&str> = resources
            .iter()
            .map(|resource| resource.name.as_str())
            .collect();
        assert_eq!(names, vec!["Google Fonts", "Stripe", "YouTube"]);
    }

    #[test]
    fn does_not_match_provider_text_in_path_or_query() {
        let html = r#"
            <script src="https://evil.example/script?next=js.stripe.com"></script>
            <img src="/google-analytics.com/logo.png">
        "#;
        assert!(detect_resources(html, &base_url()).is_empty());
    }

    #[test]
    fn ignores_same_origin_resources() {
        let html = r#"<script src="/app.js"></script>"#;
        assert!(detect_resources(html, &base_url()).is_empty());
    }
}

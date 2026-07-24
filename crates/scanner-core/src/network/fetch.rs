use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, ACCEPT, CONTENT_TYPE};
use url::Url;

use super::dns::PublicOnlyDnsResolver;
use super::target::validate_redirect_target;
use super::ScanError;

pub(crate) const DEFAULT_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;

#[derive(Debug)]
pub(crate) struct FetchedPage {
    pub final_url: Url,
    pub status: u16,
    pub headers: HeaderMap,
    pub content_type: Option<String>,
    pub body: String,
    pub body_bytes: usize,
    pub body_truncated: bool,
}

pub(crate) fn build_client() -> Result<reqwest::Client, ScanError> {
    let redirect = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("redirect limit reached");
        }
        if validate_redirect_target(attempt.url()).is_err() {
            return attempt.error("blocked redirect");
        }
        attempt.follow()
    });

    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirect(redirect)
        .dns_resolver(Arc::new(PublicOnlyDnsResolver))
        .no_proxy()
        .user_agent(concat!("shield/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| ScanError::Client)
}

pub(crate) async fn fetch_page(
    client: &reqwest::Client,
    url: Url,
    max_body_bytes: usize,
) -> Result<FetchedPage, ScanError> {
    let mut response = client
        .get(url)
        .header(ACCEPT, "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1")
        .send()
        .await
        .map_err(|error| map_request_error(&error))?;

    let status = response.status();
    if !status.is_success() {
        return Err(ScanError::HttpStatus(status.as_u16()));
    }

    let final_url = response.url().clone();
    validate_redirect_target(&final_url)?;

    let headers = response.headers().clone();
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let should_read_body = content_type.as_deref().is_none_or(is_html_content_type);

    let mut bytes = Vec::with_capacity(max_body_bytes.min(64 * 1024));
    let mut body_truncated = false;

    if should_read_body {
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| map_request_error(&error))?
        {
            if append_limited(&mut bytes, &chunk, max_body_bytes) {
                body_truncated = true;
                break;
            }
            if bytes.len() == max_body_bytes {
                body_truncated = response.content_length().is_none_or(|length| {
                    length > u64::try_from(max_body_bytes).unwrap_or(u64::MAX)
                });
                break;
            }
        }
    }

    let body_bytes = bytes.len();
    let body = String::from_utf8_lossy(&bytes).into_owned();

    Ok(FetchedPage {
        final_url,
        status: status.as_u16(),
        headers,
        content_type,
        body,
        body_bytes,
        body_truncated,
    })
}

fn append_limited(buffer: &mut Vec<u8>, chunk: &[u8], limit: usize) -> bool {
    let remaining = limit.saturating_sub(buffer.len());
    let accepted = chunk.len().min(remaining);
    buffer.extend_from_slice(&chunk[..accepted]);
    chunk.len() > remaining
}

fn is_html_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    matches!(media_type.as_str(), "text/html" | "application/xhtml+xml")
}

fn map_request_error(error: &reqwest::Error) -> ScanError {
    if error.is_timeout() {
        ScanError::Request("timeout".to_owned())
    } else if error.is_redirect() {
        ScanError::Request("redirect blocked".to_owned())
    } else if error.is_connect() {
        ScanError::Request("connection failed".to_owned())
    } else {
        ScanError::Request("response failed".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_html_content_types() {
        assert!(is_html_content_type("text/html; charset=utf-8"));
        assert!(is_html_content_type("application/xhtml+xml"));
        assert!(!is_html_content_type("application/json"));
    }

    #[test]
    fn body_chunks_never_exceed_limit() {
        let mut body = b"1234".to_vec();

        assert!(append_limited(&mut body, b"567890", 8));
        assert_eq!(body, b"12345678");
    }
}

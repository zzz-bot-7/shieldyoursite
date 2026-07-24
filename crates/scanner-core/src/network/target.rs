use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Url;

use super::ScanError;

/// Normalizes and validates an HTTP or HTTPS scan target.
///
/// # Errors
///
/// Returns [`ScanError::InvalidTarget`] when the target is malformed, uses an
/// unsupported scheme, or includes credentials. Returns
/// [`ScanError::BlockedTarget`] for forbidden hosts and non-public addresses.
pub fn normalize_target(input: &str) -> Result<Url, ScanError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(ScanError::InvalidTarget);
    }

    let candidate = if input.contains("://") {
        input.to_owned()
    } else {
        format!("https://{input}")
    };

    let mut url = Url::parse(&candidate).map_err(|_| ScanError::InvalidTarget)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ScanError::InvalidTarget);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ScanError::InvalidTarget);
    }

    let host = url.host_str().ok_or(ScanError::InvalidTarget)?;
    if is_forbidden_hostname(host) {
        return Err(ScanError::BlockedTarget);
    }
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        if !is_public_ip(&ip) {
            return Err(ScanError::BlockedTarget);
        }
    }

    url.set_fragment(None);
    Ok(url)
}

pub(crate) fn validate_redirect_target(url: &Url) -> Result<(), ScanError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ScanError::BlockedTarget);
    }

    let host = url.host_str().ok_or(ScanError::InvalidTarget)?;
    if is_forbidden_hostname(host) {
        return Err(ScanError::BlockedTarget);
    }
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        if !is_public_ip(&ip) {
            return Err(ScanError::BlockedTarget);
        }
    }
    Ok(())
}

pub(crate) fn is_forbidden_hostname(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    hostname_is_or_subdomain(&host, "localhost")
        || hostname_is_or_subdomain(&host, "local")
        || hostname_is_or_subdomain(&host, "internal")
        || hostname_is_or_subdomain(&host, "home.arpa")
        || hostname_is_or_subdomain(&host, "svc")
        || host == "instance-data"
        || host == "metadata.google.internal"
        || host == "metadata.aws.internal"
}

fn hostname_is_or_subdomain(host: &str, suffix: &str) -> bool {
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[must_use]
pub fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_public_ipv4(*ipv4),
        IpAddr::V6(ipv6) => is_public_ipv6(*ipv6),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();

    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }

    let segments = ip.segments();
    let is_ipv4_compatible = segments[..6] == [0, 0, 0, 0, 0, 0];
    let is_well_known_nat64 = segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0];
    let [first, second] = segments[6].to_be_bytes();
    let [third, fourth] = segments[7].to_be_bytes();
    let embedded_ipv4 = Ipv4Addr::new(first, second, third, fourth);

    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || is_ipv4_compatible
        || (is_well_known_nat64 && !is_public_ipv4(embedded_ipv4))
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 1)
        || segments[0] == 0x2002
        || (segments[0] == 0x2001 && segments[1] == 0)
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("test IP must parse")
    }

    #[test]
    fn accepts_public_addresses() {
        assert!(is_public_ip(&ip("1.1.1.1")));
        assert!(is_public_ip(&ip("8.8.8.8")));
        assert!(is_public_ip(&ip("2606:4700:4700::1111")));
    }

    #[test]
    fn blocks_non_public_ipv4_ranges() {
        for value in [
            "0.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!is_public_ip(&ip(value)), "{value} should be blocked");
        }
    }

    #[test]
    fn blocks_non_public_ipv6_ranges() {
        for value in [
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::192.168.1.1",
            "64:ff9b::10.0.0.1",
            "64:ff9b::169.254.169.254",
            "64:ff9b:1::1",
            "2001::1",
            "2002::1",
            "100::1",
            "2001:db8::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(!is_public_ip(&ip(value)), "{value} should be blocked");
        }
    }

    #[test]
    fn normalizes_domain_to_https() {
        let url = normalize_target("example.com/path#fragment").expect("target should normalize");
        assert_eq!(url.as_str(), "https://example.com/path");
    }

    #[test]
    fn rejects_credentials_and_private_targets() {
        assert!(matches!(
            normalize_target("https://user:pass@example.com"),
            Err(ScanError::InvalidTarget)
        ));
        assert!(matches!(
            normalize_target("http://127.0.0.1"),
            Err(ScanError::BlockedTarget)
        ));
        assert!(matches!(
            normalize_target("http://metadata.google.internal"),
            Err(ScanError::BlockedTarget)
        ));
    }
}

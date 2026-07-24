use std::net::SocketAddr;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use super::target::{is_forbidden_hostname, is_public_ip};

#[derive(Debug, Default, Clone)]
pub(crate) struct PublicOnlyDnsResolver;

impl Resolve for PublicOnlyDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().trim_end_matches('.').to_owned();
            if is_forbidden_hostname(&host) {
                return Err("blocked hostname".into());
            }

            let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                    "DNS lookup failed".into()
                })?
                .filter(|address| is_public_ip(&address.ip()))
                .collect();

            if addresses.is_empty() {
                return Err("blocked DNS result".into());
            }

            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

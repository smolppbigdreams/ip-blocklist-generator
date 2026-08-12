use anyhow::Result;
use ipnet::{IpNet, Ipv4Net};
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use tokio_retry::{
    Retry,
    strategy::{ExponentialBackoff, jitter},
};

/// Sorts, merges, and aggregates overlapping IPv4 CIDR blocks into a minimal set.
///
/// Modifies the provided vector by sorting network ranges sequentially by network address
/// and prefix length, then uses [`IpNet::aggregate`] to merge adjacent and overlapping blocks.
///
/// # Arguments
///
/// * `nets` - A vector of parsed [`Ipv4Net`] network ranges to coalesce.
///
/// # Returns
///
/// A vector of sorted and aggregated [`Ipv4Net`] network ranges containing no redundant or overlapping masks.
pub fn aggregate_cidrs(mut nets: Vec<Ipv4Net>) -> Vec<Ipv4Net> {
    nets.sort_unstable_by(|a, b| {
        a.network()
            .cmp(&b.network())
            .then_with(|| a.prefix_len().cmp(&b.prefix_len()))
    });

    let ip_nets: Vec<IpNet> = nets.into_iter().map(IpNet::V4).collect();

    IpNet::aggregate(&ip_nets)
        .into_iter()
        .filter_map(|net| match net {
            IpNet::V4(v4) => Some(v4),
            IpNet::V6(_) => None,
        })
        .collect()
}

/// Constructs a [`serde_json::Value`] representing a Cilium `CiliumClusterwideNetworkPolicy` manifest.
///
/// Modifies the provided network slice into Cilium-compatible CIDR objects and wraps them
/// inside an `ingressDeny` policy specification.
///
/// # Arguments
///
/// * `networks` - A slice of [`Ipv4Net`] ranges to deny in the policy rules.
///
/// # Returns
///
/// A JSON structure matching the `cilium.io/v2` `CiliumClusterwideNetworkPolicy` schema.
pub fn build_cilium_policy(networks: &[Ipv4Net]) -> serde_json::Value {
    let cidr_set: Vec<serde_json::Value> = networks
        .iter()
        .map(|net| json!({ "cidr": net.to_string() }))
        .collect();

    json!({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumClusterwideNetworkPolicy",
        "metadata": {
            "name": "block-bad-actors"
        },
        "spec": {
            "description": "L3/L4 eBPF Blocklist using SPAMHAUS & FIREHOL",
            "ingressDeny": [
                {
                    "fromCIDRSet": cidr_set
                }
            ]
        }
    })
}

/// Asynchronously retrieves the raw text payload from a specified URL with retry logic.
///
/// Sends an HTTP `GET` request using the provided [`Client`]. If the request fails or
/// returns a non-success HTTP status, it retries using exponential backoff with jitter.
///
/// # Arguments
///
/// * `client` - A reference to the shared HTTP [`Client`].
/// * `url` - The target endpoint URL to fetch.
/// * `max_retries` - The maximum number of retry attempts.
///
/// # Returns
///
/// The raw body content of the HTTP response as a [`String`].
///
/// # Errors
///
/// Returns an [`anyhow::Error`] if all retry attempts fail or the body cannot be decoded.
pub async fn fetch_blocklist_with_retry(
    client: &Client,
    url: &str,
    max_retries: usize,
) -> Result<String> {
    // Exponential backoff starting at 100ms, capped at 2 seconds
    let retry_strategy = ExponentialBackoff::from_millis(100)
        .max_delay(Duration::from_secs(2))
        .map(jitter)
        .take(max_retries);

    Retry::start(retry_strategy, || async {
        match client.get(url).send().await {
            Ok(response) => match response.status() {
                status if status.is_success() => response.text().await.map_err(Into::into),
                status => Err(anyhow::anyhow!(
                    "HTTP request failed with status code: {}",
                    status
                )),
            },
            Err(err) => Err(anyhow::anyhow!("Network request failed: {}", err)),
        }
    })
    .await
}

use anyhow::{Result, anyhow};
use ipnet::Ipv4Net;
use reqwest::Client;
use serde_json::{Value, json};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio_retry::{
    Retry,
    strategy::{ExponentialBackoff, jitter},
};

/// Sorts, merges, and aggregates overlapping IPv4 CIDR blocks into a minimal set.
///
/// This function sorts the input vector by network address and prefix length,
/// then uses [`Ipv4Net::aggregate`] to merge overlapping and adjacent networks.
///
/// # Arguments
///
/// * `nets` - A vector of parsed [`Ipv4Net`] network ranges to coalesce.
///
/// # Returns
///
/// A vector of sorted and aggregated [`Ipv4Net`] network ranges containing no redundant
/// or overlapping masks.
pub fn aggregate_cidrs(mut nets: Vec<Ipv4Net>) -> Vec<Ipv4Net> {
    nets.sort_unstable_by(|a, b| {
        a.network()
            .cmp(&b.network())
            .then_with(|| a.prefix_len().cmp(&b.prefix_len()))
    });
    Ipv4Net::aggregate(&nets)
}

/// Constructs a [`serde_json::Value`] representing a Cilium `CiliumClusterwideNetworkPolicy` manifest.
///
/// This function converts each IPv4 network into a Cilium CIDR object and wraps them inside
/// an `ingressDeny` policy specification.
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
            "description": "L3/L4 eBPF Blocklist using SPAMHAUS, FIREHOL & TOR",
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
    // Exponential backoff starting at 100ms, capped at 2 seconds.
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

/// Parses a single line from a blocklist into an `Ipv4Net`.
///
/// Lines are trimmed before parsing. Blank lines and lines starting with `#` or `;`
/// are ignored. If a line contains whitespace, only the first token is considered.
/// A bare IP address is treated as a `/32` network.
///
/// # Arguments
///
/// * `line` - A single line from a blocklist.
///
/// # Returns
///
/// The parsed [`Ipv4Net`] if the line is valid, or `None` if it is empty, a comment,
/// or contains no parsible network.
pub(crate) fn parse_blocklist_line(line: &str) -> Option<Ipv4Net> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    let token = line.split_whitespace().next()?;
    if let Ok(net) = token.parse::<Ipv4Net>() {
        return Some(net);
    }
    if let Ok(ip) = token.parse::<Ipv4Addr>() {
        return Ipv4Net::new(ip, 32).ok();
    }
    None
}

/// Parses a MISP warninglist JSON document into an aggregated set of IPv4 networks.
///
/// The JSON is expected to contain a `"list"` array of CIDR strings or bare IP addresses.
/// Entries that cannot be parsed as IPv4 ranges are ignored.
///
/// # Arguments
///
/// * `body` - The raw JSON body of a MISP warninglist.
///
/// # Returns
///
/// An aggregated [`Vec<Ipv4Net>`] of allowlisted networks.
///
/// # Errors
///
/// Returns an [`anyhow::Error`] if the JSON is invalid or the `"list"` array is missing.
pub(crate) fn parse_misp_warninglist(body: &str) -> Result<Vec<Ipv4Net>> {
    let value: Value = serde_json::from_str(body)
        .map_err(|err| anyhow!("failed to parse MISP warninglist JSON: {err}"))?;
    let entries = value
        .get("list")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("MISP warninglist JSON missing a 'list' array"))?;

    let networks: Vec<Ipv4Net> = entries
        .iter()
        .filter_map(Value::as_str)
        .filter_map(parse_blocklist_line)
        .collect();

    Ok(aggregate_cidrs(networks))
}

/// Removes allowlisted network ranges from a set of blocked networks.
///
/// Each blocked network is processed independently. If a blocked network is fully contained
/// in an allowlisted range, it is removed. If a blocked network partially overlaps an
/// allowlisted range, the blocked network is split so that only the non-allowlisted portions
/// remain. The resulting ranges are then aggregated.
///
/// # Arguments
///
/// * `blocked` - A vector of blocked [`Ipv4Net`] ranges.
/// * `allowlist` - A slice of allowlisted [`Ipv4Net`] ranges.
///
/// # Returns
///
/// A minimal aggregated vector of [`Ipv4Net`] ranges that excludes all allowlisted ranges.
pub(crate) fn apply_allowlist(blocked: Vec<Ipv4Net>, allowlist: &[Ipv4Net]) -> Vec<Ipv4Net> {
    let mut result = Vec::new();

    for network in blocked {
        let mut remaining = vec![network];

        for allow in allowlist {
            let mut next = Vec::new();
            for part in remaining {
                next.extend(subtract_cidr(part, allow));
            }
            remaining = next;
            if remaining.is_empty() {
                break;
            }
        }

        result.extend(remaining);
    }

    aggregate_cidrs(result)
}

/// Subtracts one CIDR from another, returning the parts of `base` not covered by `other`.
///
/// This function assumes standard CIDR alignment. For any two IPv4 networks, either they
/// are disjoint, one fully contains the other, or neither overlaps. Recursive splitting is
/// used when `base` contains `other`.
fn subtract_cidr(base: Ipv4Net, other: &Ipv4Net) -> Vec<Ipv4Net> {
    if !cidrs_overlap(&base, other) {
        return vec![base];
    }

    // Other fully contains base.
    if other.contains(&base.network()) && other.contains(&base.broadcast()) {
        return Vec::new();
    }

    // Base contains other; split base into its two subnets and recurse.
    if base.contains(&other.network()) {
        if base.prefix_len() == 32 {
            return Vec::new();
        }

        let mut result = Vec::new();
        // Pass the target prefix length (base + 1) for the immediate child subnets
        if let Ok(subnets) = base.subnets(base.prefix_len() + 1) {
            for subnet in subnets {
                result.extend(subtract_cidr(subnet, other));
            }
        }
        return result;
    }

    // Unreachable for valid CIDR pairs, but retain base for safety.
    vec![base]
}

/// Returns `true` if two IPv4 networks overlap.
fn cidrs_overlap(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_line_ignores_blank_lines() {
        // Blank lines and whitespace-only lines should not produce network entries.
        assert!(parse_blocklist_line("").is_none());
        assert!(parse_blocklist_line("   ").is_none());
    }

    #[test]
    fn parse_line_ignores_comments() {
        // Both comment prefixes used by Spamhaus and FireHOL are filtered out.
        assert!(parse_blocklist_line("# comment").is_none());
        assert!(parse_blocklist_line("; comment").is_none());
    }

    #[test]
    fn parse_line_parses_cidr() {
        // A standard CIDR notation should be preserved as-is.
        let net = parse_blocklist_line("10.0.0.0/8").unwrap();
        assert_eq!(net, "10.0.0.0/8".parse().unwrap());
    }

    #[test]
    fn parse_line_parses_bare_ip_as_32() {
        // A bare IP address is implicitly a /32 network.
        let net = parse_blocklist_line("192.0.2.1").unwrap();
        assert_eq!(net, "192.0.2.1/32".parse().unwrap());
    }

    #[test]
    fn parse_line_ignores_invalid_entries() {
        // Non-IP content should be skipped rather than cause a panic.
        assert!(parse_blocklist_line("not an ip").is_none());
    }

    #[test]
    fn parse_line_takes_first_token() {
        // Spamhaus lines have an optional second field; only the first token is meaningful.
        let net = parse_blocklist_line("10.0.0.0/8 some extra").unwrap();
        assert_eq!(net, "10.0.0.0/8".parse().unwrap());
    }

    #[test]
    fn aggregate_merges_overlapping_and_adjacent() {
        // Adjacent /24s and a covering /23 should collapse into a /22.
        let nets = vec![
            "10.0.0.0/24".parse().unwrap(),
            "10.0.1.0/24".parse().unwrap(),
            "10.0.2.0/23".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
        ];
        let result = aggregate_cidrs(nets);
        assert_eq!(
            result,
            vec![
                "10.0.0.0/22".parse().unwrap(),
                "192.168.1.0/24".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn aggregate_deduplicates_identical_networks() {
        // Duplicate entries should be consolidated to a single network.
        let nets = vec![
            "10.0.0.0/24".parse().unwrap(),
            "10.0.0.0/24".parse().unwrap(),
        ];
        assert_eq!(aggregate_cidrs(nets), vec!["10.0.0.0/24".parse().unwrap()]);
    }

    #[test]
    fn policy_contains_expected_cidrs() {
        // The generated policy must place each network under fromCIDRSet.
        let nets = vec!["10.0.0.0/8".parse().unwrap()];
        let policy = build_cilium_policy(&nets);
        assert_eq!(
            policy["spec"]["ingressDeny"][0]["fromCIDRSet"][0]["cidr"].as_str(),
            Some("10.0.0.0/8")
        );
    }

    #[test]
    fn parse_misp_warninglist_parses_cidrs_and_ips() {
        // The warninglist contains both CIDRs and bare IPs, plus an ignored non-IP entry.
        let body = r#"{"list":["10.0.0.0/8","192.0.2.1","not-a-cidr"]}"#;
        let result = parse_misp_warninglist(body).unwrap();
        assert_eq!(
            result,
            vec![
                "10.0.0.0/8".parse().unwrap(),
                "192.0.2.1/32".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn parse_misp_warninglist_rejects_invalid_json() {
        // Corrupt warninglist data should produce an error rather than silently passing.
        assert!(parse_misp_warninglist("not json").is_err());
    }

    #[test]
    fn apply_allowlist_removes_fully_contained() {
        // A blocked /24 inside an allowlisted /16 must be removed entirely.
        let blocked = vec!["10.0.0.0/24".parse().unwrap()];
        let allowlist = vec!["10.0.0.0/16".parse().unwrap()];
        assert!(apply_allowlist(blocked, &allowlist).is_empty());
    }

    #[test]
    fn apply_allowlist_removes_exact_match() {
        // An exact blocked/allowlisted match must be removed.
        let blocked = vec!["10.0.0.0/24".parse().unwrap()];
        let allowlist = vec!["10.0.0.0/24".parse().unwrap()];
        assert!(apply_allowlist(blocked, &allowlist).is_empty());
    }

    #[test]
    fn apply_allowlist_splits_partial_overlap() {
        // Removing the first half of a /24 leaves only the second half.
        let blocked = vec!["10.0.0.0/24".parse().unwrap()];
        let allowlist = vec!["10.0.0.0/25".parse().unwrap()];
        let result = apply_allowlist(blocked, &allowlist);
        assert_eq!(result, vec!["10.0.0.128/25".parse().unwrap()]);
    }

    #[test]
    fn apply_allowlist_preserves_disjoint_ranges() {
        // Blocked networks with no allowlist overlap remain unchanged.
        let blocked = vec!["10.0.0.0/24".parse().unwrap()];
        let allowlist = vec!["192.168.1.0/24".parse().unwrap()];
        let result = apply_allowlist(blocked, &allowlist);
        assert_eq!(result, vec!["10.0.0.0/24".parse().unwrap()]);
    }
}

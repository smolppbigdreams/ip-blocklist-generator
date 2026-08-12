//! A tool to fetch public IP blocklists and build Cilium network policy manifests.
//!
//! This crate fetches IP blocklists from external sources (Spamhaus DROP, FireHOL Level 1,
//! and known TOR exit nodes), aggregates and deduplicates the IP network ranges, applies
//! MISP warninglists as allowlists, and outputs a Cilium clusterwide network policy manifest
//! in JSON format to standard output.

mod functions;

use anyhow::Result;
use functions::{
    aggregate_cidrs, apply_allowlist, build_cilium_policy, fetch_blocklist_with_retry,
    parse_blocklist_line, parse_misp_warninglist,
};
use ipnet::Ipv4Net;
use reqwest::Client;
use std::time::Duration;

/// Target URL for Spamhaus DROP (Don't Route Or Peer) blocklist.
const SPAMHAUS_URL: &str = "https://www.spamhaus.org/drop/drop.txt";

/// Target URL for FireHOL Level 1 aggregated netset blocklist.
const FIREHOL_URL: &str =
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset";

/// Target URL for the official TOR exit node list.
const TOR_EXIT_URL: &str = "https://check.torproject.org/torbulkexitlist";

/// MISP warninglists used as allowlists.
const MISP_WARNINGLIST_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/apple/list.json",
    "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/cloudflare/list.json",
    "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/googlebot/list.json",
    "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/openai-gptbot/list.json",
];

/// Maximum fetch retries per URL.
const MAX_RETRIES: usize = 3;

/// Orchestrates the fetching, parsing, allowlisting, aggregation, and manifest printing process.
///
/// # Errors
///
/// Returns an [`anyhow::Error`] if network requests fail, response bodies contain invalid UTF-8,
/// a MISP warninglist cannot be parsed, or JSON serialization encounters an internal error.
#[tokio::main]
async fn main() -> Result<()> {
    // Standard client with a connection timeout to prevent hanging indefinitely.
    let http_client = Client::builder().timeout(Duration::from_secs(10)).build()?;

    // Concurrently fetch Spamhaus, FireHOL, and TOR exit node blocklists with retries.
    let (spamhaus_body, firehol_body, tor_body) = tokio::try_join!(
        fetch_blocklist_with_retry(&http_client, SPAMHAUS_URL, MAX_RETRIES),
        fetch_blocklist_with_retry(&http_client, FIREHOL_URL, MAX_RETRIES),
        fetch_blocklist_with_retry(&http_client, TOR_EXIT_URL, MAX_RETRIES)
    )?;

    // Parse each blocklist line by line, skipping comments and invalid entries.
    let spamhaus_networks = spamhaus_body.lines().filter_map(parse_blocklist_line);
    let firehol_networks = firehol_body.lines().filter_map(parse_blocklist_line);
    let tor_networks = tor_body.lines().filter_map(parse_blocklist_line);

    // Aggregate all blocked networks into a minimal set of CIDR blocks.
    let raw_networks: Vec<Ipv4Net> = spamhaus_networks
        .chain(firehol_networks)
        .chain(tor_networks)
        .collect();
    let collapsed_networks = aggregate_cidrs(raw_networks);

    // Fetch and parse MISP warninglists, using them as allowlists.
    let mut allowlist_networks = Vec::new();
    for &url in MISP_WARNINGLIST_URLS {
        let body = fetch_blocklist_with_retry(&http_client, url, MAX_RETRIES).await?;
        allowlist_networks.extend(parse_misp_warninglist(&body)?);
    }
    let allowlist = aggregate_cidrs(allowlist_networks);

    // Remove allowlisted ranges from the blocked set.
    let filtered_networks = apply_allowlist(collapsed_networks, &allowlist);

    // Construct the CiliumClusterwideNetworkPolicy Custom Resource Definition (CRD) manifest.
    let policy_manifest = build_cilium_policy(&filtered_networks);

    // Serialize the JSON manifest with pretty indentation and emit it to standard output.
    println!("{}", serde_json::to_string_pretty(&policy_manifest)?);

    Ok(())
}

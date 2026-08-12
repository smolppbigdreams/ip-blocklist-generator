//! A tool to fetch public IP blocklists and build Cilium network policy manifests.
//!
//! This crate fetches IP blocklists from external sources (Spamhaus DROP and FireHOL Level 1),
//! aggregates and deduplicates the IP network ranges, and outputs a Cilium clusterwide network policy
//! manifest in JSON format to standard output.

mod functions;

use anyhow::Result;
use functions::{aggregate_cidrs, build_cilium_policy, fetch_blocklist_with_retry};
use ipnet::Ipv4Net;
use reqwest::Client;
use std::{net::Ipv4Addr, time::Duration};

/// Target URL for Spamhaus DROP (Don't Route Or Peer) blocklist.
const SPAMHAUS_URL: &str = "https://www.spamhaus.org/drop/drop.txt";

/// Target URL for FireHOL Level 1 aggregated netset blocklist.
const FIREHOL_URL: &str =
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset";

/// Target URL for official Tor Exit Nodes.
const TOR_EXIT_URL: &str = "https://check.torproject.org/exit-addresses";

/// Maximum fetch retries per URL.
const MAX_RETRIES: usize = 3;

/// Orchestrates the fetching, parsing, aggregation, and manifest printing process.
///
/// # Errors
///
/// Returns an [`anyhow::Error`] if network requests fail, response bodies contain invalid UTF-8,
/// or JSON serialization encounters an internal error.
#[tokio::main]
async fn main() -> Result<()> {
    // Standard client with a connection timeout to prevent hanging indefinitely.
    let http_client = Client::builder().timeout(Duration::from_secs(10)).build()?;

    // Concurrently fetch both blocklists with retry mechanisms enabled.
    let (spamhaus_body, firehol_body) = tokio::try_join!(
        fetch_blocklist_with_retry(&http_client, SPAMHAUS_URL, MAX_RETRIES),
        fetch_blocklist_with_retry(&http_client, FIREHOL_URL, MAX_RETRIES)
    )?;

    // Parse the Spamhaus blocklist entries.
    let spamhaus_networks =
        spamhaus_body
            .lines()
            .map(str::trim)
            .filter_map(|line| match line.chars().next() {
                // Skip blank lines and comment lines starting with ';' or '#'
                None | Some(';') | Some('#') => None,
                Some(_) => line.split_whitespace().next()?.parse::<Ipv4Net>().ok(),
            });

    // Parse the FireHOL blocklist entries.
    let firehol_networks =
        firehol_body
            .lines()
            .map(str::trim)
            .filter_map(|line| match line.chars().next() {
                // Skip blank lines and comment lines starting with '#'
                None | Some('#') => None,
                Some(_) => match (line.parse::<Ipv4Net>(), line.parse::<Ipv4Addr>()) {
                    (Ok(net), _) => Some(net),
                    (Err(_), Ok(ip)) => Ipv4Net::new(ip, 32).ok(),
                    (Err(_), Err(_)) => None,
                },
            });

    // Aggregate overlapping networks into a minimal set of CIDR blocks.
    let raw_networks: Vec<Ipv4Net> = spamhaus_networks.chain(firehol_networks).collect();
    let collapsed_networks = aggregate_cidrs(raw_networks);

    // Construct the CiliumClusterwideNetworkPolicy Custom Resource Definition (CRD) manifest.
    let policy_manifest = build_cilium_policy(&collapsed_networks);

    // Serialize the JSON manifest with pretty indentation and emit it to standard output.
    println!("{}", serde_json::to_string_pretty(&policy_manifest)?);

    Ok(())
}

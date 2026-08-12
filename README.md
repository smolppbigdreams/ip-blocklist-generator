# ip-blocklist-generator

## Summary

This tool fetches public IPv4 blocklists, aggregates overlapping CIDRs, and prints a Cilium `CiliumClusterwideNetworkPolicy` manifest to stdout.

## Why This Exists

Manually curating a blocklist of malicious IP networks is hard to keep fresh and even harder to review.

## Requirements

- Rust 1.85+ (the project uses edition 2024)
- Network access to the blocklist URLs
- A Cilium-enabled Kubernetes cluster if you plan to apply the generated manifest

## Usage

The tool has no runtime arguments.

It reads the two hardcoded source URLs, fetches them concurrently, and writes the generated policy to stdout.

If either blocklist cannot be fetched after retries, the tool exits with an error and does not print a partial policy.

```bash
# Write the policy to a file and apply it
cargo run --release > block-bad-actors.json
kubectl apply -f block-bad-actors.json

# See how many CIDRs are blocked
jq '.spec.ingressDeny[0].fromCIDRSet | length' block-bad-actors.json
```

## Data Sources

Both URLs and the retry count are compile-time constants in `src/main.rs`.

| Source | URL | Purpose |
|---|---|---|
| Spamhaus DROP | `https://www.spamhaus.org/drop/drop.txt` | Don't Route Or Peer (DROP) networks |
| FireHOL Level 1 | `https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset` | Aggregated list of malicious/botnet IPs |


## Generated Policy

The output is a `cilium.io/v2` `CiliumClusterwideNetworkPolicy` named `block-bad-actors`. It uses `spec.ingressDeny` with `fromCIDRSet` to block inbound traffic from the listed CIDRs.

Example:

```json
{
  "apiVersion": "cilium.io/v2",
  "kind": "CiliumClusterwideNetworkPolicy",
  "metadata": {
    "name": "block-bad-actors"
  },
  "spec": {
    "description": "L3/L4 eBPF Blocklist using SPAMHAUS & FIREHOL",
    "ingressDeny": [
      {
        "fromCIDRSet": [
          { "cidr": "1.0.0.0/24" },
          { "cidr": "2.2.2.0/24" }
        ]
      }
    ]
  }
}
```

## Limitations

- IPv4 only. IPv6 entries are currently ignored.
- The policy denies ingress only; no `egressDeny` rules are generated.
- Source lists can contain false positives. Test against expected traffic before using this widely.
- Source URLs are fixed at compile time.

## Development

Run the test suite:

```bash
cargo test
```

Tests cover blocklist line parsing, CIDR aggregation/deduplication, and policy JSON generation.

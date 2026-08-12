# ip-blocklist-generator

## Summary

Manually curating a blocklist of malicious IP networks is hard to keep fresh.

This tool exists to automate that process, with intented use in CD pipelines for Kubernetes clusters that use Cilium.

It does so by fetching public IPv4 blocklists (Spamhaus, FireHOL, TOR), applying MISP warninglists as allowlists, and printing a `CiliumClusterwideNetworkPolicy` manifest to stdout.

## Requirements

- Rust 1.85+ (the project uses edition 2024)
- Network access to the blocklist URLs
- A Cilium-enabled Kubernetes cluster if you plan to apply the generated manifest

## Usage

The tool has no runtime arguments.

It reads the hardcoded source URLs, fetches them, applies the allowlists, and writes the generated policy to stdout.

If either blocklist cannot be fetched after retries, the tool exits with an error and does not print a partial policy.

### Bash

```bash
# See how many CIDRs are blocked.
cargo run --release > block-bad-actors.json
jq '.spec.ingressDeny[0].fromCIDRSet | length' block-bad-actors.json
```

### Kubernetes ChronJob

```yaml
---
# ==========================================
# IP Blocklist Synchronization
# ==========================================
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ip-blocklist-synchronization
  namespace: security-system
spec:
  schedule: "0 */4 * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          securityContext:
            runAsUser: 10001
            runAsGroup: 10001
            fsGroup: 10001
            fsGroupChangePolicy: "OnRootMismatch"
          volumes:
            - name: ip-blocklist-volume
              persistentVolumeClaim:
                claimName: ip-blocklist-pvc
          containers:
            - name: generator
              image: my-registry.internal/security/ip-blocklist-generator:latest
              command: ["/bin/sh", "-c", "/app/ip-blocklist-generator > /buckets/security-manifests/ip-blocklist.json"]
              volumeMounts:
                - name: ip-blocklist-volume
                  mountPath: /buckets/security-manifests
              securityContext:
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                runAsNonRoot: true
                capabilities:
                  drop:
                    - ALL
              resources:
                requests:
                  cpu: "50m"
                  memory: "64Mi"
                limits:
                  cpu: "100m"
                  memory: "128Mi"
```

## Data Sources

### Blocklists

| Source | URL | Purpose |
|---|---|---|
| Spamhaus DROP | `https://www.spamhaus.org/drop/drop.txt` | Don't Route Or Peer networks |
| FireHOL Level 1 | `https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset` | Aggregated list of malicious/botnet IPs |
| TOR Exit Nodes | `https://check.torproject.org/torbulkexitlist`

### Allowlists

| Name | URL |
|---|---|
| Apple | `https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/apple/list.json` |
| Cloudflare | `https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/cloudflare/list.json` |
| Googlebot | `https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/googlebot/list.json` |
| OpenAI GPTBot | `https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/openai-gptbot/list.json` |

## Generated Policy

The output is a `cilium.io/v2` `CiliumClusterwideNetworkPolicy` named `block-bad-actors`. It uses `spec.ingressDeny` with `fromCIDRSet` to block inbound traffic from the aggregated (and allowlist‑filtered) CIDRs.

Example:

```json
{
  "apiVersion": "cilium.io/v2",
  "kind": "CiliumClusterwideNetworkPolicy",
  "metadata": {
    "name": "block-bad-actors"
  },
  "spec": {
    "description": "L3/L4 eBPF Blocklist using SPAMHAUS, FIREHOL & TOR",
    "ingressDeny": [
      {
        "fromCIDRSet": [
          { "cidr": "5.83.143.18/32" },
          { "cidr": "23.129.64.201/32" },
          { "cidr": "23.147.148.0/24" },
          { "cidr": "192.88.128.0/22" },
          { "cidr": "203.20.99.0/24" }
        ]
      }
    ]
  }
}
```

## Limitations

- IPv4 only. IPv6 entries in the blocklists are currently ignored.
- The policy denies ingress only; no `egressDeny` rules are generated.
- MISP warninglists are static snapshots; they may become stale.
- Source URLs are fixed at compile time – future versions may accept command‑line arguments.
- TOR exit node list provides /32 entries. When many are consecutive, they are aggregated into larger blocks, which may deny traffic from IPs that no longer belong to TOR. Use with caution.

## Development

Run the test suite:

```bash
cargo test
```

Tests cover blocklist line parsing, CIDR aggregation/deduplication, MISP warninglist parsing, policy JSON generation, and the allowlist subtraction logic (including splitting and removal of overlapping ranges).

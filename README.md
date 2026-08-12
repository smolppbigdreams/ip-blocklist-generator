Here is the equivalent Rust implementation. It compiles down to a single, static binary (using `tokio`, `reqwest`, `ipnet`, and `kube`), making it lightweight, blazingly fast, and memory-safe inside a minimal Alpine or Distroless container image.

### Rust Core (`src/main.rs`)

`Cargo.toml` dependencies needed:

```toml
[dependencies]
tokio = { version = "1.0", features = ["full"] }
reqwest = "0.11"
ipnet = "2.9"
kube = { version = "0.88", features = ["client", "derives"] }
k8s-openapi = { version = "0.20", features = ["v1_28"] }
serde = { version = "1.0", features = ["derive"] }
serde_yaml = "0.9"
anyhow = "1.0"

```

```rust
use anyhow::{Context, Result};
use ipnet::{IpNet, Ipv4Net};
use k8s-openapi::apiextensions-apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::{
    api::{Api, DynamicObject, Patch, PatchParams, ResourceExt},
    Client,
};
use serde_json::json;
use std::collections::BTreeSet;

const SPAMHAUS_URL: &str = "https://www.spamhaus.org/drop/drop.txt";
const FIREHOL_URL: &str = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset";

#[tokio::main]
async fn main() -> Result<()> {
    println!("Fetching threat feeds...");
    let http_client = reqwest::Client::new();

    let spamhaus_body = http_client.get(SPAMHAUS_URL).send().await?.text().await?;
    let firehol_body = http_client.get(FIREHOL_URL).send().await?.text().await?;

    println!("Parsing and validating IPv4 subnets...");
    let mut raw_networks: Vec<Ipv4Net> = Vec::new();

    // Parse Spamhaus
    for line in spamhaus_body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(cidr_str) = line.split_whitespace().next() {
            if let Ok(net) = cidr_str.parse::<Ipv4Net>() {
                raw_networks.push(net);
            }
        }
    }

    // Parse FireHOL
    for line in firehol_body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(net) = line.parse::<Ipv4Net>() {
            raw_networks.push(net);
        } else if let Ok(ip) = line.parse::<std::net::Ipv4Addr>() {
            // Convert single IP to /32
            raw_networks.push(Ipv4Net::new(ip, 32).unwrap());
        }
    }

    println!("Collapsing overlapping and adjacent CIDRs...");
    let collapsed_networks = aggregate_cidrs(raw_networks);
    println!("Shrank list down to {} unique CIDR blocks.", collapsed_networks.len());

    println!("Applying CiliumClusterwideNetworkPolicy to Kubernetes cluster...");
    apply_cilium_policy(collapsed_networks).await?;

    println!("Successfully updated Cilium eBPF map via policy!");
    Ok(())
}

/// Merges overlapping and contiguous CIDR ranges to shrink eBPF map entries
fn aggregate_cidrs(mut nets: Vec<Ipv4Net>) -> Vec<Ipv4Net> {
    // Sort networks by starting address and prefix length
    nets.sort_by(|a, b| a.network().cmp(&b.network()).then(a.prefix_len().cmp(&b.prefix_len())));

    // Convert to ipnet aggregate algorithm
    IpNet::aggregate(&nets.into_iter().map(IpNet::V4).collect::<Vec<_>>())
        .into_iter()
        .filter_map(|net| match net {
            IpNet::V4(v4) => Some(v4),
            _ => None,
        })
        .collect()
}

/// Declaratively applies the CiliumClusterwideNetworkPolicy using server-side apply
async fn apply_cilium_policy(networks: Vec<Ipv4Net>) -> Result<()> {
    let client = Client::try_default().await.context("Failed to create K8s client")?;

    // Prepare CIDR list for YAML
    let cidr_set: Vec<serde_json::Value> = networks
        .into_iter()
        .map(|net| json!({ "cidr": net.to_string() }))
        .collect();

    let policy_manifest = json!({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumClusterwideNetworkPolicy",
        "metadata": {
            "name": "drop-bad-actors"
        },
        "spec": {
            "description": "Rust-generated L3/L4 eBPF Blocklist",
            "ingressDeny": [
                {
                    "fromCIDRSet": cidr_set
                }
            ]
        }
    });

    let gvk = kube::api::GroupVersionKind::gvk("cilium.io", "v2", "CiliumClusterwideNetworkPolicy");
    let api: Api<DynamicObject> = Api::all_with(client, &kube::api::ApiResource::from_gvk(&gvk));

    let ssap = PatchParams::apply("rust-ip-blocker").force();
    let patch = Patch::Apply(&policy_manifest);

    api.patch("drop-bad-actors", &ssap, &patch).await?;
    Ok(())
}

```

---

### Dockerfile (Distroless for Minimal Footprint)

You can compile this binary statically using `x86_64-unknown-linux-musl` and ship it in a scratch/distroless container under **~15MB total**:

```dockerfile
# --- Build Stage ---
FROM rust:1.80-alpine as builder
RUN apk add --no-libc-dev musl-dev
WORKDIR /app
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

# --- Execution Stage ---
FROM gcr.io/distroless/static-debian12
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/cilium-blocklist-sync /
USER 65534:65534
ENTRYPOINT ["/cilium-blocklist-sync"]

```

---

### Kubernetes CronJob Deployment (`cronjob.yaml`)

Deploy the Rust binary natively inside your Kubernetes cluster:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cilium-blocklist-sync
  namespace: envoy-gateway-system
spec:
  schedule: "0 */4 * * *" # Every 4 hours
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: cilium-blocklist-sync-sa
          restartPolicy: OnFailure
          containers:
            - name: sync
              image: my-registry.internal/security/cilium-blocklist-sync:v1.0.0
              resources:
                limits:
                  cpu: 100m
                  memory: 64Mi
                requests:
                  cpu: 10m
                  memory: 16Mi
---
# RBAC granting permission to manage CiliumClusterwideNetworkPolicy
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cilium-blocklist-sync-sa
  namespace: envoy-gateway-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cilium-blocklist-sync-role
rules:
  - apiGroups: ["cilium.io"]
    resources: ["ciliumclusterwidenetworkpolicies"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cilium-blocklist-sync-binding
subjects:
  - kind: ServiceAccount
    name: cilium-blocklist-sync-sa
    namespace: envoy-gateway-system
roleRef:
  kind: ClusterRole
  name: cilium-blocklist-sync-role
  apiGroup: rbac.authorization.k8s.io

```

### Advantages of the Rust Approach

1. **Memory Aggregation (`ipnet::IpNet::aggregate`):** Rust handles the sorting and merging of contiguous CIDRs natively in memory in a fraction of a millisecond.
2. **Native K8s API Client (`kube-rs`):** It communicates directly with the Kubernetes API Server via Server-Side Apply (SSA) rather than shelling out to `kubectl`.
3. **Hardened Security:** Runs as a non-root user (`65534`) inside a scratch image with zero shell binaries or utilities to exploit.

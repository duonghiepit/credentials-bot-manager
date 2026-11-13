# Credentials Bot Manager

**Cloud-Native Platform & Secrets Orchestrator** for Kubernetes Multi-Cluster HashiCorp Vault Integration, External Secrets Operator (ESO), and Secrets Store CSI Driver.

---

## 1. Overview

`credentials-bot-manager` acts as the operational orchestrator bridging **Kubernetes clusters**, **GitOps registries**, and **HashiCorp Vault**:

1. **Zero-Secret Cluster Join Handshake (`cluster join`):**
   - Automatically bootstraps the TokenReviewer ServiceAccount and RBAC on satellite Kubernetes clusters.
   - Extracts ServiceAccount tokens and CA certificates strictly in-memory.
   - Configures Vault Kubernetes Auth Backends directly via runtime API (`POST /v1/auth/<cluster>-kubernetes/config`).
   - **Guarantees ZERO secrets, tokens, or cluster credentials stored in Git.**

2. **Secret Orchestration & Classification (`secret sync`):**
   - Reads declarative GitOps registry YAML files (`registry/clusters/<cluster>/<namespace>.yaml`).
   - Intelligently classifies secrets into:
     - **External Secrets (`secrets.es`):** Synchronizes into Native K8s Secrets (for microservices consuming environment variables).
     - **CSI Driver (`secrets.csi`):** Generates `SecretProviderClass` for RAM tmpfs mounts (Zero etcd footprint for PCI-DSS/banking workloads).
   - Automatically provisions namespaced `SecretStore` according to the **Principle of Least Privilege (PoLP)**.

---

## 2. CLI Usage

### 2.1. Cluster Join Handshake

Join a new satellite cluster to central Vault:

```bash
credentials-bot-manager cluster join \
  --cluster app-cluster \
  --kubeconfig ~/.kube/config \
  --context k3d-app-cluster \
  --vault-addr http://127.0.0.1:8200 \
  --vault-token "$VAULT_ADMIN_TOKEN"
```

Preview without making changes:
```bash
credentials-bot-manager cluster join --cluster app-cluster --dry-run
```

---

### 2.2. Secret Synchronization (ES & CSI)

Synchronize secrets defined in GitOps registry into Kubernetes:

```bash
# Preview generated SecretStore, ExternalSecret, and SecretProviderClass manifests
credentials-bot-manager secret sync \
  --registry ../credentials-registry \
  --cluster app-cluster \
  --dry-run

# Apply live to Kubernetes cluster
credentials-bot-manager secret sync \
  --registry ../credentials-registry \
  --cluster app-cluster \
  --kubeconfig ~/.kube/config \
  --context k3d-app-cluster \
  --vault-server http://vault.external-secrets.svc:8200
```

---

## 3. Development & Build

```bash
# Clean and tidy dependencies
make tidy

# Build local binary
make build

# Run unit tests
make test

# Build container image
make docker-build
```

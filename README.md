# Platform Controller

**Cloud-Native Platform Orchestrator** for Kubernetes Multi-Cluster HashiCorp Vault Integration, External Secrets Operator (ESO), and Secrets Store CSI Driver.

---

## 1. Overview

`platform-controller` acts as the operational orchestrator bridging **Kubernetes clusters**, **GitOps registries**, and **HashiCorp Vault**:

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
platform-controller cluster join \
  --cluster app-cluster \
  --kubeconfig ~/.kube/config \
  --context k3d-app-cluster \
  --vault-addr http://127.0.0.1:8200 \
  --vault-token "$VAULT_ADMIN_TOKEN"
```

Preview without making changes:
```bash
platform-controller cluster join --cluster app-cluster --dry-run
```

---

### 2.2. Secret Synchronization (ES & CSI)

Synchronize secrets defined in GitOps registry into Kubernetes:

```bash
# Preview generated SecretStore, ExternalSecret, and SecretProviderClass manifests
platform-controller secret sync \
  --registry ../vault-as-code/registry \
  --cluster app-cluster \
  --dry-run

# Apply live to Kubernetes cluster
platform-controller secret sync \
  --registry ../vault-as-code/registry \
  --cluster app-cluster \
  --kubeconfig ~/.kube/config \
  --context k3d-app-cluster \
  --vault-server http://vault.external-secrets.svc:8200
```

---

## 3. Registry Schema Specification

Namespace definition file: `registry/clusters/<cluster>/<namespace>.yaml`:

```yaml
editors:
  - dev.user
viewers:
  - qa.user

secrets:
  # External Secrets Operator (synced to Native K8s Secret in etcd)
  es:
    - app_config
    - redis

  # Secrets Store CSI Driver (RAM tmpfs mount only, zero etcd)
  csi:
    - payment_gateway
    - database
```

> **Backward Compatibility:** If `secrets` is provided as a simple list `[item1, item2]`, it is automatically treated as `es` secrets.

---

## 4. Build & Development (Dockerized)

No local Go installation required. Build directly via Docker:

```bash
# Resolve dependencies
make tidy

# Build local binary (bin/platform-controller)
make build

# Build minimal container image (~20MB)
make docker-build
```

---

## 5. Security Principles

- **Zero Secrets in Git:** TokenReviewer JWTs and CA certificates are never written to repository files or disk.
- **Least Privilege (PoLP):** Every namespace receives a dedicated `SecretStore` bound to its own ServiceAccount role (`r-<cluster>-<namespace>`). Cross-namespace secret access is strictly blocked with HTTP 403.
- **Decoupled Architecture:** Vault core configuration is managed via Terraform, while Kubernetes client synchronization is orchestrated dynamically by `platform-controller`.

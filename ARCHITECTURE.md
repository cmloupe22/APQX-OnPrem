# Architecture Documentation

## Overview

The APQX GitOps Platform is a production-ready, cloud-native application deployment demonstrating modern DevOps practices, GitOps principles, and security-first design. It simulates an on-premises deployment with local container registry and optional secure remote access via Tailscale.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Developer Workflow                      │
└─────────────────────────────────────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   GitHub Repository      │
                    │  ┌─────────────────┐   │
                    │  │  Application    │   │
                    │  │  Code (Flask)   │   │
                    │  └─────────────────┘   │
                    │  ┌─────────────────┐   │
                    │  │  GitOps         │   │
                    │  │  Manifests      │   │
                    │  └─────────────────┘   │
                    └──────┬──────────────────┘
                           │
                           │ Pull/Clone
                           │
                 ┌─────────▼─────────────┐
                 │  k3d Cluster          │
                 │  ┌─────────────────┐  │
                 │  │ Local Registry  │  │
                 │  │   :5000         │  │
                 │  └────────┬────────┘  │
                 │           │            │
                 │  ┌────────▼────────┐  │
                 │  │  ArgoCD         │  │
                 │  │  (GitOps)       │  │
                 │  └────────┬────────┘  │
                 │           │            │
                 │  ┌────────▼────────┐  │
                 │  │  Traefik        │  │
                 │  │  (Ingress)      │  │
                 │  │  + cert-manager │  │
                 │  └────────┬────────┘  │
                 │           │            │
                 │  ┌────────▼────────┐  │
                 │  │  Sample App     │  │
                 │  │  - Deployment   │  │
                 │  │  - Service      │  │
                 │  │  - HPA          │  │
                 │  │  - PDB          │  │
                 │  └─────────────────┘  │
                 └───────────┬────────────┘
                             │
          ┌──────────────────┴──────────────────┐
          │                                     │
┌─────────▼────────────┐           ┌───────────▼──────────┐
│  Local Access        │           │  Tailscale (Optional)│
│  HTTP/HTTPS          │           │  Secure Remote       │
│  127.0.0.1:8080/8443 │           │  Access              │
└──────────────────────┘           └──────────────────────┘
```

## Component Choices & Rationale

### 1. Kubernetes Distribution: k3d

**Choice**: k3d (k3s in Docker)

**Rationale**:
-  **Lightweight**: Runs entirely in Docker containers
-  **Fast**: Cluster creation in <30 seconds
-  **Cross-platform**: Works on macOS, Linux, and Windows
-  **Reproducible**: Consistent behavior across environments
-  **Production-like**: Uses k3s, deployed in edge/IoT environments
-  **Built-in registry**: Simulates on-prem container registry

**Configuration**:
```yaml
Cluster: apqx-platform
  - Server nodes: 1
  - Agent nodes: 2
  - Registry: apqx-platform-registry:5000
  - API Port: 6443
  - HTTP Port: 8080
  - HTTPS Port: 8443
```

**Alternatives Considered**:
- **kind**: Similar, but k3d has better registry integration
- **minikube**: Slower startup, more resource-intensive

### 2. Container Registry: Local k3d Registry

**Choice**: Built-in k3d registry

**Rationale**:
-  **On-prem simulation**: Mimics air-gapped environments
-  **Fast**: No internet required for image pulls
-  **Integrated**: Automatic DNS resolution in cluster
-  **Simple**: No authentication needed for local dev
-  **Realistic**: Represents corporate registry setup

**Configuration**:
```
Registry: apqx-platform-registry:5000
Access: localhost:5000 (from host)
        apqx-platform-registry:5000 (from cluster)
```

**CI/CD Note**: GitHub Actions builds and validates images locally. In production, this would push to corporate registry (Harbor, Artifactory, etc.)

### 3. GitOps: Argo CD

**Choice**: Argo CD

**Rationale**:
-  **Declarative**: Git as single source of truth
-  **Self-healing**: Automatically syncs to desired state
-  **Web UI**: Visual dashboard for deployments
-  **Health assessment**: Understands Kubernetes resource health
-  **Multi-tenancy**: RBAC and project isolation

**Configuration**:
```yaml
Sync Policy:
  - Automated: true
  - Self-heal: true
  - Prune: true
Applications:
  - sample-app
  - traefik
  - cert-manager
  - tailscale-operator (optional)
```

**Alternatives Considered**:
- **Flux CD**: More lightweight, but less mature UI
- **Manual kubectl**: Doesn't scale, no audit trail

### 4. Ingress Controller: Traefik

**Choice**: Traefik v2

**Rationale**:
- **Automatic discovery**: No manual ingress configuration
- **Modern**: Built for cloud-native environments
- **Lightweight**: Lower resource footprint than NGINX
- **TLS**: Automatic cert-manager integration
- **Metrics**: Built-in Prometheus endpoints

**Configuration**:
```yaml
Entrypoints:
  - web (HTTP): 8080
  - websecure (HTTPS): 8443
IngressClass: traefik
TLS: cert-manager integration
```

**Alternatives Considered**:
- **NGINX Ingress**: More mature, but heavier
- **Envoy**: More complex configuration

### 5. Certificate Management: cert-manager

**Choice**: cert-manager

**Rationale**:
- **Automatic TLS**: Self-signed certificates for local dev
- **Kubernetes-native**: CRD-based configuration
- **Certificate rotation**: Automatic renewal

**Configuration**:
```yaml
ClusterIssuer: selfsigned-issuer
Certificate: sample-app-tls
  - Duration: 8760h (1 year)
  - RenewBefore: 720h (30 days)
```

### 6. DNS Solution: sslip.io

**Choice**: sslip.io magic DNS

**Rationale**:
- **Zero configuration**: No setup required
- **Wildcard support**: `*.127.0.0.1.sslip.io` → `127.0.0.1`
- **No /etc/hosts editing**: Works immediately
- **Works offline**: No external DNS required

**How it works**:
```
app.127.0.0.1.sslip.io → 127.0.0.1
```

### 7. Remote Access: Tailscale (Optional)

**Choice**: Tailscale

**Rationale**:
- **Secure**: WireGuard-based VPN
- **Simple**: No port forwarding needed
- **MagicDNS**: Friendly hostnames
- **Cross-platform**: Works everywhere
- **Free**: For personal/small team use

**Access**:
```
Local:  http://app.127.0.0.1.sslip.io:8080
Remote: http://sample-app.<tailnet>.ts.net
```

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────┐
│ 1. CI Pipeline Validation                  │
│    - Pytest tests                           │
│    - Trivy vulnerability scanning           │
│    - Manifest validation                    │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│ 2. Image Security                          │
│    - Multi-stage builds                     │
│    - Minimal base (Python 3.11-slim)        │
│    - No root user                           │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│ 3. Pod Security Standards                  │
│    - runAsNonRoot: true                     │
│    - readOnlyRootFilesystem: false          │
│    - capabilities: drop [ALL]               │
│    - seccompProfile: RuntimeDefault         │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│ 4. RBAC (Least Privilege)                  │
│    - Dedicated ServiceAccount               │
│    - Minimal Role permissions               │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│ 5. Network Security                        │
│    - TLS via cert-manager                   │
│    - Tailscale encryption (optional)        │
└─────────────────────────────────────────────┘
```

### Security Features Implemented

#### 1. Container Security
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault
containers:
  securityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: false
    capabilities:
      drop: [ALL]
```

#### 2. RBAC Configuration
```yaml
ServiceAccount: sample-app
Role: Minimal permissions
  - pods: get, list
  - services: get
```

#### 3. Image Security
- **Multi-stage builds**: Separate build and runtime
- **Vulnerability scanning**: Trivy in CI pipeline
- **Minimal base images**: Python 3.11-slim
- **Platform detection**: Builds for arm64/amd64

## SRE & Operability

### Reliability Features

#### 1. High Availability
```yaml
replicas: 2
PodDisruptionBudget:
  minAvailable: 1
topologySpreadConstraints:
  maxSkew: 1
  topologyKey: kubernetes.io/hostname
```

#### 2. Auto-scaling
```yaml
HorizontalPodAutoscaler:
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - CPU: 70%
    - Memory: 80%
```

**Note**: Metrics may show `<unknown>` in k3d without metrics-server.

#### 3. Health Checks
```yaml
livenessProbe:
  httpGet: /health
  initialDelaySeconds: 30
  
readinessProbe:
  httpGet: /ready
  initialDelaySeconds: 10
  
startupProbe:
  httpGet: /health
  failureThreshold: 30
```

#### 4. Resource Management
```yaml
resources:
  requests:
    memory: 128Mi
    cpu: 100m
  limits:
    memory: 256Mi
    cpu: 500m
```

### Observability

#### 1. Metrics
- **Application**: `/metrics` endpoint
- **Annotations**: `prometheus.io/scrape: "true"`

#### 2. Logging
- **Structured JSON logging**
- **Downward API**: Pod metadata in logs

```python
{
  "app_name": "apqx-sample-app",
  "pod": {
    "name": "sample-app-xxx",
    "namespace": "sample-app",
    "node": "k3d-server-0"
  }
}
```

## Deployment Architecture

### GitOps Workflow

```
1. Dev commits code to GitHub
   ↓
2. CI pipeline runs (test + scan)
   ↓
3. Image built and pushed to local registry
   ↓
4. GitOps manifests stored in git
   ↓
5. ArgoCD detects changes
   ↓
6. ArgoCD syncs to cluster
   ↓
7. Rolling update (zero downtime)
   ↓
8. Application accessible via Ingress
```

### Zero-Downtime Deployments

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 1
    maxUnavailable: 0
```

**Process**:
1. New pod (v2) created
2. Readiness probe passes
3. Added to service endpoints
4. Old pod (v1) terminated
5. Repeat for all replicas

## Networking

### Traffic Flow

```
External Request
      ↓
app.127.0.0.1.sslip.io:8080
      ↓
k3d LoadBalancer
      ↓
Traefik Ingress Controller
      ↓
sample-app Service (ClusterIP)
      ↓
Pod Endpoints (via readiness probe)
      ↓
Flask Application (port 8080)
```

### Service Types

- **sample-app**: ClusterIP (internal only)
- **sample-app-tailscale**: LoadBalancer (Tailscale)
- **traefik**: LoadBalancer (k3d ports)

## Disaster Recovery

### Backup Strategy

1. **Git is source of truth**
   - All manifests versioned
   - Easy rollback via Git

2. **Cluster Recreation**
   ```bash
   make down    # Destroy
   make up      # Recreate
   ```

3. **Stateless Design**
   - No persistent data
   - Fast recovery


### Core Operations

```bash
make up              # Bootstrap entire platform
make down            # Destroy platform
make restart         # Restart platform
make status          # Show status
make app-test        # Test application
```

### ArgoCD

```bash
make argocd-ui       # Open ArgoCD UI
make argocd-password # Get admin password
make argocd-sync     # Sync applications
```

### Tailscale

```bash
make tailscale-setup  # Setup Tailscale
make tailscale-status # Check status
make tailscale-clean  # Remove Tailscale
```

## Production Considerations

### What Changes for Production?

1. **Registry**:
   - Local → Corporate registry (Harbor, Artifactory)
   - Add image pull secrets
   - Implement image signing

2. **Certificates**:
   - Self-signed → Let's Encrypt/Corporate
   - Configure ACME issuer

3. **Monitoring**:
   - Add Prometheus + Grafana
   - Set up alerting rules
   - Implement log aggregation

4. **Security**:
   - Add NetworkPolicies
   - Implement OPA/Kyverno policies
   - External secrets management
   - Pod Security Admission

5. **Scaling**:
   - Add metrics-server
   - Configure VPA
   - Implement cluster autoscaling

6. **Multi-cluster**:
   - ArgoCD manages multiple clusters
   - Disaster recovery automation
   - Blue/green deployments

## Future Enhancements

### Implemented
- [x] k3d local cluster
- [x] ArgoCD GitOps
- [x] Traefik ingress
- [x] cert-manager TLS
- [x] HPA configuration
- [x] Security hardening
- [x] Tailscale integration

## References

- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
- [Argo CD Documentation](https://argo-cd.readthedocs.io/)
- [OWASP Kubernetes Security](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
- [GitOps Principles](https://opengitops.dev/)
- [Tailscale Kubernetes Operator](https://tailscale.com/kb/1236/kubernetes-operator)
- [k3d Documentation](https://k3d.io/)
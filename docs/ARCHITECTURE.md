# Architecture Documentation

## Overview

The APQX GitOps Platform demonstrates a production-ready, cloud-native application deployment using modern DevOps practices, GitOps principles, and security-first design.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Developer Workflow                       │
└─────────────────────────────────────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   GitHub Repository      │
                    │  ┌─────────────────┐   │
                    │  │  Application    │   │
                    │  │  Code (Python)  │   │
                    │  └─────────────────┘   │
                    │  ┌─────────────────┐   │
                    │  │  GitOps         │   │
                    │  │  Manifests      │   │
                    │  └─────────────────┘   │
                    └──────┬──────────┬───────┘
                           │          │
              ┌────────────▼──┐  ┌───▼──────────────┐
              │  GitHub       │  │  Argo CD         │
              │  Actions      │  │  (GitOps)        │
              │  (CI/CD)      │  │                  │
              └───────┬───────┘  └────────┬─────────┘
                      │                   │
        ┌─────────────▼──────┐           │
        │  Build & Security  │           │
        │  - Build Image     │           │
        │  - Run Tests       │           │
        │  - Scan (Trivy)    │           │
        │  - Push to GHCR    │           │
        └─────────┬──────────┘           │
                  │                       │
                  │   Update GitOps       │
                  └──────────┬────────────┘
                             │
                 ┌───────────▼────────────┐
                 │  k3d Cluster (Docker)  │
                 │  ┌──────────────────┐  │
                 │  │  Traefik         │  │
                 │  │  (Ingress)       │  │
                 │  └─────────┬────────┘  │
                 │            │            │
                 │  ┌─────────▼────────┐  │
                 │  │  Sample App      │  │
                 │  │  - Deployment    │  │
                 │  │  - Service       │  │
                 │  │  - HPA           │  │
                 │  │  - PDB           │  │
                 │  └──────────────────┘  │
                 └─────────────────────────┘
                             │
                 ┌───────────▼────────────┐
                 │  External Access       │
                 │  app.127.0.0.1.sslip.io│
                 └────────────────────────┘
```

## Component Choices & Rationale

### 1. Kubernetes Distribution: k3d

**Choice**: k3d (k3s in Docker)

**Rationale**:
- ✅ **Lightweight**: Runs entirely in Docker containers
- ✅ **Fast**: Cluster creation in <30 seconds
- ✅ **Cross-platform**: Works identically on macOS, Linux, and Windows (WSL2)
- ✅ **Reproducible**: Consistent behavior across environments
- ✅ **Production-like**: Uses the same k3s distribution used in edge/IoT deployments
- ✅ **Local registry**: Built-in registry support for faster iteration

**Alternatives Considered**:
- **kind**: Similar, but k3d has better registry support
- **MicroK8s**: More production-focused, heavier weight
- **minikube**: Slower startup, more resource-intensive

### 2. Ingress Controller: Traefik

**Choice**: Traefik v2

**Rationale**:
- ✅ **Native k3d support**: Comes pre-configured with k3d
- ✅ **Automatic service discovery**: No manual configuration needed
- ✅ **Modern**: Built for cloud-native environments
- ✅ **Lightweight**: Lower resource footprint than NGINX
- ✅ **HTTP/2 & gRPC**: Native support
- ✅ **Metrics**: Built-in Prometheus metrics
- ✅ **Let's Encrypt**: Easy TLS certificate management

**Configuration**:
```yaml
Ports:
  - HTTP: 8080 → 80
  - HTTPS: 8443 → 443
  - Metrics: 9100
```

**Alternatives Considered**:
- **NGINX Ingress**: More mature, but heavier
- **HAProxy**: Less Kubernetes-native
- **Envoy**: More complex configuration

### 3. GitOps: Argo CD

**Choice**: Argo CD

**Rationale**:
- ✅ **Declarative**: True GitOps - Git as single source of truth
- ✅ **Self-healing**: Automatically syncs to desired state
- ✅ **Web UI**: Visual dashboard for deployments
- ✅ **RBAC**: Fine-grained access control
- ✅ **Multi-cluster**: Can manage multiple clusters
- ✅ **Health assessment**: Understands Kubernetes resource health
- ✅ **Sync waves**: Ordered deployment of resources

**Configuration**:
```yaml
Sync Policy:
  - Automated: true
  - Self-heal: true
  - Prune: true (removes orphaned resources)
```

**Alternatives Considered**:
- **Flux CD**: More lightweight, but less mature UI
- **Jenkins X**: Too heavyweight for this use case

### 4. DNS Solution: sslip.io

**Choice**: sslip.io magic DNS

**Rationale**:
- ✅ **No configuration**: Zero setup required
- ✅ **Wildcard support**: `*.127.0.0.1.sslip.io` → `127.0.0.1`
- ✅ **No /etc/hosts editing**: Works immediately
- ✅ **Works offline**: No external DNS required
- ✅ **Free**: No cost or registration

**How it works**:
```
app.127.0.0.1.sslip.io → DNS resolves to 127.0.0.1
```

**Stretch Goal**: Tailscale for remote access
- Uses Tailscale MagicDNS
- Provides `app.<hostname>.ts.net` addresses
- Secure remote access without exposing ports

### 5. Container Registry: GitHub Container Registry (GHCR)

**Choice**: GitHub Container Registry

**Rationale**:
- ✅ **Free**: Unlimited public images
- ✅ **Integrated**: Part of GitHub ecosystem
- ✅ **OCI-compliant**: Standard container registry
- ✅ **Fine-grained tokens**: Secure access control
- ✅ **No rate limits**: Unlike Docker Hub

**Image Naming**:
```
ghcr.io/<username>/sample-app:<tag>
ghcr.io/<username>/sample-app@sha256:<digest>
```

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────┐
│ 1. Image Scanning (Trivy)                  │
│    - CVE detection before deployment        │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│ 2. Image Signing & Digest Pinning          │
│    - Immutable references                   │
│    - No :latest tags in production          │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│ 3. Pod Security Standards                  │
│    - Non-root containers                    │
│    - Read-only root filesystem              │
│    - Drop all capabilities                  │
│    - seccomp profiles                       │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│ 4. RBAC (Least Privilege)                  │
│    - Dedicated ServiceAccount               │
│    - Minimal Role permissions               │
│    - No default ServiceAccount              │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│ 5. Network Policies (Optional)             │
│    - Restrict pod-to-pod communication      │
│    - Allow only necessary egress            │
└─────────────────────────────────────────────┘
```

### Security Features Implemented

#### 1. Container Security
```dockerfile
# Non-root user
USER 1000

# Read-only root filesystem
readOnlyRootFilesystem: true

# Drop all capabilities
capabilities:
  drop: [ALL]

# Seccomp profile
seccompProfile:
  type: RuntimeDefault
```

#### 2. RBAC Configuration
```yaml
ServiceAccount: sample-app
Role: Read-only access to own namespace
  - pods: get, list
  - services: get, list
  - configmaps: get
```

#### 3. Image Security
- **Digest pinning**: All images referenced by SHA256 digest
- **Vulnerability scanning**: Trivy scans in CI pipeline
- **Minimal base images**: Python 3.11-slim (CVE surface reduction)
- **Multi-stage builds**: Separate build and runtime layers

#### 4. Secrets Management
- Kubernetes Secrets (base64 encoded)
- No plaintext secrets in Git
- Future: External secrets operator integration

## SRE & Operability

### Reliability Features

#### 1. High Availability
```yaml
replicas: 2                    # Multiple instances
PodDisruptionBudget:
  minAvailable: 1              # Always 1 pod running
topologySpreadConstraints:     # Spread across nodes
  maxSkew: 1
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

#### 3. Health Checks
```yaml
livenessProbe:               # Restart unhealthy pods
  httpGet: /health
  
readinessProbe:              # Remove from service when not ready
  httpGet: /ready
  
startupProbe:                # Handle slow starts
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

### Observability Stack

#### 1. Metrics
- **Application**: `/metrics` endpoint (Prometheus format)
- **Traefik**: Built-in metrics endpoint
- **Annotations**: `prometheus.io/scrape: "true"`

#### 2. Logging
- **Structured JSON logging** in application
- **Access logs** via Traefik
- **kubectl logs** for debugging

#### 3. Tracing (Future)
- OpenTelemetry integration
- Distributed tracing with Jaeger

## CI/CD Pipeline

### Pipeline Stages

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Test    │ → │  Build   │ → │  Scan    │ → │  Deploy  │
│          │    │          │    │          │    │          │
│ pytest   │    │ Docker   │    │ Trivy    │    │ GitOps   │
│ coverage │    │ buildx   │    │ Checkov  │    │ Update   │
└──────────┘    └──────────┘    └──────────┘    └──────────┘
```

### Pipeline Features

1. **Automated Testing**
   - Unit tests with pytest
   - Coverage reporting
   - Test on every PR

2. **Container Building**
   - Multi-platform support (amd64, arm64)
   - Layer caching for speed
   - Semantic versioning

3. **Security Scanning**
   - **Trivy**: Container vulnerability scanning
   - **Checkov**: IaC security scanning
   - **TruffleHog**: Secret detection
   - Results uploaded to GitHub Security

4. **GitOps Update**
   - Automatic manifest updates
   - Digest-based image references
   - Commit and push to trigger sync

## Deployment Flow

### Developer Workflow

```
1. Developer pushes code to GitHub
   ↓
2. GitHub Actions triggered
   ↓
3. Tests run (pytest)
   ↓
4. Image built and pushed to GHCR
   ↓
5. Image scanned (Trivy)
   ↓
6. GitOps manifest updated with new digest
   ↓
7. Argo CD detects change
   ↓
8. Argo CD syncs to cluster
   ↓
9. Rolling update (zero downtime)
   ↓
10. Application accessible via Ingress
```

### Zero-Downtime Deployments

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 1           # One extra pod during update
    maxUnavailable: 0     # Never go below desired count
```

**Flow**:
1. New pod created (v2)
2. Wait for readiness probe (v2)
3. Add to service endpoints (v2)
4. Terminate old pod (v1)
5. Repeat for remaining pods

## Networking

### Traffic Flow

```
External Request
      ↓
app.127.0.0.1.sslip.io:8080
      ↓
Traefik LoadBalancer (k3d)
      ↓
Traefik Ingress Controller
      ↓
sample-app Service (ClusterIP)
      ↓
Pod endpoints (via readiness probe)
      ↓
Flask application (port 8080)
```

### Service Mesh (Future)

- **Linkerd** or **Istio** for:
  - mTLS between services
  - Advanced traffic management
  - Observability improvements

## Disaster Recovery

### Backup Strategy

1. **Git is the source of truth**
   - All manifests in version control
   - Easy rollback via Git

2. **Cluster Recreation**
   ```bash
   make down    # Destroy cluster
   make up      # Recreate everything
   ```

3. **State Management**
   - Stateless application design
   - No persistent volumes (yet)

### Rollback Procedure

```bash
# Argo CD rollback
kubectl argo rollout undo deployment/sample-app -n sample-app

# Git rollback
git revert <commit-sha>
git push
```

## Monitoring & Alerting (Future)

### Metrics to Monitor

1. **Application Metrics**
   - Request rate
   - Response time (p50, p95, p99)
   - Error rate (5xx responses)

2. **Infrastructure Metrics**
   - CPU/Memory usage
   - Pod restart count
   - HPA scaling events

3. **Business Metrics**
   - User activity
   - API call patterns

### Alerting Rules (Example)

```yaml
- alert: HighErrorRate
  expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
  
- alert: PodCrashLooping
  expr: rate(kube_pod_container_status_restarts_total[15m]) > 0
```

## Cost Optimization

### Resource Efficiency

1. **Right-sizing**
   - Start with minimal requests
   - Monitor actual usage
   - Adjust based on metrics

2. **Auto-scaling**
   - Scale down during low traffic
   - Scale up during high traffic

3. **Spot Instances** (Production)
   - Use for non-critical workloads
   - Implement pod disruption budgets

## Future Enhancements

### Phase 1 (Short-term)
- [ ] cert-manager for automatic TLS
- [ ] Kyverno for policy enforcement
- [ ] External Secrets Operator
- [ ] Tailscale integration

### Phase 2 (Medium-term)
- [ ] Prometheus + Grafana stack
- [ ] Loki for log aggregation
- [ ] Argo Rollouts for progressive delivery
- [ ] Service mesh (Linkerd)

### Phase 3 (Long-term)
- [ ] Multi-cluster setup
- [ ] Disaster recovery automation
- [ ] Cost optimization tools
- [ ] Chaos engineering (Chaos Mesh)

## References

- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
- [Argo CD Documentation](https://argo-cd.readthedocs.io/)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
- [12-Factor App Methodology](https://12factor.net/)
- [GitOps Principles](https://opengitops.dev/)

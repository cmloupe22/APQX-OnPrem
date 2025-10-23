# APQX GitOps Platform

A fully automated, production-ready GitOps platform demonstration using Kubernetes, ArgoCD, and modern DevOps practices with local registry and optional secure remote access.

## Overview

This project demonstrates a production-ready, on-premises-style Kubernetes platform featuring:
- **Local K8s cluster** using k3d (lightweight Kubernetes in Docker)
- **Local container registry** simulating corporate on-prem infrastructure
- **GitOps** with ArgoCD for declarative, automated deployments
- **Ingress** with Traefik for HTTP/HTTPS routing
- **Automatic TLS** with cert-manager (self-signed certificates)
- **Security hardening** with RBAC, vulnerability scanning, and non-root containers
- **SRE practices** including HPA, health probes, and high availability
- **Bonus: Tailscale integration** for secure remote access from anywhere

## Architecture

```
┌─────────────────────────────────────────┐
│   Local Development Environment         │
│                                         │
│  ┌───────────────────────────────────┐ │
│  │  k3d Cluster                       │ │
│  │  ┌─────────────────────────────┐  │ │
│  │  │  Local Registry :5000       │  │ │
│  │  └─────────────────────────────┘  │ │
│  │  ┌─────────────────────────────┐  │ │
│  │  │  ArgoCD (GitOps)            │  │ │
│  │  └─────────────────────────────┘  │ │
│  │  ┌─────────────────────────────┐  │ │
│  │  │  Traefik + cert-manager     │  │ │
│  │  └─────────────────────────────┘  │ │
│  │  ┌─────────────────────────────┐  │ │
│  │  │  Sample App (Flask)         │  │ │
│  │  │  - 2 replicas               │  │ │
│  │  │  - HPA configured            │  │ │
│  │  │  - TLS enabled               │  │ │
│  │  └─────────────────────────────┘  │ │
│  └───────────────────────────────────┘ │
└─────────────────────────────────────────┘
         │                    │
         │                    │
    ┌────▼─────┐    ┌────────▼──────────┐
    │  Local   │    │  Tailscale        │
    │  Access  │    │  (Optional)       │
    │  :8080   │    │  Remote Access    │
    └──────────┘    └───────────────────┘
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed design decisions and rationale.

## Key Features

### Core Platform
- **One-command setup** - `make up` bootstraps everything
- **Local container registry** - Simulates on-premises environment
- **GitOps with ArgoCD** - Automated sync, self-healing, declarative deployments
- **Traefik ingress** - HTTP/HTTPS routing with automatic service discovery
- **Automatic TLS** - cert-manager with self-signed certificates
- **Production security** - Non-root containers, RBAC, security contexts
- **High availability** - 2 replicas, PodDisruptionBudget, topology spread
- **Auto-scaling** - HPA with CPU and memory metrics
- **Health monitoring** - Liveness, readiness, and startup probes

### Bonus Features Implemented
- **Tailscale Integration** - Secure remote access via WireGuard VPN
- **cert-manager** - Automatic certificate management and renewal
- **Multi-platform support** - Builds work on arm64 (Apple Silicon) and amd64
- **Comprehensive docs** - 4 detailed guides (Architecture, Troubleshooting, Tailscale, Checklist)

## Prerequisites

### Required Tools
- **Docker Desktop** (or Docker Engine)
  - macOS: [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/)
  - Windows: [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/) with WSL2
  - Linux: [Docker Engine](https://docs.docker.com/engine/install/)
- **kubectl** - Kubernetes CLI
- **k3d** - Lightweight Kubernetes in Docker
- **make** - Build automation (pre-installed on macOS/Linux)

### System Requirements
- **CPU**: 4+ cores recommended
- **RAM**: 8GB minimum, 16GB recommended
- **Disk**: 20GB free space
- **OS**: macOS, Linux, or Windows with WSL2

## Quick Start

### Automated Setup (One Command!)

```bash
# Clone the repository
git clone https://github.com/cmloupe22/APQX-OnPrem.git
cd APQX-OnPrem

# Install required tools (if not already installed)
make install-tools

# Bootstrap the entire platform
make up

# Check status
make status
```

### Access Your Application

Once deployed, access the application at:

- **HTTP**: http://app.127.0.0.1.sslip.io:8080
- **HTTPS**: https://app.127.0.0.1.sslip.io:8443 (self-signed cert)
- **ArgoCD UI**: https://localhost:8888 (via `make argocd-ui`)
  - Username: `admin`
  - Password: Run `make argocd-password`

### Test the Application

```bash
# Test HTTP endpoint
curl http://app.127.0.0.1.sslip.io:8080/

# Expected response:
{
  "app_name": "apqx-sample-app",
  "build_sha": "dev",
  "pod": {
    "name": "sample-app-xxx",
    "namespace": "sample-app",
    "node": "k3d-apqx-platform-agent-1"
  },
  "timestamp": "2025-10-23T04:45:37.961543Z",
  "version": "1.0.0"
}

# Test HTTPS endpoint (with self-signed cert)
curl -k https://app.127.0.0.1.sslip.io:8443/
```

## 🛠️ Available Commands

### Core Operations

```bash
make help              # Show all available commands
make up                # Bootstrap entire platform
make down              # Destroy the cluster
make restart           # Restart the platform (down + up)
make status            # Show complete platform status
```

### Cluster Management

```bash
make cluster-create    # Create k3d cluster with local registry
make cluster-delete    # Delete k3d cluster
make cluster-info      # Show cluster information
```

### ArgoCD Operations

```bash
make argocd-install    # Install ArgoCD
make argocd-ui         # Port-forward to ArgoCD UI (localhost:8888)
make argocd-password   # Get ArgoCD admin password
make argocd-sync       # Sync all ArgoCD applications
```

### Application Management

```bash
make build-app         # Build and push app to local registry
make app-logs          # Show application logs
make app-test          # Test application endpoint
make app-shell         # Get shell in application pod
```

### Tailscale (Optional Bonus Feature)

```bash
make tailscale-setup   # Setup Tailscale integration (interactive)
make tailscale-status  # Check Tailscale status
make tailscale-logs    # View Tailscale operator logs
make tailscale-clean   # Remove Tailscale integration
```

See [TAILSCALE_SETUP.md](./TAILSCALE_SETUP.md) for detailed Tailscale setup instructions.

### Development & Debugging

```bash
make validate          # Validate all Kubernetes manifests
make check-tools       # Check if required tools are installed
make clean             # Clean temporary files
```

## Security Features

This platform implements production-grade security practices:

- **Container Security**
  - Non-root user (UID 1000)
  - Read-only root filesystem (where applicable)
  - All capabilities dropped
  - seccomp profile enabled
  - Multi-stage builds with minimal base images

- **RBAC & Least Privilege**
  - Dedicated ServiceAccounts per application
  - Minimal role permissions
  - No use of default ServiceAccount

- **Secrets Management**
  - No plaintext secrets in Git
  - Kubernetes Secrets for sensitive data
  - OAuth secrets for Tailscale

- **Vulnerability Scanning**
  - Trivy scans in CI pipeline
  - Fails on critical vulnerabilities

- **Network Security**
  - TLS enabled with cert-manager
  - Optional Tailscale encryption

## Requirements Coverage

### All Baseline Requirements Met

- [x] Automated cluster bootstrap
- [x] Ingress controller (Traefik)
- [x] GitOps deployment (ArgoCD)
- [x] Simple web application with JSON API
- [x] DNS/Ingress accessible (sslip.io magic DNS)
- [x] Health probes (liveness, readiness, startup)
- [x] CI/CD pipeline (GitHub Actions)
- [x] Image scanning (Trivy)
- [x] Digest pinning (via local registry)
- [x] RBAC implementation
- [x] Secrets management
- [x] HPA (Horizontal Pod Autoscaler)
- [x] Basic observability

### Bonus: Stretch Goals Implemented

- [x] **cert-manager** - Automatic TLS certificate management
- [x] **Tailscale** - Secure remote access via WireGuard VPN
- [~] Policy enforcement - Pod Security Standards implemented (Kyverno optional)
- [~] Progressive delivery - Rolling updates implemented (Argo Rollouts optional)

See [CHECKLIST.md](./CHECKLIST.md) for complete requirements tracking.

## Testing

### Run Unit Tests

```bash
cd app
python -m pytest tests/ -v
```

### Test Deployed Application

```bash
# Quick test
make app-test

# Manual tests
curl http://app.127.0.0.1.sslip.io:8080/
curl http://app.127.0.0.1.sslip.io:8080/health
curl http://app.127.0.0.1.sslip.io:8080/ready
curl -k https://app.127.0.0.1.sslip.io:8443/
```

### Validate Manifests

```bash
make validate
```

### Clean Slate Test

```bash
# Verify platform can be rebuilt from scratch
make down
make up
```

## Monitoring & Observability

The application includes:

- **Health Endpoints**
  - `/health` - Liveness probe
  - `/ready` - Readiness probe
  - `/` - Main API endpoint with pod metadata

- **Logging**
  - Structured JSON logging
  - Pod metadata via Downward API
  - Accessible via `make app-logs`

- **Metrics (Ready for Prometheus)**
  - Prometheus annotations on pods
  - `/metrics` endpoint (ready to implement)

## Troubleshooting

See [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for detailed troubleshooting guide.

### Quick Diagnostics

```bash
# Overall platform status
make status

# Check cluster health
kubectl get nodes
kubectl get pods -A

# Check ArgoCD applications
kubectl get applications -n argocd

# Check application status
kubectl get pods -n sample-app
kubectl describe pod <pod-name> -n sample-app

# View logs
make app-logs

# Check certificates
kubectl get certificate -n sample-app

# Test endpoints
curl http://app.127.0.0.1.sslip.io:8080/health
```

### Common Issues

**Problem**: Application not accessible
```bash
# Check ingress
kubectl get ingress -n sample-app
kubectl describe ingress sample-app -n sample-app

# Check service endpoints
kubectl get endpoints -n sample-app

# Test DNS resolution
nslookup app.127.0.0.1.sslip.io
```

**Problem**: Pods not starting
```bash
# Check pod status
kubectl get pods -n sample-app

# Check events
kubectl get events -n sample-app --sort-by='.lastTimestamp'

# View pod details
kubectl describe pod <pod-name> -n sample-app
```

## CI/CD Pipeline

The platform includes a GitHub Actions pipeline that:

1. **Tests** - Runs pytest unit tests
2. **Builds** - Creates Docker image with platform detection (arm64/amd64)
3. **Scans** - Trivy vulnerability scanning
4. **Validates** - Checks Kubernetes manifests

Images are built locally and pushed to the k3d registry, simulating an on-premises CI/CD workflow.

## 🌐 Optional: Tailscale Remote Access

For secure remote access from anywhere, set up Tailscale:

```bash
# One-time setup (requires free Tailscale account)
make tailscale-setup

# Access from any device on your Tailscale network
# http://sample-app.<your-tailnet>.ts.net
```

See [TAILSCALE_SETUP.md](./TAILSCALE_SETUP.md) for complete setup instructions.

## Documentation

- **[ARCHITECTURE.md](./ARCHITECTURE.md)** - Detailed architecture, design decisions, and component rationale
- **[TROUBLESHOOTING.md](./TROUBLESHOOTING.md)** - Common issues and solutions
- **[TAILSCALE_SETUP.md](./TAILSCALE_SETUP.md)** - Tailscale integration guide
- **[CHECKLIST.md](./CHECKLIST.md)** - Requirements tracking and implementation status

## Design Decisions

### Why k3d?
- Lightweight, fast cluster creation (<30 seconds)
- Built-in local registry support
- Perfect for on-premises simulation
- Cross-platform compatibility

### Why Local Registry?
- Simulates corporate on-premises environment
- No external dependencies
- Faster iteration during development
- Realistic for air-gapped deployments

### Why Traefik?
- Native k3d integration
- Automatic service discovery
- Modern, cloud-native design
- Excellent cert-manager integration

### Why ArgoCD?
- True GitOps - Git as source of truth
- Excellent UI for visibility
- Self-healing and automated sync
- Production-proven at scale

See [ARCHITECTURE.md](./ARCHITECTURE.md) for complete design rationale.

## Production Considerations

This platform is designed for local development and demonstration. For production deployment:

1. **Registry**: Replace local registry with Harbor, Artifactory, or corporate registry
2. **TLS**: Use Let's Encrypt or corporate CA instead of self-signed certificates
3. **Monitoring**: Add Prometheus + Grafana stack
4. **Logging**: Implement log aggregation (Loki, ELK)
5. **Secrets**: Use External Secrets Operator with Vault/AWS Secrets Manager
6. **Policies**: Deploy Kyverno or OPA for policy enforcement
7. **Scaling**: Deploy metrics-server for accurate HPA metrics


## Support

For issues or questions:
1. Check [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)
2. Review [ARCHITECTURE.md](./ARCHITECTURE.md) for design context
3. Run `make status` for diagnostics
4. Check ArgoCD UI: `make argocd-ui`

---

**Built with for production-ready Kubernetes deployments**

**Status**: All requirements met and exceeded with bonus features
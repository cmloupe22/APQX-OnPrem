# APQX GitOps Platform

A fully automated, production-ready GitOps platform demonstration using Kubernetes, Argo CD, and modern DevOps practices.

## 🎯 Overview

This project demonstrates an "on-premises-style" Kubernetes platform with:
- **Local K8s cluster** using k3d (Docker-based)
- **GitOps** with Argo CD for declarative deployments
- **Ingress** with Traefik for HTTP/HTTPS routing
- **CI/CD** with GitHub Actions for automated builds and deployments
- **Security** hardening with RBAC, image scanning, and secrets management
- **SRE practices** including HPA, probes, and observability

## 🏗️ Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture diagram and design decisions.

## 📋 Prerequisites

### Required Tools
- **Docker Desktop** (or Docker Engine + Docker Compose)
  - macOS: [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/)
  - Windows: [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/) with WSL2
  - Linux: [Docker Engine](https://docs.docker.com/engine/install/)
- **kubectl** - Kubernetes CLI
- **k3d** - Lightweight Kubernetes in Docker
- **Terraform** - Infrastructure as Code
- **make** - Build automation (pre-installed on macOS/Linux)

### Optional Tools
- **helm** - Kubernetes package manager
- **argocd CLI** - Argo CD CLI (for easier interaction)

### System Requirements
- **CPU**: 4+ cores recommended
- **RAM**: 8GB minimum, 16GB recommended
- **Disk**: 20GB free space
- **OS**: macOS, Linux, or Windows with WSL2

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/apqx-gitops-platform.git
cd apqx-gitops-platform

# Install prerequisites (if not already installed)
make install-tools

# Bootstrap the entire platform
make up

# Access the application
make status
```

The platform will be accessible at:
- **Sample App**: http://app.127.0.0.1.sslip.io:8080
- **Argo CD UI**: https://argocd.127.0.0.1.sslip.io:8443
  - Username: `admin`
  - Password: Get it with `make argocd-password`

### Option 2: Manual Step-by-Step

```bash
# 1. Create k3d cluster
make cluster-create

# 2. Bootstrap Argo CD
make argocd-install

# 3. Deploy applications via GitOps
make gitops-sync

# 4. Check status
make status
```

## 🛠️ Available Commands

```bash
make help              # Show all available commands
make up                # Bootstrap entire platform
make down              # Destroy the cluster
make restart           # Restart the platform (down + up)

make cluster-create    # Create k3d cluster only
make cluster-delete    # Delete k3d cluster only
make cluster-info      # Show cluster information

make argocd-install    # Install Argo CD
make argocd-ui         # Port-forward to Argo CD UI
make argocd-password   # Get Argo CD admin password
make argocd-sync       # Sync all Argo CD applications

make app-logs          # Show application logs
make app-test          # Test application endpoint

make status            # Show complete platform status
make validate          # Validate all configurations
```

## 📦 Project Structure

```
.
├── .github/
│   └── workflows/          # GitHub Actions CI/CD pipelines
├── app/                    # Python web application
│   ├── src/
│   ├── tests/
│   ├── Dockerfile
│   └── requirements.txt
├── docs/                   # Documentation
│   ├── ARCHITECTURE.md
│   └── TROUBLESHOOTING.md
├── gitops/                 # GitOps manifests
│   ├── argocd/            # Argo CD installation
│   ├── apps/              # Application manifests
│   └── system/            # System components
├── infra/                  # Infrastructure automation
│   ├── terraform/         # Terraform configurations
│   └── scripts/           # Helper scripts
├── Makefile               # Build automation
└── README.md              # This file
```

## 🔒 Security Features

- ✅ Container images pinned by digest
- ✅ Image vulnerability scanning (Trivy)
- ✅ RBAC with least privilege ServiceAccounts
- ✅ Secrets management (Kubernetes Secrets, no plaintext)
- ✅ Network policies (optional)
- ✅ Pod Security Standards
- ✅ Non-root containers

## 🎯 Key Features Implemented

### Baseline Requirements
- ✅ Automated cluster bootstrap with k3d
- ✅ Traefik ingress controller configuration
- ✅ Argo CD GitOps deployment
- ✅ Python web app with JSON API
- ✅ Magic DNS with sslip.io
- ✅ Readiness/liveness probes
- ✅ Resource requests/limits
- ✅ GitHub Actions CI/CD pipeline
- ✅ Image scanning and security checks
- ✅ Digest-based image pinning
- ✅ RBAC and least privilege
- ✅ HPA (Horizontal Pod Autoscaler)

### Stretch Goals
- ✅ TLS with cert-manager (self-signed)
- ⏳ Policy enforcement (Kyverno) - optional
- ⏳ Progressive delivery (Argo Rollouts) - optional
- ⏳ Tailscale integration - optional

## 🧪 Testing

```bash
# Run local tests
cd app
python -m pytest tests/

# Test the deployed application
make app-test

# Validate all manifests
make validate
```

## 📊 Monitoring & Observability

The application includes:
- Prometheus-compatible metrics endpoint (`/metrics`)
- Health check endpoints (`/health`, `/ready`)
- Structured JSON logging
- Resource usage annotations

## 🐛 Troubleshooting

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for common issues and solutions.

### Quick Diagnostics

```bash
# Check cluster health
kubectl get nodes
kubectl get pods -A

# Check Argo CD status
kubectl get applications -n argocd

# Check application logs
make app-logs

# Restart the platform
make restart
```

## 🤝 Contributing

This is a take-home project demonstration. Feel free to fork and adapt for your own use!

## 📝 License

MIT License - see LICENSE file for details

## 🙋 Questions?

- Check [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design decisions
- Check [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for common issues
- Review the Makefile for available commands

---

**Built with ❤️ for the APQX Platform Take-Home Challenge**

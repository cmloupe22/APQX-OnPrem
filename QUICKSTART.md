# Quick Start Guide

Get the APQX GitOps Platform running in under 10 minutes!

## Prerequisites Check

Before starting, ensure you have:

- [ ] **Docker Desktop** installed and running
- [ ] **macOS, Linux, or Windows with WSL2**
- [ ] **4GB+ free RAM**
- [ ] **10GB+ free disk space**
- [ ] **Internet connection** (for downloading images)

## Step 1: Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/apqx-gitops-platform.git
cd apqx-gitops-platform
```

## Step 2: Install Prerequisites

### Option A: Automated (Recommended)

```bash
make install-tools
```

This will install:
- kubectl
- k3d  
- helm
- argocd CLI

### Option B: Manual Installation

#### macOS (Homebrew)
```bash
brew install kubectl k3d helm
```

#### Linux
```bash
# kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install kubectl /usr/local/bin/

# k3d
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash

# helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

#### Windows (WSL2)
```bash
# Use Linux instructions above in WSL2
```

**Verify Installation:**
```bash
make check-tools
```

## Step 3: Bootstrap Platform

### One Command Setup

```bash
make up
```

This single command will:
1.  Create k3d cluster with 2 worker nodes
2.  Install Traefik ingress controller
3.  Install Argo CD
4.  Deploy sample application
5.  Configure ingress and DNS

**Expected time:** 3-5 minutes

### What's Happening?

Watch the progress:
```bash
# In another terminal
watch kubectl get pods -A
```

You'll see pods starting in these namespaces:
- `kube-system` - Core Kubernetes components
- `traefik` - Ingress controller
- `argocd` - GitOps controller
- `sample-app` - Your application

## Step 4: Verify Installation

```bash
make status
```

You should see:
- 2-3 nodes ready
- All system pods running
- Argo CD applications synced
- Sample app pods running (2 replicas)

## Step 5: Access Applications

### Sample Application

**URL:** http://app.127.0.0.1.sslip.io:8080

```bash
# Test from command line
curl http://app.127.0.0.1.sslip.io:8080

# Or open in browser
open http://app.127.0.0.1.sslip.io:8080  # macOS
xdg-open http://app.127.0.0.1.sslip.io:8080  # Linux
```

**Expected Response:**
```json
{
  "app_name": "apqx-sample-app",
  "version": "1.0.0",
  "build_sha": "dev",
  "timestamp": "2025-01-15T10:30:00Z",
  "pod": {
    "name": "sample-app-xxx",
    "namespace": "sample-app",
    "node": "k3d-apqx-platform-agent-0"
  }
}
```

### Argo CD UI

**URL:** https://argocd.127.0.0.1.sslip.io:8443

**Username:** `admin`

**Get Password:**
```bash
make argocd-password
```

**Or port-forward:**
```bash
make argocd-ui
# Then open: http://localhost:8888
```

## Step 6: Explore the Platform

### View Logs

```bash
# Application logs
make app-logs

# Argo CD logs
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-server

# All pods
kubectl get pods -A
```

### Test Endpoints

```bash
# Health check
curl http://app.127.0.0.1.sslip.io:8080/health

# Readiness check
curl http://app.127.0.0.1.sslip.io:8080/ready

# Metrics
curl http://app.127.0.0.1.sslip.io:8080/metrics

# Version info
curl http://app.127.0.0.1.sslip.io:8080/version
```

### Monitor Resources

```bash
# Resource usage
kubectl top nodes
kubectl top pods -n sample-app

# Watch pods
watch kubectl get pods -n sample-app

# Check HPA status
kubectl get hpa -n sample-app
```

## Step 7: Make Changes (Optional)

### Update Application Code

1. **Edit the app:**
   ```bash
   vi app/src/app.py
   # Make your changes
   ```

2. **Commit and push:**
   ```bash
   git add app/src/app.py
   git commit -m "feat: update application"
   git push
   ```

3. **GitHub Actions will automatically:**
   - Run tests
   - Build new image
   - Scan for vulnerabilities
   - Update GitOps manifests
   - Trigger Argo CD sync

4. **Watch deployment:**
   ```bash
   kubectl get pods -n sample-app -w
   ```

### Manual Image Build (Local Testing)

```bash
# Build and push to local registry
make dev-build

# Restart deployment
kubectl rollout restart deployment/sample-app -n sample-app

# Watch rollout
kubectl rollout status deployment/sample-app -n sample-app
```

## Common Commands

```bash
# View all commands
make help

# Check status
make status

# Restart platform
make restart

# View app logs
make app-logs

# Test app
make app-test

# Argo CD password
make argocd-password

# Destroy platform
make down
```

## Troubleshooting

### Platform Not Starting?

```bash
# Check Docker is running
docker ps

# Check for port conflicts
lsof -i :8080
lsof -i :8443

# Restart from scratch
make restart
```

### Can't Access Application?

```bash
# Verify pods are running
kubectl get pods -n sample-app

# Check service
kubectl get svc -n sample-app

# Test DNS
nslookup app.127.0.0.1.sslip.io

# Port-forward directly
kubectl port-forward -n sample-app svc/sample-app 8080:80
# Then try: http://localhost:8080
```

### Argo CD Issues?

```bash
# Check Argo CD pods
kubectl get pods -n argocd

# Force sync
kubectl patch application sample-app -n argocd \
  --type merge \
  -p '{"operation":{"sync":{"revision":"HEAD"}}}'

# Access via port-forward
make argocd-ui
```

**For more help:** See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

## Next Steps

### Setup GitHub Actions

1. **Fork the repository** on GitHub

2. **Enable GitHub Packages:**
   - Go to repository Settings
   - Actions → General
   - Workflow permissions: "Read and write permissions"

3. **Update repository URLs:**
   ```bash
   # Update YOUR_USERNAME in these files:
   - .github/workflows/ci-cd.yaml
   - gitops/argocd/applications/sample-app.yaml
   - gitops/apps/sample-app/deployment.yaml (after first build)
   ```

4. **Push changes:**
   ```bash
   git add .
   git commit -m "feat: configure for my repository"
   git push
   ```

5. **Watch GitHub Actions:**
   - Go to repository → Actions tab
   - See your workflow running

### Explore Features

-  **Monitoring:** Check `/metrics` endpoint
-  **Security:** Review RBAC and pod security
-  **Scaling:** Test HPA with load
-  **GitOps:** Make changes via Git
-  **Argo CD:** Explore the UI

### Advanced Topics

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for:
- Detailed component explanations
- Security architecture
- SRE best practices
- Future enhancements

## Cleanup

When you're done:

```bash
# Destroy everything
make down

# Clean Docker resources
docker system prune -af
```

## Getting Help

- **Documentation:** Check [docs/](docs/) folder
- **Troubleshooting:** See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- **Issues:** Open a GitHub issue
- **Commands:** Run `make help`

---

**Congratulations!** You now have a fully functional GitOps platform running locally!

# Troubleshooting Guide

This guide covers common issues and their solutions when working with the APQX GitOps Platform.

## Table of Contents

- [Prerequisites Issues](#prerequisites-issues)
- [Cluster Issues](#cluster-issues)
- [Argo CD Issues](#argo-cd-issues)
- [Application Issues](#application-issues)
- [Networking Issues](#networking-issues)
- [CI/CD Issues](#cicd-issues)
- [General Debugging](#general-debugging)

## Prerequisites Issues

### Docker Not Running

**Symptom**: `Cannot connect to the Docker daemon`

**Solution**:
```bash
# macOS
open -a Docker

# Linux
sudo systemctl start docker

# Windows (WSL2)
# Start Docker Desktop from Windows
```

### Insufficient Resources

**Symptom**: Cluster creation fails or pods crash with OOMKilled

**Solution**:
```bash
# Check Docker resources
docker system df

# Increase Docker resources:
# Docker Desktop → Settings → Resources
# Recommended:
# - CPUs: 4+
# - Memory: 8GB+
# - Disk: 20GB+
```

### Tools Not Found

**Symptom**: `command not found: kubectl` or `command not found: k3d`

**Solution**:
```bash
# Install all tools
make install-tools

# Or check what's missing
make check-tools

# Restart shell after installation
source ~/.bashrc  # or ~/.zshrc
```

## Cluster Issues

### Cluster Won't Create

**Symptom**: `k3d cluster create` hangs or fails

**Diagnosis**:
```bash
# Check Docker is running
docker ps

# Check for port conflicts
lsof -i :6443  # API server
lsof -i :8080  # HTTP ingress
lsof -i :8443  # HTTPS ingress

# Check existing clusters
k3d cluster list
```

**Solution**:
```bash
# Clean up existing cluster
make cluster-delete

# Kill processes using ports
kill -9 <PID>

# Try again
make cluster-create
```

### Cluster Creation Timeout

**Symptom**: Cluster created but nodes not ready

**Diagnosis**:
```bash
# Check node status
kubectl get nodes

# Check system pods
kubectl get pods -n kube-system

# Check events
kubectl get events -A --sort-by='.lastTimestamp'
```

**Solution**:
```bash
# Wait longer (sometimes slow on first start)
kubectl wait --for=condition=Ready nodes --all --timeout=300s

# If still failing, recreate
make restart
```

### Registry Not Accessible

**Symptom**: `Failed to pull image from k3d-apqx-platform-registry:5000`

**Diagnosis**:
```bash
# Check if registry is running
docker ps | grep registry

# Test registry
curl http://localhost:5000/v2/_catalog
```

**Solution**:
```bash
# Recreate cluster with registry
make cluster-delete
make cluster-create

# Verify registry
docker ps | grep registry
```

## Argo CD Issues

### Argo CD Won't Install

**Symptom**: `kubectl apply` fails or pods crashloop

**Diagnosis**:
```bash
# Check Argo CD namespace
kubectl get ns argocd

# Check Argo CD pods
kubectl get pods -n argocd

# Check logs
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-server
```

**Solution**:
```bash
# Delete and reinstall
kubectl delete namespace argocd
make argocd-install

# Wait for all pods to be ready
kubectl wait --for=condition=available --timeout=300s \
  deployment/argocd-server -n argocd
```

### Can't Access Argo CD UI

**Symptom**: Cannot connect to Argo CD web interface

**Diagnosis**:
```bash
# Check Argo CD service
kubectl get svc -n argocd argocd-server

# Check ingress
kubectl get ingress -A

# Try port-forward directly
kubectl port-forward svc/argocd-server -n argocd 8888:443
```

**Solution**:
```bash
# Access via port-forward
make argocd-ui
# Then open: http://localhost:8888

# Or via ingress (if Traefik is running)
# https://argocd.127.0.0.1.sslip.io:8443

# Get password
make argocd-password
```

### Applications Won't Sync

**Symptom**: Argo CD application stuck in "Progressing" or "Degraded"

**Diagnosis**:
```bash
# Check application status
kubectl get applications -n argocd

# Get details
kubectl describe application sample-app -n argocd

# Check Argo CD logs
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-application-controller
```

**Solution**:
```bash
# Force sync
kubectl patch application sample-app -n argocd \
  --type merge \
  -p '{"operation":{"initiatedBy":{"username":"admin"},"sync":{"revision":"HEAD"}}}'

# Or via CLI
argocd app sync sample-app

# Check for manifest errors
kubectl apply --dry-run=client -f gitops/apps/sample-app/
```

### Repository Not Accessible

**Symptom**: `Failed to load live state: repository not accessible`

**Diagnosis**:
```bash
# Check Argo CD can reach GitHub
kubectl exec -n argocd deploy/argocd-repo-server -- \
  git ls-remote https://github.com/YOUR_USERNAME/apqx-gitops-platform.git
```

**Solution**:
```bash
# Update repository URL in application
kubectl edit application sample-app -n argocd

# Or delete and recreate application
kubectl delete application sample-app -n argocd
kubectl apply -f gitops/argocd/applications/sample-app.yaml
```

## Application Issues

### Pods Not Starting

**Symptom**: Pods stuck in `Pending`, `ImagePullBackOff`, or `CrashLoopBackOff`

**Diagnosis**:
```bash
# Check pod status
kubectl get pods -n sample-app

# Describe pod
kubectl describe pod <pod-name> -n sample-app

# Check events
kubectl get events -n sample-app --sort-by='.lastTimestamp'

# Check logs
kubectl logs -n sample-app <pod-name>
```

**Solutions**:

#### ImagePullBackOff
```bash
# Check image name
kubectl get deployment sample-app -n sample-app -o jsonpath='{.spec.template.spec.containers[0].image}'

# Verify image exists
docker pull <image-name>

# Check image pull secrets (if using private registry)
kubectl get secrets -n sample-app
```

#### CrashLoopBackOff
```bash
# Check application logs
make app-logs

# Check for missing dependencies
kubectl exec -n sample-app <pod-name> -- pip list

# Check readiness probe
kubectl describe pod <pod-name> -n sample-app | grep -A 5 "Readiness"
```

#### Pending (Insufficient Resources)
```bash
# Check node resources
kubectl top nodes

# Check pod resource requests
kubectl get pod <pod-name> -n sample-app -o jsonpath='{.spec.containers[0].resources}'

# Reduce requests if needed
kubectl edit deployment sample-app -n sample-app
```

### Application Not Responding

**Symptom**: Service exists but application not accessible

**Diagnosis**:
```bash
# Check service endpoints
kubectl get endpoints -n sample-app

# Check if pods are ready
kubectl get pods -n sample-app

# Test service internally
kubectl run test --rm -it --image=curlimages/curl -- \
  curl http://sample-app.sample-app.svc.cluster.local/health

# Check ingress
kubectl describe ingress sample-app -n sample-app
```

**Solution**:
```bash
# Restart pods
kubectl rollout restart deployment/sample-app -n sample-app

# Check readiness probe is passing
kubectl describe pod <pod-name> -n sample-app | grep -A 10 "Readiness"

# Port-forward directly to pod
kubectl port-forward -n sample-app <pod-name> 8080:8080
# Then test: curl http://localhost:8080
```

### High Memory Usage / OOMKilled

**Symptom**: Pods restarting with OOMKilled

**Diagnosis**:
```bash
# Check pod resource usage
kubectl top pods -n sample-app

# Check memory limits
kubectl get deployment sample-app -n sample-app \
  -o jsonpath='{.spec.template.spec.containers[0].resources}'

# Check pod events for OOM
kubectl describe pod <pod-name> -n sample-app | grep -i oom
```

**Solution**:
```bash
# Increase memory limits
kubectl set resources deployment sample-app -n sample-app \
  --limits=memory=512Mi

# Or edit deployment
kubectl edit deployment sample-app -n sample-app

# Monitor after change
kubectl top pods -n sample-app --watch
```

## Networking Issues

### Cannot Access Application via Ingress

**Symptom**: `curl http://app.127.0.0.1.sslip.io:8080` fails

**Diagnosis**:
```bash
# Check Traefik is running
kubectl get pods -n traefik

# Check ingress exists
kubectl get ingress -n sample-app

# Check ingress details
kubectl describe ingress sample-app -n sample-app

# Check Traefik service
kubectl get svc -n traefik
```

**Solution**:
```bash
# Verify sslip.io works
nslookup app.127.0.0.1.sslip.io
# Should return: 127.0.0.1

# Check port forwarding
lsof -i :8080

# Test Traefik directly
kubectl port-forward -n traefik svc/traefik 8080:80

# Restart Traefik
kubectl rollout restart deployment/traefik -n traefik
```

### DNS Resolution Issues

**Symptom**: `sslip.io` not resolving

**Diagnosis**:
```bash
# Test DNS resolution
nslookup app.127.0.0.1.sslip.io
dig app.127.0.0.1.sslip.io

# Check DNS servers
cat /etc/resolv.conf
```

**Solution**:
```bash
# Try alternative magic DNS
# Use nip.io instead: app.127.0.0.1.nip.io

# Or use /etc/hosts
sudo echo "127.0.0.1 app.local" >> /etc/hosts
curl http://app.local:8080

# Update ingress to use new host
kubectl edit ingress sample-app -n sample-app
```

### Connection Refused

**Symptom**: `curl: (7) Failed to connect to 127.0.0.1 port 8080`

**Diagnosis**:
```bash
# Check k3d port mapping
k3d cluster list
docker ps | grep k3d

# Check if port is bound
netstat -an | grep 8080
```

**Solution**:
```bash
# Recreate cluster with correct ports
make cluster-delete
make cluster-create

# Or manually add port mapping
k3d cluster edit apqx-platform --port-add "8080:80@loadbalancer"
```

## CI/CD Issues

### GitHub Actions Failing

**Symptom**: CI pipeline fails in GitHub Actions

**Diagnosis**:
```bash
# Check workflow runs on GitHub
# https://github.com/YOUR_USERNAME/apqx-gitops-platform/actions

# Common failures:
# - Test failures: Check pytest output
# - Build failures: Check Dockerfile
# - Push failures: Check GITHUB_TOKEN permissions
```

**Solutions**:

#### Test Failures
```bash
# Run tests locally
cd app
python -m pytest tests/ -v

# Check dependencies
pip install -r requirements.txt
```

#### Image Build Failures
```bash
# Build locally
cd app
docker build -t test:local .

# Check Dockerfile syntax
docker build --check .
```

#### Registry Push Failures
```bash
# Verify GitHub Package permissions
# Settings → Actions → General → Workflow permissions
# Must have "Read and write permissions"

# Check token has packages scope
# Should be automatic for GITHUB_TOKEN
```

### Image Not Updating in Cluster

**Symptom**: New image built but old version running

**Diagnosis**:
```bash
# Check current image
kubectl get deployment sample-app -n sample-app \
  -o jsonpath='{.spec.template.spec.containers[0].image}'

# Check Argo CD sync status
kubectl get application sample-app -n argocd

# Check last GitOps commit
git log --oneline gitops/apps/sample-app/deployment.yaml
```

**Solution**:
```bash
# Manual sync
kubectl patch application sample-app -n argocd \
  --type merge \
  -p '{"operation":{"sync":{"revision":"HEAD"}}}'

# Or force refresh
argocd app sync sample-app --force

# Check image was actually updated in Git
cat gitops/apps/sample-app/deployment.yaml | grep image:
```

## General Debugging

### Get Complete System Status

```bash
# Use status command
make status

# Or manual checks:
kubectl get all -A
kubectl get events -A --sort-by='.lastTimestamp' | tail -20
kubectl top nodes
kubectl top pods -A
```

### Enable Debug Logging

```bash
# Argo CD
kubectl set env deployment/argocd-server -n argocd ARGOCD_LOG_LEVEL=debug

# Application
kubectl set env deployment/sample-app -n sample-app LOG_LEVEL=DEBUG
```

### Collect Logs for Support

```bash
# Collect all logs
kubectl logs -n argocd --all-containers --prefix > argocd-logs.txt
kubectl logs -n sample-app --all-containers --prefix > app-logs.txt
kubectl logs -n traefik --all-containers --prefix > traefik-logs.txt

# Collect cluster info
kubectl cluster-info dump > cluster-dump.txt

# Collect resource status
kubectl get all -A -o yaml > resources.yaml
```

### Reset Everything

```bash
# Nuclear option: start fresh
make down
docker system prune -af
make up
```

## Platform-Specific Issues

### macOS

#### Docker Desktop Not Responding
```bash
# Kill and restart
killall Docker
open -a Docker
```

#### Port Already in Use
```bash
# Find process
lsof -i :8080

# Kill process
kill -9 <PID>
```

### Linux

#### Permission Denied
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Or use sudo
sudo make up
```

### Windows (WSL2)

#### WSL2 Not Starting
```powershell
# From PowerShell (Admin)
wsl --shutdown
wsl --set-default-version 2
```

#### Docker Desktop Not Connecting to WSL2
```powershell
# Reset Docker Desktop
# Docker Desktop → Troubleshoot → Reset to factory defaults
```

## Getting Help

### Useful Commands

```bash
# System information
kubectl version
k3d version
docker version

# Cluster health
kubectl get componentstatuses
kubectl get nodes
kubectl top nodes

# Pod health
kubectl get pods -A
kubectl top pods -A

# Detailed pod info
kubectl describe pod <pod-name> -n <namespace>
kubectl logs <pod-name> -n <namespace> --previous  # Previous container logs
kubectl logs <pod-name> -n <namespace> --follow    # Stream logs

# Events
kubectl get events -A --sort-by='.lastTimestamp' | tail -50

# Network debugging
kubectl run netshoot --rm -it --image=nicolaka/netshoot -- /bin/bash
```

### Where to Look

1. **Application Issues**
   - Application logs: `make app-logs`
   - Pod describe: `kubectl describe pod <name> -n sample-app`

2. **GitOps Issues**
   - Argo CD UI: `make argocd-ui`
   - Argo CD logs: `kubectl logs -n argocd -l app.kubernetes.io/name=argocd-application-controller`

3. **Network Issues**
   - Traefik logs: `kubectl logs -n traefik -l app.kubernetes.io/name=traefik`
   - Ingress: `kubectl describe ingress sample-app -n sample-app`

4. **CI/CD Issues**
   - GitHub Actions: Repository → Actions tab
   - Workflow logs: Click on failed run

### Additional Resources

- [Kubernetes Debugging Guide](https://kubernetes.io/docs/tasks/debug/)
- [Argo CD Troubleshooting](https://argo-cd.readthedocs.io/en/stable/operator-manual/troubleshooting/)
- [k3d Documentation](https://k3d.io/)
- [Traefik Documentation](https://doc.traefik.io/traefik/)

---

**Still stuck?** Open an issue with:
1. Output of `make status`
2. Relevant logs
3. Steps to reproduce
4. OS and Docker version

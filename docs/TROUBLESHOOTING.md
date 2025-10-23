# Troubleshooting Guide

Common issues and solutions for the APQX GitOps Platform.

## Quick Diagnostics

```bash
# Check overall platform status
make status

# Check what tools are installed
make check-tools

# View application logs
make app-logs

# Test application endpoint
make app-test
```

## Common Issues

### Prerequisites

#### Docker Not Running

**Symptom**: `Cannot connect to the Docker daemon`

**Solution**:
```bash
# macOS
open -a Docker

# Linux
sudo systemctl start docker

# Verify
docker ps
```

#### Tools Not Installed

**Symptom**: `command not found: kubectl` or `command not found: k3d`

**Solution**:
```bash
# Install all required tools
make install-tools

# Verify installation
make check-tools
```

#### Insufficient Resources

**Symptom**: Pods showing `OOMKilled` or cluster creation fails

**Solution**:
- Docker Desktop → Settings → Resources
- Recommended: 4+ CPUs, 8GB+ RAM, 20GB+ disk

### Cluster Issues

#### Cluster Won't Create

**Symptom**: `k3d cluster create` hangs or fails

**Diagnosis**:
```bash
# Check for port conflicts
lsof -i :6443  # Kubernetes API
lsof -i :8080  # HTTP ingress
lsof -i :8443  # HTTPS ingress
```

**Solution**:
```bash
# Clean up and retry
make down
make up

# Or manually kill processes using ports
kill -9 <PID>
```

#### Registry Issues

**Symptom**: `Failed to pull image from apqx-platform-registry:5000`

**Diagnosis**:
```bash
# Check registry is running
docker ps | grep registry

# Test registry
curl http://localhost:5000/v2/_catalog
```

**Solution**:
```bash
# Recreate cluster
make restart
```

### ArgoCD Issues

#### Can't Access ArgoCD UI

**Symptom**: Cannot connect to ArgoCD web interface

**Solution**:
```bash
# Use port-forward
make argocd-ui

# Then open: http://localhost:8888

# Get password
make argocd-password
```

#### Applications Won't Sync

**Symptom**: Application stuck in "Progressing" or "OutOfSync"

**Diagnosis**:
```bash
# Check application status
kubectl get applications -n argocd

# Get detailed info
kubectl describe application sample-app -n argocd
```

**Solution**:
```bash
# Force sync
make argocd-sync

# Or sync specific app
kubectl patch application sample-app -n argocd \
  --type merge \
  -p '{"operation":{"initiatedBy":{"username":"admin"},"sync":{"revision":"HEAD"}}}'
```

### Application Issues

#### Pods Not Starting

**Symptom**: Pods stuck in `Pending`, `ImagePullBackOff`, or `CrashLoopBackOff`

**Diagnosis**:
```bash
# Check pod status
kubectl get pods -n sample-app

# Get detailed info
kubectl describe pod <pod-name> -n sample-app

# Check logs
kubectl logs -n sample-app <pod-name>
```

**Common Solutions**:

**ImagePullBackOff**:
```bash
# Rebuild and push image
make build-app

# Restart deployment
kubectl rollout restart deployment/sample-app -n sample-app
```

**CrashLoopBackOff**:
```bash
# Check application logs
make app-logs

# Check for Python errors
kubectl logs -n sample-app <pod-name> --previous
```

**Pending (Resources)**:
```bash
# Check node resources
kubectl top nodes

# Check pod resource requests
kubectl get deployment sample-app -n sample-app -o yaml | grep -A 5 resources
```

#### Application Not Responding

**Symptom**: Service exists but curl fails

**Diagnosis**:
```bash
# Check service endpoints
kubectl get endpoints -n sample-app

# Check pod readiness
kubectl get pods -n sample-app

# Test internally
kubectl run test --rm -it --image=curlimages/curl -- \
  curl http://sample-app.sample-app.svc.cluster.local
```

**Solution**:
```bash
# Restart pods
kubectl rollout restart deployment/sample-app -n sample-app

# Check health endpoints
kubectl exec -n sample-app <pod-name> -- curl localhost:8080/health
```

### Networking Issues

#### Cannot Access via Ingress

**Symptom**: `curl http://app.127.0.0.1.sslip.io:8080` fails

**Diagnosis**:
```bash
# Check Traefik is running
kubectl get pods -n kube-system -l app.kubernetes.io/name=traefik

# Check ingress exists
kubectl get ingress -n sample-app

# Check ingress details
kubectl describe ingress sample-app -n sample-app
```

**Solution**:
```bash
# Verify DNS resolution
nslookup app.127.0.0.1.sslip.io
# Should return: 127.0.0.1

# Check port is bound
lsof -i :8080

# Restart Traefik
kubectl delete pod -n kube-system -l app.kubernetes.io/name=traefik
```

#### HTTPS Not Working

**Symptom**: HTTPS returns 404 or connection refused

**Diagnosis**:
```bash
# Check certificate status
kubectl get certificate -n sample-app
kubectl get certificaterequest -n sample-app

# Check cert-manager
kubectl get pods -n cert-manager
```

**Solution**:
```bash
# Wait for certificate to be ready
kubectl wait --for=condition=Ready certificate/sample-app-tls -n sample-app --timeout=60s

# If stuck, delete and recreate
kubectl delete certificate sample-app-tls -n sample-app
kubectl delete secret sample-app-tls -n sample-app

# ArgoCD will recreate them
make argocd-sync
```

#### DNS Resolution Issues

**Symptom**: `sslip.io` not resolving

**Solution**:
```bash
# Test DNS
nslookup app.127.0.0.1.sslip.io

# Alternative: use nip.io
# Update ingress host to: app.127.0.0.1.nip.io

# Or use localhost
curl http://localhost:8080
```

### HPA Issues

#### HPA Shows "unknown" Metrics

**Symptom**: `kubectl get hpa` shows `<unknown>/70%`

**Diagnosis**:
```bash
# Check HPA status
kubectl get hpa -n sample-app
kubectl describe hpa sample-app -n sample-app
```

**Explanation**: This is expected in k3d. The metrics-server isn't running by default.

**Solution** (if needed):
```bash
# Install metrics-server for k3d
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# Patch for k3d
kubectl patch deployment metrics-server -n kube-system --type=json \
  -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--kubelet-insecure-tls"}]'
```

### Tailscale Issues

See [TAILSCALE_SETUP.md](./TAILSCALE_SETUP.md#troubleshooting) for Tailscale-specific troubleshooting.

## Debugging Commands

### View Logs

```bash
# Application logs
make app-logs

# All pods in namespace
kubectl logs -n sample-app --all-containers=true --prefix

# Previous container (if crashed)
kubectl logs -n sample-app <pod-name> --previous

# Follow logs
kubectl logs -n sample-app <pod-name> --follow
```

### Check Resources

```bash
# Overall status
make status

# Node resources
kubectl top nodes

# Pod resources
kubectl top pods -n sample-app

# Describe pod
kubectl describe pod <pod-name> -n sample-app
```

### Check Events

```bash
# Recent events in namespace
kubectl get events -n sample-app --sort-by='.lastTimestamp'

# All events
kubectl get events -A --sort-by='.lastTimestamp' | tail -20
```

### Network Debugging

```bash
# Test service from inside cluster
kubectl run debug --rm -it --image=curlimages/curl --restart=Never -- \
  curl http://sample-app.sample-app.svc.cluster.local

# Check DNS
kubectl run debug --rm -it --image=busybox --restart=Never -- \
  nslookup sample-app.sample-app.svc.cluster.local

# Get shell in application pod
make app-shell
```

### ArgoCD Debugging

```bash
# Check ArgoCD application status
kubectl get applications -n argocd

# Detailed application info
kubectl describe application sample-app -n argocd

# ArgoCD controller logs
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-application-controller

# Force refresh
kubectl delete application sample-app -n argocd
kubectl apply -f gitops/argocd/applications/
```

## Complete Reset

If everything is broken, start fresh:

```bash
# Delete everything
make down

# Optional: Clean Docker
docker system prune -af

# Start fresh
make up
```

## Platform-Specific Notes

### macOS

```bash
# Port already in use
lsof -i :8080
kill -9 <PID>

# Docker not responding
killall Docker
open -a Docker
```

### Linux

```bash
# Permission denied
sudo usermod -aG docker $USER
newgrp docker

# Firewall blocking ports
sudo ufw allow 8080/tcp
sudo ufw allow 8443/tcp
```

### Windows (WSL2)

```powershell
# WSL not starting
wsl --shutdown
wsl --set-default-version 2

# Docker Desktop issues
# Docker Desktop → Troubleshoot → Reset
```

## Getting More Help

### Collect Debug Information

```bash
# System info
kubectl version
k3d version
docker version

# Cluster dump
kubectl cluster-info dump > cluster-dump.txt

# All logs
kubectl logs -n sample-app --all-containers --prefix > app-logs.txt
kubectl logs -n argocd --all-containers --prefix > argocd-logs.txt
```

### Useful Links

- [Kubernetes Debugging](https://kubernetes.io/docs/tasks/debug/)
- [ArgoCD Troubleshooting](https://argo-cd.readthedocs.io/en/stable/operator-manual/troubleshooting/)
- [k3d Documentation](https://k3d.io/)
- [Traefik Documentation](https://doc.traefik.io/traefik/)
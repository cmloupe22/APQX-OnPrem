# Tailscale Integration

## Overview

This platform includes optional Tailscale integration that exposes your application securely over a private network, accessible from anywhere without exposing public ports.

**Note**: The core platform works without Tailscale. This is a bonus feature that requires a free Tailscale account.

## What You Get

- Secure remote access to your application
- No public port exposure required
- Access from any device on your Tailscale network
- Automatic TLS encryption via Tailscale

## Prerequisites

Before setting up Tailscale integration, you'll need:

### 1. Tailscale Account
Sign up for free at https://tailscale.com

### 2. OAuth Client Credentials
Create an OAuth client to authenticate the operator:

1. Go to https://login.tailscale.com/admin/settings/oauth
2. Click **"Generate OAuth client"**
3. Add these scopes:
   - `devices:write`
   - `routes:write`
   - `dns:write`
4. Save the **Client ID** and **Client Secret**

### 3. Configure ACL Tags
Allow the operator to use specific tags:

1. Go to https://login.tailscale.com/admin/acls/file
2. Add to the `tagOwners` section:
```json
"tagOwners": {
  "tag:k8s-operator": [],
  "tag:k8s": [],
  "tag:apqx-platform": []
}
```
3. Click **Save**

### 4. Enable MagicDNS (Optional)
For friendly hostname access:

1. Go to https://login.tailscale.com/admin/dns
2. Toggle on **"MagicDNS"**

## Setup

### Quick Setup

The platform includes a one-command setup:

```bash
make tailscale-setup
```

You'll be prompted to enter your OAuth credentials:
- **Client ID**: Your OAuth client ID
- **Client Secret**: Your OAuth client secret (starts with `tskey-client-`)

### Manual Setup

If you prefer manual control:

```bash
# 1. Create the OAuth secret
kubectl create namespace tailscale
kubectl create secret generic operator-oauth \
  --namespace=tailscale \
  --from-literal=client_id=YOUR_CLIENT_ID \
  --from-literal=client_secret=YOUR_CLIENT_SECRET

# 2. Deploy Tailscale components
make tailscale-deploy

# 3. Check status
make tailscale-status
```

## Verification

After setup, verify everything is working:

```bash
# Check Tailscale status
make tailscale-status
```

You should see:
- Tailscale operator pod running
- LoadBalancer service with Tailscale IP assigned

Visit your Tailscale admin panel at https://login.tailscale.com/admin/machines - you should see a device named **"sample-app"**.

## Access Your Application

### From Your Computer

1. Install Tailscale on your device: https://tailscale.com/download
2. Connect to your Tailscale network
3. Access the app:

```bash
# By IP (always works)
curl http://100.x.x.x

# By hostname (if MagicDNS enabled)
curl http://sample-app.tailXXXX.ts.net
```

### From Other Devices

Any device connected to your Tailscale network can access the app using the same URLs.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Your Tailscale Network (Tailnet)              │
│                                                  │
│  ┌────────────┐      ┌────────────┐            │
│  │  Laptop    │      │   Phone    │            │
│  └─────┬──────┘      └─────┬──────┘            │
│        │                   │                    │
│        └────────┬──────────┘                    │
│                 │                               │
│        ┌────────▼────────┐                      │
│        │   sample-app    │                      │
│        │   100.x.x.x     │                      │
│        └────────┬────────┘                      │
└─────────────────┼──────────────────────────────┘
                  │
         ┌────────▼────────┐
         │  k3d Cluster    │
         │  ┌───────────┐  │
         │  │ Tailscale │  │
         │  │ Service   │  │
         │  └─────┬─────┘  │
         │        │        │
         │  ┌─────▼─────┐  │
         │  │sample-app │  │
         │  │   Pods    │  │
         │  └───────────┘  │
         └─────────────────┘
```

## Makefile Commands

| Command | Description |
|---------|-------------|
| `make tailscale-setup` | Complete setup with interactive prompts |
| `make tailscale-deploy` | Deploy operator and services |
| `make tailscale-status` | Show Tailscale integration status |
| `make tailscale-logs` | View operator logs |
| `make tailscale-clean` | Remove Tailscale integration |

## Troubleshooting

### "API token invalid"

Your OAuth credentials may be incorrect or expired.

**Solution**: Regenerate OAuth client and update the secret:

```bash
kubectl delete secret operator-oauth -n tailscale
kubectl create secret generic operator-oauth \
  --namespace=tailscale \
  --from-literal=client_id=NEW_CLIENT_ID \
  --from-literal=client_secret=NEW_CLIENT_SECRET
kubectl delete pod -n tailscale -l app=operator
```

### Cannot resolve hostname

If `sample-app.tailXXXX.ts.net` doesn't resolve:

1. Verify MagicDNS is enabled: https://login.tailscale.com/admin/dns
2. Use the IP address instead: `curl http://100.x.x.x`
3. Flush DNS cache (macOS):
   ```bash
   sudo dscacheutil -flushcache
   sudo killall -HUP mDNSResponder
   ```

### Device not appearing in Tailscale

Check the operator status:

```bash
# View operator logs
make tailscale-logs

# Check operator pod
kubectl get pods -n tailscale

# Verify service exists
kubectl get svc sample-app-tailscale -n sample-app
```

## Files Reference

The Tailscale integration consists of:

- **`gitops/argocd/applications/tailscale-operator.yaml`** - ArgoCD application for Tailscale operator
- **`gitops/argocd/applications/tailscale-rbac-extra.yaml`** - Additional RBAC permissions
- **`gitops/apps/sample-app/tailscale-ingress.yaml`** - LoadBalancer service configuration

## Security Notes

- OAuth credentials are stored as Kubernetes secrets (not in git)
- Each user needs their own OAuth client from their Tailscale account
- Use ACL tags to control access to your services
- All traffic is encrypted by Tailscale automatically

## Additional Resources

- [Tailscale Documentation](https://tailscale.com/kb)
- [Tailscale Kubernetes Operator](https://tailscale.com/kb/1236/kubernetes-operator)
- [Tailscale ACLs](https://tailscale.com/kb/1018/acls)
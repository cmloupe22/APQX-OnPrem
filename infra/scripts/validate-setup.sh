#!/usr/bin/env bash

# APQX Platform - Setup Validation Script
# This script validates that everything is set up correctly

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}  APQX Platform Validator${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

# Track results
PASSED=0
FAILED=0
WARNINGS=0

# Function to check a requirement
check() {
    local description="$1"
    local command="$2"
    
    echo -n "Checking: $description... "
    
    if eval "$command" &> /dev/null; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        ((FAILED++))
        return 1
    fi
}

# Function for optional checks
check_optional() {
    local description="$1"
    local command="$2"
    
    echo -n "Checking: $description... "
    
    if eval "$command" &> /dev/null; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${YELLOW}⚠ OPTIONAL${NC}"
        ((WARNINGS++))
        return 1
    fi
}

echo -e "${YELLOW}Phase 1: Prerequisites${NC}"
echo "-----------------------------------"
check "Docker is installed" "command -v docker"
check "Docker is running" "docker ps"
check "kubectl is installed" "command -v kubectl"
check "k3d is installed" "command -v k3d"
check_optional "helm is installed" "command -v helm"
check_optional "argocd CLI is installed" "command -v argocd"
echo ""

echo -e "${YELLOW}Phase 2: Cluster Status${NC}"
echo "-----------------------------------"
check "k3d cluster exists" "k3d cluster list | grep -q apqx-platform"
check "kubectl can connect" "kubectl cluster-info"
check "All nodes are ready" "kubectl get nodes | grep -q Ready"
check "Core DNS is running" "kubectl get pods -n kube-system -l k8s-app=kube-dns | grep -q Running"
echo ""

echo -e "${YELLOW}Phase 3: Argo CD Status${NC}"
echo "-----------------------------------"
check "Argo CD namespace exists" "kubectl get namespace argocd"
check "Argo CD server is running" "kubectl get deployment argocd-server -n argocd | grep -q '1/1'"
check "Argo CD repo-server is running" "kubectl get deployment argocd-repo-server -n argocd | grep -q '1/1'"
check "Argo CD applications exist" "kubectl get applications -n argocd | grep -q sample-app"
echo ""

echo -e "${YELLOW}Phase 4: Traefik Status${NC}"
echo "-----------------------------------"
check "Traefik namespace exists" "kubectl get namespace traefik"
check "Traefik is deployed" "kubectl get deployment traefik -n traefik"
check "Traefik service exists" "kubectl get svc traefik -n traefik"
echo ""

echo -e "${YELLOW}Phase 5: Application Status${NC}"
echo "-----------------------------------"
check "Application namespace exists" "kubectl get namespace sample-app"
check "Application deployment exists" "kubectl get deployment sample-app -n sample-app"
check "Application pods are running" "kubectl get pods -n sample-app -l app=sample-app | grep -q Running"
check "Application service exists" "kubectl get svc sample-app -n sample-app"
check "Application ingress exists" "kubectl get ingress sample-app -n sample-app"
check "HPA is configured" "kubectl get hpa sample-app -n sample-app"
check "PDB is configured" "kubectl get pdb sample-app -n sample-app"
echo ""

echo -e "${YELLOW}Phase 6: Security Configuration${NC}"
echo "-----------------------------------"
check "ServiceAccount exists" "kubectl get serviceaccount sample-app -n sample-app"
check "Role exists" "kubectl get role sample-app -n sample-app"
check "RoleBinding exists" "kubectl get rolebinding sample-app -n sample-app"
check "Deployment uses ServiceAccount" "kubectl get deployment sample-app -n sample-app -o yaml | grep -q 'serviceAccountName: sample-app'"
check "Pods run as non-root" "kubectl get deployment sample-app -n sample-app -o yaml | grep -q 'runAsNonRoot: true'"
echo ""

echo -e "${YELLOW}Phase 7: Network Connectivity${NC}"
echo "-----------------------------------"
check "DNS resolution works" "nslookup app.127.0.0.1.sslip.io | grep -q '127.0.0.1'"
check "Application endpoint responds" "curl -f -s http://app.127.0.0.1.sslip.io:8080/ > /dev/null"
check "Health endpoint responds" "curl -f -s http://app.127.0.0.1.sslip.io:8080/health > /dev/null"
check "Ready endpoint responds" "curl -f -s http://app.127.0.0.1.sslip.io:8080/ready > /dev/null"
check "Metrics endpoint responds" "curl -f -s http://app.127.0.0.1.sslip.io:8080/metrics > /dev/null"
echo ""

echo -e "${YELLOW}Phase 8: GitOps Sync Status${NC}"
echo "-----------------------------------"
if kubectl get application sample-app -n argocd &> /dev/null; then
    SYNC_STATUS=$(kubectl get application sample-app -n argocd -o jsonpath='{.status.sync.status}')
    HEALTH_STATUS=$(kubectl get application sample-app -n argocd -o jsonpath='{.status.health.status}')
    
    echo -n "Checking: Application sync status... "
    if [ "$SYNC_STATUS" = "Synced" ]; then
        echo -e "${GREEN}✓ PASS${NC} (Synced)"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC} ($SYNC_STATUS)"
        ((FAILED++))
    fi
    
    echo -n "Checking: Application health status... "
    if [ "$HEALTH_STATUS" = "Healthy" ]; then
        echo -e "${GREEN}✓ PASS${NC} (Healthy)"
        ((PASSED++))
    else
        echo -e "${YELLOW}⚠ WARNING${NC} ($HEALTH_STATUS)"
        ((WARNINGS++))
    fi
else
    echo -e "${RED}✗ FAIL${NC} - Argo CD application not found"
    ((FAILED+=2))
fi
echo ""

echo -e "${YELLOW}Phase 9: Resource Metrics${NC}"
echo "-----------------------------------"
if command -v kubectl &> /dev/null; then
    echo "Cluster Resource Usage:"
    kubectl top nodes 2>/dev/null || echo "  (Metrics not available - this is normal)"
    echo ""
    echo "Pod Resource Usage:"
    kubectl top pods -n sample-app 2>/dev/null || echo "  (Metrics not available - this is normal)"
fi
echo ""

# Summary
echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}  Validation Summary${NC}"
echo -e "${BLUE}================================${NC}"
echo ""
echo -e "${GREEN}Passed:${NC} $PASSED"
echo -e "${YELLOW}Warnings:${NC} $WARNINGS"
echo -e "${RED}Failed:${NC} $FAILED"
echo ""

TOTAL=$((PASSED + FAILED + WARNINGS))
PASS_RATE=$((PASSED * 100 / TOTAL))

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All critical checks passed! ($PASS_RATE%)${NC}"
    echo ""
    echo -e "${GREEN}Your APQX Platform is ready to use!${NC}"
    echo ""
    echo "Access your application:"
    echo "  Application: http://app.127.0.0.1.sslip.io:8080"
    echo "  Argo CD UI:  https://argocd.127.0.0.1.sslip.io:8443"
    echo ""
    echo "Get Argo CD password:"
    echo "  make argocd-password"
    echo ""
    exit 0
else
    echo -e "${RED}✗ Some checks failed. ($PASS_RATE% passed)${NC}"
    echo ""
    echo "Troubleshooting steps:"
    echo "  1. Check if all pods are running: kubectl get pods -A"
    echo "  2. View platform status: make status"
    echo "  3. Check logs: make app-logs"
    echo "  4. Restart platform: make restart"
    echo "  5. See TROUBLESHOOTING.md for detailed help"
    echo ""
    exit 1
fi

.PHONY: help up down restart cluster-create cluster-delete cluster-info \
        argocd-install argocd-ui argocd-password argocd-sync \
        app-logs app-test status validate install-tools clean

# Configuration
CLUSTER_NAME ?= apqx-platform
K3D_VERSION ?= v5.6.0
KUBECTL_VERSION ?= v1.28.0
HELM_VERSION ?= v3.13.0
ARGOCD_NAMESPACE ?= argocd
APP_NAMESPACE ?= sample-app
REGISTRY_PORT ?= 5000
API_PORT ?= 8080
INGRESS_HTTP_PORT ?= 8080
INGRESS_HTTPS_PORT ?= 8443

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(GREEN)APQX GitOps Platform - Available Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'

# Detect platform
PLATFORM := $(shell uname -m)
ifeq ($(PLATFORM),arm64)
    DOCKER_PLATFORM := linux/arm64
else ifeq ($(PLATFORM),aarch64)
    DOCKER_PLATFORM := linux/arm64
else
    DOCKER_PLATFORM := linux/amd64
endif

build-app: ## Build and push application to local registry
	@echo "$(GREEN)Building application for platform: $(DOCKER_PLATFORM)$(NC)"
	@cd app && docker build --platform $(DOCKER_PLATFORM) -t apqx-platform-registry:5000/sample-app:latest .
	@docker tag apqx-platform-registry:5000/sample-app:latest localhost:5000/sample-app:latest
	@docker push localhost:5000/sample-app:latest
	@echo "$(GREEN) Application built and pushed$(NC)"


# ============================================================================
# Main Commands
# ============================================================================

up: ## Bootstrap the entire platform (cluster + ArgoCD + apps)
	@echo "$(GREEN) Bootstrapping APQX GitOps Platform...$(NC)"
	@$(MAKE) cluster-create
	@echo "$(GREEN) Waiting for cluster to be ready...$(NC)"
	@sleep 10
	@$(MAKE) build-app
	@$(MAKE) argocd-install
	@echo "$(GREEN) Waiting for ArgoCD to be ready...$(NC)"
	@sleep 30
	@$(MAKE) gitops-sync
	@echo "$(GREEN) Platform is ready!$(NC)"
	@$(MAKE) status

down: ## Destroy the entire platform
	@echo "$(YELLOW) Destroying platform...$(NC)"
	@$(MAKE) cluster-delete
	@echo "$(GREEN) Platform destroyed$(NC)"

restart: ## Restart the platform (down + up)
	@echo "$(YELLOW) Restarting platform...$(NC)"
	@$(MAKE) down
	@sleep 5
	@$(MAKE) up

# ============================================================================
# Cluster Management
# ============================================================================

cluster-create: ##  Create k3d cluster
	@echo "$(GREEN)Creating k3d cluster: $(CLUSTER_NAME)$(NC)"
	@if k3d cluster list | grep -q $(CLUSTER_NAME); then \
		echo "$(YELLOW)Cluster $(CLUSTER_NAME) already exists$(NC)"; \
	else \
		k3d cluster create $(CLUSTER_NAME) \
			--api-port 6443 \
			--port "$(INGRESS_HTTP_PORT):80@loadbalancer" \
			--port "$(INGRESS_HTTPS_PORT):443@loadbalancer" \
			--registry-create $(CLUSTER_NAME)-registry:$(REGISTRY_PORT) \
			--volume /tmp/k3d-$(CLUSTER_NAME):/tmp/k3d \
			--agents 2 \
			--k3s-arg "--disable=traefik@server:0" \
			--wait; \
		echo "$(GREEN) Cluster created successfully$(NC)"; \
	fi
	@kubectl cluster-info
	@kubectl get nodes

cluster-delete: ##  Delete k3d cluster
	@echo "$(YELLOW)Deleting k3d cluster: $(CLUSTER_NAME)$(NC)"
	@k3d cluster delete $(CLUSTER_NAME) || true
	@echo "$(GREEN) Cluster deleted$(NC)"

cluster-info: ##  Show cluster information
	@echo "$(GREEN)Cluster Information:$(NC)"
	@kubectl cluster-info
	@echo ""
	@echo "$(GREEN)Nodes:$(NC)"
	@kubectl get nodes
	@echo ""
	@echo "$(GREEN)Namespaces:$(NC)"
	@kubectl get namespaces

# ============================================================================
# ArgoCD Management
# ============================================================================

argocd-install: ## Install ArgoCD
	@echo "$(GREEN)Installing ArgoCD...$(NC)"
	@kubectl create namespace $(ARGOCD_NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -
	@kubectl apply -n $(ARGOCD_NAMESPACE) -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
	@echo "$(GREEN)⏳ Waiting for ArgoCD to be ready...$(NC)"
	@kubectl wait --for=condition=available --timeout=300s deployment/argocd-server -n $(ARGOCD_NAMESPACE)
	@kubectl wait --for=condition=available --timeout=300s deployment/argocd-repo-server -n $(ARGOCD_NAMESPACE)
	@echo "$(GREEN) ArgoCD installed successfully$(NC)"
	@echo ""
	@echo "$(YELLOW)ArgoCD UI: https://argocd.127.0.0.1.sslip.io:$(INGRESS_HTTPS_PORT)$(NC)"
	@echo "$(YELLOW)Username: admin$(NC)"
	@echo "$(YELLOW)Password: $$(kubectl -n $(ARGOCD_NAMESPACE) get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" 2>/dev/null | base64 -d || echo 'Run: make argocd-password')$(NC)"

argocd-password: ## Get ArgoCD admin password
	@echo "$(GREEN)ArgoCD Admin Password:$(NC)"
	@kubectl -n $(ARGOCD_NAMESPACE) get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d && echo

argocd-ui: ## Port-forward to ArgoCD UI (localhost:8080)
	@echo "$(GREEN)Opening ArgoCD UI at http://localhost:8888$(NC)"
	@echo "$(YELLOW)Username: admin$(NC)"
	@echo "$(YELLOW)Password: $$(kubectl -n $(ARGOCD_NAMESPACE) get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)$(NC)"
	@kubectl port-forward svc/argocd-server -n $(ARGOCD_NAMESPACE) 8888:443

argocd-sync: ## Sync all ArgoCD applications
	@echo "$(GREEN)Syncing ArgoCD applications...$(NC)"
	@kubectl get applications -n $(ARGOCD_NAMESPACE) -o name | xargs -I {} kubectl patch {} -n $(ARGOCD_NAMESPACE) --type merge -p '{"operation":{"initiatedBy":{"username":"admin"},"sync":{"revision":"HEAD"}}}'
	@echo "$(GREEN) Applications synced$(NC)"

gitops-sync: ## Deploy applications via GitOps (apply ArgoCD apps)
	@echo "$(GREEN)Deploying applications via GitOps...$(NC)"
	@kubectl apply -f gitops/argocd/applications/ || true
	@echo "$(GREEN) GitOps applications configured$(NC)"
	@kubectl get applications -n $(ARGOCD_NAMESPACE)

# ============================================================================
# Application Management
# ============================================================================

app-logs: ## Show application logs
	@echo "$(GREEN)Application logs:$(NC)"
	@kubectl logs -n $(APP_NAMESPACE) -l app=sample-app --tail=50 -f

app-test: ## Test application endpoint
	@echo "$(GREEN)Testing application endpoint...$(NC)"
	@echo ""
	@curl -s http://app.127.0.0.1.sslip.io:$(INGRESS_HTTP_PORT)/ | jq . || curl -s http://app.127.0.0.1.sslip.io:$(INGRESS_HTTP_PORT)/
	@echo ""

app-shell: ## Get shell in application pod
	@kubectl exec -it -n $(APP_NAMESPACE) $$(kubectl get pods -n $(APP_NAMESPACE) -l app=sample-app -o jsonpath='{.items[0].metadata.name}') -- /bin/sh

# ============================================================================
# Status & Validation
# ============================================================================

status: ## Show complete platform status
	@echo "$(GREEN)========================================$(NC)"
	@echo "$(GREEN)    APQX Platform Status$(NC)"
	@echo "$(GREEN)========================================$(NC)"
	@echo ""
	@echo "$(YELLOW) Cluster:$(NC)"
	@kubectl get nodes
	@echo ""
	@echo "$(YELLOW) System Pods:$(NC)"
	@kubectl get pods -n kube-system
	@echo ""
	@echo "$(YELLOW) ArgoCD Applications:$(NC)"
	@kubectl get applications -n $(ARGOCD_NAMESPACE) 2>/dev/null || echo "ArgoCD not installed"
	@echo ""
	@echo "$(YELLOW) Sample App:$(NC)"
	@kubectl get pods,svc,ingress -n $(APP_NAMESPACE) 2>/dev/null || echo "App not deployed yet"
	@echo ""
	@echo "$(GREEN)========================================$(NC)"
	@echo "$(GREEN)    Access Information$(NC)"
	@echo "$(GREEN)========================================$(NC)"
	@echo "$(YELLOW) Application: http://app.127.0.0.1.sslip.io:$(INGRESS_HTTP_PORT)$(NC)"
	@echo "$(YELLOW) ArgoCD UI: https://argocd.127.0.0.1.sslip.io:$(INGRESS_HTTPS_PORT)$(NC)"
	@echo "$(YELLOW)   Username: admin$(NC)"
	@echo "$(YELLOW)   Password: $$(kubectl -n $(ARGOCD_NAMESPACE) get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" 2>/dev/null | base64 -d || echo 'Not yet available')$(NC)"
	@echo ""

validate: ## Validate all configurations
	@echo "$(GREEN)Validating configurations...$(NC)"
	@echo "$(YELLOW)Checking Kubernetes manifests...$(NC)"
	@find gitops -name "*.yaml" -type f -exec kubectl apply --dry-run=client -f {} \; > /dev/null && echo "$(GREEN) All manifests are valid$(NC)" || echo "$(RED) Invalid manifests found$(NC)"

# ============================================================================
# Tool Installation
# ============================================================================

install-tools: ## Install required tools (kubectl, k3d, helm)
	@echo "$(GREEN)Installing required tools...$(NC)"
	@./infra/scripts/install-tools.sh

check-tools: ## Check if required tools are installed
	@echo "$(GREEN)Checking required tools...$(NC)"
	@command -v docker >/dev/null 2>&1 && echo "$(GREEN) docker$(NC)" || echo "$(RED) docker (required)$(NC)"
	@command -v kubectl >/dev/null 2>&1 && echo "$(GREEN) kubectl$(NC)" || echo "$(RED) kubectl (install with: make install-tools)$(NC)"
	@command -v k3d >/dev/null 2>&1 && echo "$(GREEN) k3d$(NC)" || echo "$(RED) k3d (install with: make install-tools)$(NC)"
	@command -v helm >/dev/null 2>&1 && echo "$(GREEN) helm$(NC)" || echo "$(YELLOW)  helm (optional)$(NC)"

# ============================================================================
# Cleanup
# ============================================================================

clean: ## Clean all temporary files
	@echo "$(GREEN)Cleaning temporary files...$(NC)"
	@rm -rf /tmp/k3d-$(CLUSTER_NAME)
	@docker system prune -f
	@echo "$(GREEN) Cleanup complete$(NC)"

# ============================================================================
# Development
# ============================================================================

dev-build: ## Build application Docker image locally
	@echo "$(GREEN)Building application image...$(NC)"
	@cd app && docker build -t localhost:$(REGISTRY_PORT)/sample-app:dev .
	@docker push localhost:$(REGISTRY_PORT)/sample-app:dev
	@echo "$(GREEN) Image built and pushed to local registry$(NC)"

dev-watch: ## Watch for changes and redeploy
	@echo "$(GREEN)Watching for changes...$(NC)"
	@while true; do \
		inotifywait -r -e modify,create,delete app/ gitops/ 2>/dev/null || sleep 2; \
		$(MAKE) dev-build && kubectl rollout restart deployment/sample-app -n $(APP_NAMESPACE); \
	done

# ============================================================================
# Tailscale Integration
# ============================================================================

.PHONY: tailscale-setup tailscale-secret tailscale-deploy tailscale-status tailscale-logs tailscale-clean

tailscale-setup: ## Complete Tailscale setup (interactive)
	@echo "$(GREEN) Setting up Tailscale integration...$(NC)"
	@read -p "Enter your Tailscale auth key (tskey-auth-...): " AUTH_KEY; \
	$(MAKE) tailscale-secret AUTH_KEY=$$AUTH_KEY
	@$(MAKE) tailscale-deploy
	@echo "$(YELLOW) Waiting for Tailscale operator to be ready...$(NC)"
	@sleep 15
	@$(MAKE) tailscale-status

tailscale-secret: ##  Create Tailscale OAuth secret
	@if [ -z "$(AUTH_KEY)" ]; then \
		echo "$(RED) Error: AUTH_KEY not provided$(NC)"; \
		echo "Usage: make tailscale-secret AUTH_KEY=tskey-auth-xxxxx"; \
		exit 1; \
	fi
	@echo "$(GREEN)Creating Tailscale OAuth secret...$(NC)"
	@kubectl create namespace tailscale --dry-run=client -o yaml | kubectl apply -f -
	@kubectl create secret generic operator-oauth \
		--namespace=tailscale \
		--from-literal=client_id=$(AUTH_KEY) \
		--from-literal=client_secret=$(AUTH_KEY) \
		--dry-run=client -o yaml | kubectl apply -f -
	@echo "$(GREEN) Tailscale secret created$(NC)"

tailscale-deploy: ## Deploy Tailscale operator and ingress via ArgoCD
	@echo "$(GREEN) Deploying Tailscale operator...$(NC)"
	@kubectl apply -f gitops/argocd/applications/tailscale-operator.yaml
	@echo "$(GREEN) Applying extra RBAC permissions...$(NC)"
	@kubectl apply -f gitops/argocd/applications/tailscale-rbac-extra.yaml
	@echo "$(YELLOW) Waiting for operator to sync...$(NC)"
	@kubectl wait --for=condition=Synced --timeout=300s \
		application/tailscale-operator -n argocd 2>/dev/null || true
	@echo "$(GREEN) Deploying Tailscale ingress...$(NC)"
	@kubectl apply -f gitops/apps/sample-app/tailscale-ingress.yaml
	@echo "$(GREEN) Tailscale deployment complete$(NC)"

tailscale-status: ##  Check Tailscale status
	@echo "$(GREEN)========================================$(NC)"
	@echo "$(GREEN)    Tailscale Status$(NC)"
	@echo "$(GREEN)========================================$(NC)"
	@echo ""
	@echo "$(YELLOW) Tailscale Operator:$(NC)"
	@kubectl get pods -n tailscale -l app.kubernetes.io/name=tailscale-operator 2>/dev/null || echo "  No operator pods found"
	@echo ""
	@echo "$(YELLOW) Tailscale Connector:$(NC)"
	@kubectl get connector -n sample-app 2>/dev/null || echo "  No connectors found"
	@echo ""
	@echo "$(YELLOW) Tailscale Ingress Pods:$(NC)"
	@kubectl get pods -n sample-app -l app=tailscale-ingress 2>/dev/null || echo "  No ingress pods found"
	@echo ""
	@echo "$(GREEN)========================================$(NC)"
	@echo "$(YELLOW) Next Steps:$(NC)"
	@echo "  1. Visit: $(GREEN)https://login.tailscale.com/admin/machines$(NC)"
	@echo "  2. Look for device named: $(GREEN)sample-app$(NC)"
	@echo "  3. Access your app at: $(GREEN)https://sample-app.<your-tailnet>.ts.net$(NC)"
	@echo ""

tailscale-logs: ##  View Tailscale operator logs
	@kubectl logs -n tailscale -l app.kubernetes.io/name=tailscale-operator --tail=50 -f

tailscale-clean: ##  Remove Tailscale integration
	@echo "$(YELLOW) Removing Tailscale integration...$(NC)"
	@kubectl delete -f gitops/apps/sample-app/tailscale-ingress.yaml --ignore-not-found
	@kubectl delete application tailscale-operator -n argocd --ignore-not-found
	@kubectl delete namespace tailscale --ignore-not-found
	@echo "$(GREEN) Tailscale removed$(NC)"
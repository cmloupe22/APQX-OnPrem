#!/usr/bin/env bash

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Versions
KUBECTL_VERSION="v1.28.0"
K3D_VERSION="v5.6.0"
HELM_VERSION="v3.13.0"
ARGOCD_VERSION="v2.9.3"

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  APQX Platform Tool Installer${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# Detect OS and Architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

echo -e "${YELLOW}Detected OS: $OS${NC}"
echo -e "${YELLOW}Detected Architecture: $ARCH${NC}"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed!${NC}"
    echo -e "${YELLOW}Please install Docker first:${NC}"
    echo "  macOS: https://docs.docker.com/desktop/install/mac-install/"
    echo "  Linux: https://docs.docker.com/engine/install/"
    echo "  Windows: https://docs.docker.com/desktop/install/windows-install/"
    exit 1
else
    echo -e "${GREEN}✅ Docker is installed${NC}"
fi

# Create bin directory
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo -e "${YELLOW}Adding $BIN_DIR to PATH...${NC}"
    
    # Detect shell and update appropriate config file
    if [ -n "$ZSH_VERSION" ]; then
        echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$HOME/.zshrc"
        echo -e "${GREEN}Added to ~/.zshrc${NC}"
    elif [ -n "$BASH_VERSION" ]; then
        echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$HOME/.bashrc"
        echo -e "${GREEN}Added to ~/.bashrc${NC}"
    fi
    
    export PATH="$PATH:$BIN_DIR"
fi

# Function to install kubectl
install_kubectl() {
    if command -v kubectl &> /dev/null; then
        echo -e "${GREEN}✅ kubectl already installed${NC}"
        return
    fi
    
    echo -e "${YELLOW}Installing kubectl...${NC}"
    
    curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/${OS}/${ARCH}/kubectl"
    chmod +x kubectl
    mv kubectl "$BIN_DIR/"
    
    echo -e "${GREEN}✅ kubectl installed${NC}"
}

# Function to install k3d
install_k3d() {
    if command -v k3d &> /dev/null; then
        echo -e "${GREEN}✅ k3d already installed${NC}"
        return
    fi
    
    echo -e "${YELLOW}Installing k3d...${NC}"
    
    if [ "$OS" = "darwin" ]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install k3d
        else
            curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
        fi
    else
        # Linux
        curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
    fi
    
    echo -e "${GREEN}✅ k3d installed${NC}"
}

# Function to install helm
install_helm() {
    if command -v helm &> /dev/null; then
        echo -e "${GREEN}✅ helm already installed${NC}"
        return
    fi
    
    echo -e "${YELLOW}Installing helm...${NC}"
    
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    
    echo -e "${GREEN}✅ helm installed${NC}"
}

# Function to install argocd CLI
install_argocd_cli() {
    if command -v argocd &> /dev/null; then
        echo -e "${GREEN}✅ argocd CLI already installed${NC}"
        return
    fi
    
    echo -e "${YELLOW}Installing argocd CLI...${NC}"
    
    if [ "$OS" = "darwin" ]; then
        # macOS
        curl -sSL -o "$BIN_DIR/argocd" "https://github.com/argoproj/argo-cd/releases/download/${ARGOCD_VERSION}/argocd-${OS}-${ARCH}"
    else
        # Linux
        curl -sSL -o "$BIN_DIR/argocd" "https://github.com/argoproj/argo-cd/releases/download/${ARGOCD_VERSION}/argocd-${OS}-${ARCH}"
    fi
    
    chmod +x "$BIN_DIR/argocd"
    
    echo -e "${GREEN}✅ argocd CLI installed${NC}"
}

# Install all tools
echo -e "${GREEN}Installing tools...${NC}"
echo ""

install_kubectl
install_k3d
install_helm
install_argocd_cli

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo -e "${YELLOW}Installed tools:${NC}"
kubectl version --client 2>/dev/null | grep "Client Version" || echo "kubectl: $(kubectl version --client --short 2>/dev/null)"
echo "k3d: $(k3d version 2>/dev/null | head -n1)"
echo "helm: $(helm version --short 2>/dev/null)"
echo "argocd: $(argocd version --client --short 2>/dev/null)"
echo ""
echo -e "${YELLOW}Note: If commands are not found, restart your shell or run:${NC}"
echo "  source ~/.bashrc   # for bash"
echo "  source ~/.zshrc    # for zsh"
echo ""
echo -e "${GREEN}Ready to bootstrap the platform with: make up${NC}"

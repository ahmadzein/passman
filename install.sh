#!/bin/bash
set -euo pipefail

# Passman Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/ahmadzein/passman/main/install.sh | bash
#
# Downloads a pre-built binary. No Rust, no cargo, no cloning required.
# Falls back to building from source if no binary is available for your platform.

REPO="ahmadzein/passman"
BINARY="passman-mcp-server"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-latest}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

header() {
    echo ""
    echo -e "${PURPLE}${BOLD}"
    echo "  ╔═══════════════════════════════════════════╗"
    echo "  ║           PASSMAN INSTALLER               ║"
    echo "  ║   Secure Credential Proxy MCP Server      ║"
    echo "  ╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
}

info()    { echo -e "  ${BLUE}[INFO]${NC} $1"; }
success() { echo -e "  ${GREEN}[OK]${NC}   $1"; }
warn()    { echo -e "  ${RED}[WARN]${NC} $1"; }
step()    { echo -e "  ${CYAN}[STEP]${NC} $1"; }

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Darwin) PLATFORM="apple-darwin" ;;
        Linux)  PLATFORM="unknown-linux-gnu" ;;
        *)      warn "Unsupported OS: $OS"; exit 1 ;;
    esac

    case "$ARCH" in
        x86_64|amd64) ARCH="x86_64" ;;
        arm64|aarch64) ARCH="aarch64" ;;
        *)             warn "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    TARGET="${ARCH}-${PLATFORM}"
    TARBALL="${BINARY}-${TARGET}.tar.gz"
    info "Detected platform: ${BOLD}${TARGET}${NC}"
}

get_download_url() {
    if [ "$VERSION" = "latest" ]; then
        DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${TARBALL}"
    else
        DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"
    fi
}

install_binary() {
    step "Downloading pre-built binary..."
    get_download_url

    TMPDIR=$(mktemp -d)
    HTTP_CODE=$(curl -fsSL -w "%{http_code}" -o "$TMPDIR/$TARBALL" "$DOWNLOAD_URL" 2>/dev/null) || HTTP_CODE="000"

    if [ "$HTTP_CODE" = "200" ] && [ -f "$TMPDIR/$TARBALL" ]; then
        info "Extracting..."
        tar xzf "$TMPDIR/$TARBALL" -C "$TMPDIR"

        mkdir -p "$INSTALL_DIR"
        cp "$TMPDIR/$BINARY" "$INSTALL_DIR/$BINARY"
        chmod +x "$INSTALL_DIR/$BINARY"
        rm -rf "$TMPDIR"
        success "Downloaded pre-built binary"
        return 0
    else
        rm -rf "$TMPDIR"
        warn "No pre-built binary for ${TARGET}"
        info "Falling back to building from source..."
        return 1
    fi
}

install_from_source() {
    step "Building from source (requires Rust)..."

    if ! command -v cargo &>/dev/null; then
        if ! command -v rustup &>/dev/null; then
            info "Installing Rust toolchain..."
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y 2>/dev/null
            source "$HOME/.cargo/env"
        fi
    fi

    if ! command -v cargo &>/dev/null; then
        warn "Failed to install Rust. Please install manually: https://rustup.rs/"
        exit 1
    fi

    TMPDIR=$(mktemp -d)
    info "Cloning repository..."
    git clone --depth 1 "https://github.com/${REPO}.git" "$TMPDIR/passman" 2>/dev/null
    info "Building release binary (this may take a few minutes)..."
    cd "$TMPDIR/passman"
    cargo build --release -p passman-mcp-server 2>/dev/null

    mkdir -p "$INSTALL_DIR"
    cp "target/release/$BINARY" "$INSTALL_DIR/$BINARY"
    chmod +x "$INSTALL_DIR/$BINARY"
    rm -rf "$TMPDIR"
    success "Built from source"
}

setup_path() {
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        warn "$INSTALL_DIR is not in your PATH"

        SHELL_NAME="$(basename "$SHELL")"
        case "$SHELL_NAME" in
            zsh)  RC_FILE="$HOME/.zshrc" ;;
            bash) RC_FILE="$HOME/.bashrc" ;;
            fish) RC_FILE="$HOME/.config/fish/config.fish" ;;
            *)    RC_FILE="$HOME/.profile" ;;
        esac

        if [ -f "$RC_FILE" ]; then
            if ! grep -q "$INSTALL_DIR" "$RC_FILE" 2>/dev/null; then
                echo "" >> "$RC_FILE"
                echo "# Passman" >> "$RC_FILE"
                echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$RC_FILE"
                success "Added $INSTALL_DIR to PATH in $RC_FILE"
                info "Run: source $RC_FILE (or restart your terminal)"
            fi
        fi
    fi
}

verify_install() {
    BINARY_PATH="$INSTALL_DIR/$BINARY"
    if [ -x "$BINARY_PATH" ]; then
        success "Verified: $BINARY_PATH"
    else
        warn "Binary not found at $BINARY_PATH"
        exit 1
    fi
}

print_config() {
    BINARY_PATH="$INSTALL_DIR/$BINARY"

    echo ""
    echo -e "  ${GREEN}${BOLD}Installation complete!${NC}"
    echo -e "  ${GREEN}Binary:${NC} $BINARY_PATH"
    echo ""
    echo -e "  ${BOLD}Configure your AI client:${NC}"
    echo ""
    echo -e "  ${CYAN}Claude Code (quickest):${NC}"
    echo -e "    claude mcp add --transport stdio passman -- $BINARY_PATH"
    echo ""
    echo -e "  ${CYAN}Or add to .mcp.json / settings:${NC}"
    echo '    {'
    echo '      "mcpServers": {'
    echo '        "passman": {'
    echo "          \"command\": \"$BINARY_PATH\","
    echo '          "args": []'
    echo '        }'
    echo '      }'
    echo '    }'
    echo ""
    echo -e "  ${CYAN}Works with:${NC} Claude Code, Cursor, VS Code, Claude Desktop, Windsurf"
    echo ""
    echo -e "  ${PURPLE}${BOLD}Getting started:${NC}"
    echo -e "    1. Add Passman to your AI client config (above)"
    echo -e "    2. Restart your AI client"
    echo -e "    3. Ask: \"Unlock my Passman vault\""
    echo -e "    4. Store credentials and use them securely!"
    echo ""
    echo -e "  ${BLUE}Docs:${NC}   https://ahmadzein.github.io/passman"
    echo -e "  ${BLUE}GitHub:${NC} https://github.com/${REPO}"
    echo ""
}

# Main
header
detect_platform

# Try pre-built binary first, fall back to source
if ! install_binary; then
    install_from_source
fi

setup_path
verify_install
print_config

#!/bin/bash
set -euo pipefail

# Passman Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/ahmadzein/passman/main/install.sh | bash
#        curl -fsSL https://raw.githubusercontent.com/ahmadzein/passman/main/install.sh | GUI=1 bash
#
# Downloads a pre-built binary. No Rust, no cargo, no cloning required.
# Falls back to building from source if no binary is available for your platform.
# Set GUI=1 to also install the Desktop GUI app.

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

        # Strip macOS quarantine attribute so Gatekeeper doesn't kill the binary
        if [ "$(uname -s)" = "Darwin" ] && command -v xattr &>/dev/null; then
            xattr -cr "$INSTALL_DIR/$BINARY" 2>/dev/null || true
        fi

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

find_gui_asset() {
    local api_url
    if [ "$VERSION" = "latest" ]; then
        api_url="https://api.github.com/repos/${REPO}/releases/latest"
    else
        api_url="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
    fi

    local pattern="$1"
    GUI_ASSET_URL=$(curl -fsSL "$api_url" 2>/dev/null | grep -o "\"browser_download_url\": *\"[^\"]*${pattern}[^\"]*\"" | head -1 | grep -o 'https://[^"]*')
}

install_gui() {
    step "Installing Desktop GUI..."
    local gui_os="$(uname -s)"
    local gui_arch="$(uname -m)"

    case "$gui_os" in
        Darwin)
            # Determine arch pattern for macOS
            local arch_pattern
            case "$gui_arch" in
                arm64|aarch64) arch_pattern="aarch64" ;;
                x86_64|amd64) arch_pattern="x64" ;;
                *) warn "Unsupported architecture for GUI: $gui_arch"; return 1 ;;
            esac

            find_gui_asset "${arch_pattern}\.dmg"
            if [ -z "${GUI_ASSET_URL:-}" ]; then
                warn "No macOS GUI build found for $gui_arch"
                return 1
            fi

            info "Downloading macOS DMG..."
            local dmg_path
            dmg_path=$(mktemp /tmp/passman-gui.XXXXXX.dmg)
            if ! curl -fsSL -o "$dmg_path" "$GUI_ASSET_URL"; then
                warn "Failed to download GUI"; rm -f "$dmg_path"; return 1
            fi

            info "Mounting DMG..."
            local mount_point
            mount_point=$(hdiutil attach "$dmg_path" -nobrowse 2>/dev/null | grep -o '/Volumes/.*' | head -1)
            if [ -z "$mount_point" ]; then
                warn "Failed to mount DMG"; rm -f "$dmg_path"; return 1
            fi

            local app_name
            app_name=$(ls "$mount_point" | grep '\.app$' | head -1)
            if [ -z "$app_name" ]; then
                warn "No .app found in DMG"; hdiutil detach "$mount_point" -quiet 2>/dev/null; rm -f "$dmg_path"; return 1
            fi

            info "Installing $app_name to /Applications..."
            cp -R "$mount_point/$app_name" "/Applications/$app_name"
            hdiutil detach "$mount_point" -quiet 2>/dev/null
            rm -f "$dmg_path"

            # Strip quarantine attribute so Gatekeeper doesn't block the app
            xattr -cr "/Applications/$app_name" 2>/dev/null || true

            success "Installed /Applications/$app_name"
            ;;

        Linux)
            find_gui_asset "\.AppImage"
            if [ -z "${GUI_ASSET_URL:-}" ]; then
                warn "No Linux GUI build found"
                return 1
            fi

            info "Downloading AppImage..."
            local appimage_dir="$HOME/.local/bin"
            mkdir -p "$appimage_dir"
            local appimage_path="$appimage_dir/Passman.AppImage"
            if ! curl -fsSL -o "$appimage_path" "$GUI_ASSET_URL"; then
                warn "Failed to download GUI"; return 1
            fi

            chmod +x "$appimage_path"
            success "Installed $appimage_path"
            ;;

        *)
            warn "GUI install not supported on $gui_os (download manually from GitHub Releases)"
            return 1
            ;;
    esac
}

offer_gui_install() {
    # If GUI=1 is set, install without prompting
    if [ "${GUI:-0}" = "1" ]; then
        install_gui
        return
    fi

    # Only prompt in interactive terminal (not piped)
    if [ -t 0 ]; then
        echo ""
        echo -e "  ${BOLD}Desktop GUI available!${NC}"
        echo -n "  Install Passman Desktop GUI too? [y/N] "
        read -r response
        case "$response" in
            [yY]|[yY][eE][sS]) install_gui ;;
            *) info "Skipping GUI install. You can install later with: GUI=1 bash install.sh" ;;
        esac
    fi
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
offer_gui_install
print_config

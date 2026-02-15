#!/usr/bin/env bash
set -euo pipefail

# Passman build script
# Usage: ./scripts/build.sh [mcp|gui|all]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

build_mcp() {
    echo "==> Building MCP server (release)..."
    cargo build --release -p passman-mcp-server
    echo "    Binary: target/release/passman-mcp-server"
    echo "    Version: $(./target/release/passman-mcp-server --version)"
}

build_gui() {
    echo "==> Installing frontend dependencies..."
    cd "$ROOT_DIR/app"
    npm install

    echo "==> Building frontend..."
    npx vite build

    echo "==> Building Tauri app..."
    npx tauri build

    echo "    App bundle: app/src-tauri/target/release/bundle/"
}

run_tests() {
    echo "==> Running tests..."
    cd "$ROOT_DIR"
    cargo test --workspace
    cargo test -p passman-vault --test lifecycle
    echo "    All tests passed!"
}

case "${1:-all}" in
    mcp)
        cd "$ROOT_DIR"
        build_mcp
        ;;
    gui)
        build_gui
        ;;
    test)
        run_tests
        ;;
    all)
        cd "$ROOT_DIR"
        run_tests
        build_mcp
        build_gui
        ;;
    *)
        echo "Usage: $0 [mcp|gui|test|all]"
        exit 1
        ;;
esac

echo "==> Done!"

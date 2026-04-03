#!/bin/bash
set -e

# kuro-sign installer
# Usage: curl -fsSL https://raw.githubusercontent.com/TeamSHIRO/kuro-sign/main/install.sh | bash

REPO_URL="https://github.com/TeamSHIRO/kuro-sign.git"
INSTALL_DIR="$HOME/.local/bin"
BUILD_DIR="/tmp/kuro-sign-build"

# ── Colours ────────────────────────────────────────────────────────────────────
T_RED='\033[1;31m'
T_GREEN='\033[1;32m'
T_YELLOW='\033[1;33m'
T_BLUE='\033[1;34m'

RESET='\033[0m'
BOLD='\033[1m'

B_RED='\033[1;41m'
B_GREEN='\033[1;42m'
B_YELLOW='\033[1;43m'
B_BLUE='\033[1;44m'

info()    { echo -e "${B_BLUE} INFO ${RESET} $*"; }
success() { echo -e "${B_GREEN}  OK  ${RESET} $*"; }
warn()    { echo -e "${B_YELLOW} WARN ${RESET} $*"; }
error()   { echo -e "${B_RED} ERR! ${RESET} $*" >&2; exit 1; }

# ── Dependency check ───────────────────────────────────────────────────────────
check_dep() {
    command -v "$1" &>/dev/null || error "Required dependency '$1' is not installed. Please install it and try again."
}

info "Checking dependencies..."
check_dep git
check_dep cmake
check_dep make

# Check for OpenSSL headers
if ! pkg-config --exists openssl 2>/dev/null; then
    warn "pkg-config could not find OpenSSL. The build may fail."
    warn "Install it with: sudo apt install libssl-dev  OR  sudo dnf install openssl-devel"
fi

success "All dependencies found."

# ── Clone (skip if already inside the source repo) ────────────────────────────
if [[ -f "$(pwd)/CMakeLists.txt" ]] && grep -q "KURO_SIGNER" "$(pwd)/CMakeLists.txt" 2>/dev/null; then
    info "Source directory detected. Building in place..."
    BUILD_DIR="$(pwd)"
else
    info "Cloning kuro-sign into $BUILD_DIR..."
    rm -rf "$BUILD_DIR"
    git clone --depth=1 "$REPO_URL" "$BUILD_DIR"
    cd "$BUILD_DIR"
fi

# ── Build ──────────────────────────────────────────────────────────────────────
info "Configuring with CMake..."
cmake -S "$BUILD_DIR" -B "$BUILD_DIR/build" -DCMAKE_BUILD_TYPE=Release

info "Building..."
cmake --build "$BUILD_DIR/build" --parallel "$(nproc)"

success "Build complete."

# ── Install ────────────────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
cp "$BUILD_DIR/build/kuro-sign" "$INSTALL_DIR/kuro-sign"
chmod +x "$INSTALL_DIR/kuro-sign"

success "kuro-sign installed to $INSTALL_DIR/kuro-sign"

# ── PATH check ────────────────────────────────────────────────────────────────
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    warn "$INSTALL_DIR is not in your PATH."
    echo ""
    echo "  Add it by appending the following line to your shell config:"
    echo ""
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    SHELL_RC=""
    if [[ "$SHELL" == */zsh ]]; then
        SHELL_RC="$HOME/.zshrc"
    elif [[ "$SHELL" == */bash ]]; then
        SHELL_RC="$HOME/.bashrc"
    fi

    if [[ -n "$SHELL_RC" ]]; then
        read -r -p "  Append it to $SHELL_RC automatically? [y/N] " REPLY </dev/tty
        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            echo "" >> "$SHELL_RC"
            echo "# Added by kuro-sign installer" >> "$SHELL_RC"
            echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$SHELL_RC"
            success "PATH updated in $SHELL_RC. Restart your shell or run: source $SHELL_RC"
        fi
    fi
else
    success "$INSTALL_DIR is already in your PATH."
fi

# ── Cleanup ───────────────────────────────────────────────────────────────────
if [[ "$BUILD_DIR" == "/tmp/kuro-sign-build" ]]; then
    rm -rf "$BUILD_DIR"
fi

echo ""
success "kuro-sign is ready! Try: kuro-sign --help"

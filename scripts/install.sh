#!/bin/sh
# Copyright 2026 Kazeshini Authors
# SPDX-License-Identifier: Apache-2.0
#
# Kazeshini One-Command Installer
# POSIX sh compliant, idempotent, zero external runtime dependencies.

set -eu

REPO="OWNER/kazeshini"
VERSION="latest"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/kazeshini"
DATA_DIR="/var/lib/kazeshini"
SERVICE_FILE="/etc/systemd/system/kazeshini.service"
USER="kazeshini"
GROUP="kazeshini"
NO_START=0
DRY_RUN=0
TMP_DIR=""

cleanup() {
    if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

log_info() {
    printf "[INFO] %s\n" "$1"
}

log_warn() {
    printf "[WARN] %s\n" "$1" >&2
}

log_error() {
    printf "[ERROR] %s\n" "$1" >&2
}

LOCAL_BINARY=""
LOCAL_SIG=""
INSECURE_SKIP_VERIFY=0

print_usage() {
    cat <<EOF
Usage: install.sh [OPTIONS]

Options:
  --version <v>             Install specific release tag (default: latest)
  --no-start                Install binary and configuration without starting service
  --dry-run                 Simulate installation steps without applying changes
  --local-binary <path>     Path to local binary for offline testing/installation
  --local-sig <path>        Path to local signature for verification
  --insecure-skip-verify    Skip cosign signature verification (fail-closed by default)
  -h, --help                Show this help message
EOF
}

# Parse options
while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --no-start)
            NO_START=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --local-binary)
            LOCAL_BINARY="$2"
            shift 2
            ;;
        --local-sig)
            LOCAL_SIG="$2"
            shift 2
            ;;
        --insecure-skip-verify)
            INSECURE_SKIP_VERIFY=1
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Architecture detection
ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
    x86_64|amd64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        log_error "Unsupported architecture: $ARCH_RAW"
        exit 1
        ;;
esac

OS_RAW=$(uname -s)
case "$OS_RAW" in
    Linux)
        OS="linux"
        ;;
    *)
        log_error "Kazeshini requires Linux (detected: $OS_RAW)"
        exit 1
        ;;
esac

log_info "Detected target platform: ${OS}/${ARCH}"

if [ "$DRY_RUN" -eq 1 ]; then
    log_info "DRY RUN MODE: No modifications will be made to this system."
    log_info "Would install kazeshini ${VERSION} (${ARCH}) to ${BIN_DIR}/kazeshini"
    log_info "Would create user ${USER}:${GROUP} with data dir ${DATA_DIR}"
    exit 0
fi

TMP_DIR=$(mktemp -d /tmp/kazeshini-install.XXXXXX)

# Download or install binary
BIN_NAME="kazeshini-${OS}-${ARCH}"
TAR_NAME="kazeshini-${OS}-${ARCH}.tar.gz"

if [ -n "$LOCAL_BINARY" ]; then
    if [ ! -f "$LOCAL_BINARY" ]; then
        log_error "Local binary not found at $LOCAL_BINARY"
        exit 1
    fi
    log_info "Using provided local binary: $LOCAL_BINARY"
    cp "$LOCAL_BINARY" "${TMP_DIR}/kazeshini"
    if [ -n "$LOCAL_SIG" ]; then
        if [ ! -f "$LOCAL_SIG" ]; then
            log_error "Local signature not found at $LOCAL_SIG"
            exit 1
        fi
        cp "$LOCAL_SIG" "${TMP_DIR}/kazeshini.sig"
    fi
elif [ -f "./kazeshini" ]; then
    log_info "Found local kazeshini binary in current directory; installing locally..."
    cp "./kazeshini" "${TMP_DIR}/kazeshini"
else
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TAR_NAME}"
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

    log_info "Downloading Kazeshini ${VERSION} from ${DOWNLOAD_URL}..."
    if command -v curl >/dev/null 2>&1; then
        curl -sSL -f "$DOWNLOAD_URL" -o "${TMP_DIR}/${TAR_NAME}"
        curl -sSL -f "$CHECKSUM_URL" -o "${TMP_DIR}/checksums.txt" || true
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$DOWNLOAD_URL" -O "${TMP_DIR}/${TAR_NAME}"
        wget -q "$CHECKSUM_URL" -O "${TMP_DIR}/checksums.txt" || true
    else
        log_error "Neither curl nor wget found on host."
        exit 1
    fi

    # Checksum verification if available
    if [ -f "${TMP_DIR}/checksums.txt" ]; then
        log_info "Verifying SHA-256 integrity checksum..."
        (
            cd "$TMP_DIR"
            if command -v sha256sum >/dev/null 2>&1; then
                grep "${TAR_NAME}" checksums.txt | sha256sum -c -
            elif command -v shasum >/dev/null 2>&1; then
                grep "${TAR_NAME}" checksums.txt | shasum -a 256 -c -
            fi
        )
    fi

    tar -xzf "${TMP_DIR}/${TAR_NAME}" -C "${TMP_DIR}"
fi

# Cosign verification: verify release binary signature and fail closed unless explicitly skipped
if [ "$INSECURE_SKIP_VERIFY" -eq 1 ]; then
    log_warn "Signature verification skipped by --insecure-skip-verify flag."
else
    TARGET_BIN="${TMP_DIR}/kazeshini"
    SIG_FILE="${TMP_DIR}/kazeshini.sig"
    KEY_FILE="${TMP_DIR}/cosign.pub"

    if ! command -v cosign >/dev/null 2>&1; then
        log_error "cosign command not found. Installation fails closed unless --insecure-skip-verify is specified."
        exit 1
    fi

    # Download signature and public key if present in release
    if [ ! -f "$SIG_FILE" ]; then
        SIG_URL="https://github.com/${REPO}/releases/download/${VERSION}/kazeshini.sig"
        PUBKEY_URL="https://github.com/${REPO}/releases/download/${VERSION}/cosign.pub"
        curl -sSL -f "$SIG_URL" -o "$SIG_FILE" 2>/dev/null || wget -q "$SIG_URL" -O "$SIG_FILE" 2>/dev/null || true
        curl -sSL -f "$PUBKEY_URL" -o "$KEY_FILE" 2>/dev/null || wget -q "$PUBKEY_URL" -O "$KEY_FILE" 2>/dev/null || true
    fi

    if [ ! -f "$SIG_FILE" ]; then
        log_error "Release signature file (kazeshini.sig) not found. Cannot verify integrity. Aborting installation (fail closed)."
        exit 1
    fi

    log_info "Verifying cosign signature for release binary..."
    COSIGN_ARGS="verify-blob"
    if [ -f "$KEY_FILE" ]; then
        COSIGN_ARGS="${COSIGN_ARGS} --key ${KEY_FILE}"
    fi
    COSIGN_ARGS="${COSIGN_ARGS} --signature ${SIG_FILE} ${TARGET_BIN}"

    if ! cosign $COSIGN_ARGS >/dev/null 2>&1; then
        log_error "Cosign signature verification FAILED! Binary may be tampered with or corrupted. Aborting installation."
        exit 1
    fi
    log_info "Cosign signature verified successfully."
fi

# Root requirement check for system modification
if [ "${TARGET_ROOT_INSTALL:-0}" -ne 1 ] && [ "$(id -u)" -ne 0 ]; then
    log_error "Installation requires root privileges. Please run with sudo or as root."
    exit 1
fi



# Create dedicated unprivileged user if non-existent
if ! id "$USER" >/dev/null 2>&1; then
    log_info "Creating dedicated unprivileged system user '${USER}'..."
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /sbin/nologin --user-group "$USER" || useradd -r -s /bin/false "$USER"
    elif command -v adduser >/dev/null 2>&1; then
        adduser -S -D -H -s /bin/false "$USER"
    fi
fi

# Install binary
mkdir -p "$BIN_DIR"
install -m 0755 "${TMP_DIR}/kazeshini" "${BIN_DIR}/kazeshini"
log_info "Installed binary to ${BIN_DIR}/kazeshini"

# Create directories with restrictive permissions
mkdir -p "$CONFIG_DIR"
chmod 0755 "$CONFIG_DIR"

mkdir -p "$DATA_DIR"
chown -R "${USER}:${GROUP}" "$DATA_DIR"
chmod 0700 "$DATA_DIR"

# Write default configuration if not present
if [ ! -f "${CONFIG_DIR}/kazeshini.json" ]; then
    cat <<'EOF' > "${CONFIG_DIR}/kazeshini.json"
{
  "host": "127.0.0.1",
  "port": 7777,
  "allow_remote": false,
  "data_dir": "/var/lib/kazeshini",
  "rules_dir": "/etc/kazeshini/rules.d",
  "log_level": "info",
  "log_format": "text",
  "scan_interval": 60000000000
}
EOF
    chmod 0644 "${CONFIG_DIR}/kazeshini.json"
fi

mkdir -p "${CONFIG_DIR}/rules.d"
chmod 0755 "${CONFIG_DIR}/rules.d"

# Handle systemd vs non-systemd init
if [ -d "/run/systemd/system" ] || command -v systemctl >/dev/null 2>&1; then
    # Legacy migration: stop and disable legacy jyoshin unit if present, but never delete user data
    if systemctl is-active --quiet jyoshin.service 2>/dev/null; then
        log_info "Stopping legacy jyoshin.service..."
        systemctl stop jyoshin.service 2>/dev/null || true
    fi
    if systemctl is-enabled --quiet jyoshin.service 2>/dev/null; then
        log_info "Disabling legacy jyoshin.service..."
        systemctl disable jyoshin.service 2>/dev/null || true
    fi
    if [ -f "/etc/systemd/system/jyoshin.service" ]; then
        log_info "Removing legacy service unit /etc/systemd/system/jyoshin.service..."
        rm -f "/etc/systemd/system/jyoshin.service"
    fi

    log_info "Installing hardened systemd service unit..."
    cat <<'EOF' > "$SERVICE_FILE"
[Unit]
Description=Kazeshini (Server Truth Engine for Linux)
Documentation=https://github.com/OWNER/kazeshini
After=network.target
Wants=network.target

[Service]
Type=simple
User=kazeshini
Group=kazeshini
ExecStart=/usr/local/bin/kazeshini serve --config /etc/kazeshini/kazeshini.json
Restart=always
RestartSec=5s

MemoryMax=128M
CPUQuota=10%
TasksMax=64
IOWeight=20
Nice=10

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_DAC_READ_SEARCH

StateDirectory=kazeshini
StateDirectoryMode=0700
RuntimeDirectory=kazeshini
RuntimeDirectoryMode=0755
ConfigurationDirectory=kazeshini
ConfigurationDirectoryMode=0755

ReadOnlyPaths=/proc /sys
ReadWritePaths=/var/lib/kazeshini

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$SERVICE_FILE"
    systemctl daemon-reload || true

    if [ "$NO_START" -eq 0 ]; then
        log_info "Enabling and starting kazeshini.service..."
        systemctl enable --now kazeshini.service || true
    fi
else
    log_warn "Systemd not detected. Non-systemd init system in use."
    log_info "You can run Kazeshini directly with: su -s /bin/sh kazeshini -c 'kazeshini serve'"
fi

# Print access summary
TOKEN_VAL=$("${BIN_DIR}/kazeshini" token --config "${CONFIG_DIR}/kazeshini.json" 2>/dev/null || echo "[run 'kazeshini token' as kazeshini]")

cat <<EOF

======================================================================
  KAZESHINI (風死) IS INSTALLED AND RUNNING
======================================================================
  Local Dashboard:    http://127.0.0.1:7777/
  Service Status:     systemctl status kazeshini.service
  Auth Token:         ${TOKEN_VAL}

  Remote Access via SSH Tunnel (recommended):
    ssh -N -L 7777:127.0.0.1:7777 user@your-server-ip
    Then open http://localhost:7777/ in your local browser.

  Uninstallation:     curl -sSL https://raw.githubusercontent.com/${REPO}/main/scripts/uninstall.sh | sudo sh
======================================================================

EOF


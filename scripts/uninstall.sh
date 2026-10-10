#!/bin/sh
# Copyright 2026 Jyōshin Authors
# SPDX-License-Identifier: Apache-2.0
#
# Jyōshin Uninstaller
# Completely and safely removes Jyōshin binaries, systemd units, and data directories.

set -eu

BIN_PATH="/usr/local/bin/jyoshin"
CONFIG_DIR="/etc/jyoshin"
DATA_DIR="/var/lib/jyoshin"
SERVICE_FILE="/etc/systemd/system/jyoshin.service"
USER="jyoshin"
GROUP="jyoshin"

log_info() {
    printf "[INFO] %s\n" "$1"
}

DRY_RUN=0

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN=1
            ;;
        --help|-h)
            printf "Usage: %s [--dry-run]\n" "$0"
            exit 0
            ;;
    esac
done

if [ "$DRY_RUN" -eq 1 ]; then
    log_info "DRY RUN MODE: No modifications will be made to this system."
    log_info "Would stop and disable jyoshin.service"
    log_info "Would remove $BIN_PATH, $CONFIG_DIR, $DATA_DIR, and $SERVICE_FILE"
    log_info "Would remove user and group $USER"
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    printf "[ERROR] Uninstallation requires root privileges. Please run with sudo or as root.\n" >&2
    exit 1
fi

log_info "Initiating uninstallation of Jyōshin..."

# Stop and disable systemd service if running
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet jyoshin.service 2>/dev/null; then
        log_info "Stopping jyoshin.service..."
        systemctl stop jyoshin.service || true
    fi
    if systemctl is-enabled --quiet jyoshin.service 2>/dev/null; then
        log_info "Disabling jyoshin.service..."
        systemctl disable jyoshin.service || true
    fi
fi

# Remove systemd service file
if [ -f "$SERVICE_FILE" ]; then
    rm -f "$SERVICE_FILE"
    log_info "Removed service unit: $SERVICE_FILE"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || true
    fi
fi

# Remove binary
if [ -f "$BIN_PATH" ]; then
    rm -f "$BIN_PATH"
    log_info "Removed binary: $BIN_PATH"
fi

# Remove state and configuration
if [ -d "$DATA_DIR" ]; then
    rm -rf "$DATA_DIR"
    log_info "Removed persistent data directory: $DATA_DIR"
fi

if [ -d "$CONFIG_DIR" ]; then
    rm -rf "$CONFIG_DIR"
    log_info "Removed configuration directory: $CONFIG_DIR"
fi

# Remove system user if existent
if id "$USER" >/dev/null 2>&1; then
    if command -v userdel >/dev/null 2>&1; then
        userdel "$USER" 2>/dev/null || true
        log_info "Removed system user: $USER"
    elif command -v deluser >/dev/null 2>&1; then
        deluser "$USER" 2>/dev/null || true
        log_info "Removed system user: $USER"
    fi
fi

log_info "Jyōshin has been completely uninstalled. No residual files remain."

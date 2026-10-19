#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop kazeshini.service || true
    systemctl disable kazeshini.service || true
fi


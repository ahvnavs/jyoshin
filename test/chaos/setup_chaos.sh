#!/bin/sh
# Copyright 2026 Jyōshin Authors
# SPDX-License-Identifier: Apache-2.0
#
# Chaos Host Fixture Script for Jyōshin
# Builds a deliberately messy Linux server environment to test detection,
# provenance graph reconstruction, ranking, and report fidelity.
# Also serves as the standard demo environment.

set -eu

ROOT_DIR="${1:-/tmp/jyoshin-chaos-root}"
echo "Building chaos fixture environment in: $ROOT_DIR"

mkdir -p "$ROOT_DIR/etc" \
         "$ROOT_DIR/proc" \
         "$ROOT_DIR/sys" \
         "$ROOT_DIR/var/lib/dpkg" \
         "$ROOT_DIR/usr/local/bin" \
         "$ROOT_DIR/opt/legacy-app/bin" \
         "$ROOT_DIR/opt/node-v14.17.0/bin" \
         "$ROOT_DIR/opt/node-v18.19.0/bin" \
         "$ROOT_DIR/opt/python-3.8/bin" \
         "$ROOT_DIR/opt/python-3.11/bin" \
         "$ROOT_DIR/opt/jdk-8/bin" \
         "$ROOT_DIR/opt/jdk-17/bin" \
         "$ROOT_DIR/var/log/stale"

# 1. Host identity
cat << 'EOF' > "$ROOT_DIR/etc/os-release"
NAME="Ubuntu"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.4 LTS"
VERSION_ID="22.04"
EOF

# 2. Manual unmanaged binaries in /usr/local/bin and /opt
echo '#!/bin/sh\necho "manual utility"' > "$ROOT_DIR/usr/local/bin/custom-collector"
chmod 755 "$ROOT_DIR/usr/local/bin/custom-collector"

echo '#!/bin/sh\necho "legacy service"' > "$ROOT_DIR/opt/legacy-app/bin/server"
chmod 755 "$ROOT_DIR/opt/legacy-app/bin/server"

# 3. Multiple Python / Node / Java versions (some EOL)
echo '#!/bin/sh\necho "Python 3.8.10"' > "$ROOT_DIR/opt/python-3.8/bin/python3"
chmod 755 "$ROOT_DIR/opt/python-3.8/bin/python3"

echo '#!/bin/sh\necho "Python 3.11.8"' > "$ROOT_DIR/opt/python-3.11/bin/python3"
chmod 755 "$ROOT_DIR/opt/python-3.11/bin/python3"

echo '#!/bin/sh\necho "v14.17.0"' > "$ROOT_DIR/opt/node-v14.17.0/bin/node"
chmod 755 "$ROOT_DIR/opt/node-v14.17.0/bin/node"

echo '#!/bin/sh\necho "v18.19.0"' > "$ROOT_DIR/opt/node-v18.19.0/bin/node"
chmod 755 "$ROOT_DIR/opt/node-v18.19.0/bin/node"

echo '#!/bin/sh\necho "openjdk version 1.8.0_382"' > "$ROOT_DIR/opt/jdk-8/bin/java"
chmod 755 "$ROOT_DIR/opt/jdk-8/bin/java"

echo '#!/bin/sh\necho "openjdk version 17.0.9"' > "$ROOT_DIR/opt/jdk-17/bin/java"
chmod 755 "$ROOT_DIR/opt/jdk-17/bin/java"

# 4. Mock dpkg status
cat << 'EOF' > "$ROOT_DIR/var/lib/dpkg/status"
Package: bash
Status: install ok installed
Priority: required
Section: shells
Installed-Size: 1500
Maintainer: Ubuntu Developers
Architecture: amd64
Version: 5.1-6ubuntu1

Package: openssl
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 2100
Maintainer: Ubuntu Developers
Architecture: amd64
Version: 3.0.2-0ubuntu1.15
EOF

# 5. Stale log waste
head -c 1048576 </dev/zero > "$ROOT_DIR/var/log/stale/orphaned_crash_dump.log" 2>/dev/null || true

echo "Chaos fixture generation complete in $ROOT_DIR."


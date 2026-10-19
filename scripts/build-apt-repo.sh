#!/bin/bash
# scripts/build-apt-repo.sh - Builds a signed Debian/Ubuntu APT repository
set -euo pipefail

REPO_DIR="${1:-./dist/apt}"
GPG_KEY_ID="${2:-}"

mkdir -p "${REPO_DIR}/dists/stable/main/binary-amd64"
mkdir -p "${REPO_DIR}/dists/stable/main/binary-arm64"
mkdir -p "${REPO_DIR}/pool/main"

echo "=== Copying Debian packages to pool ==="
if compgen -G "dist/*.deb" > /dev/null; then
    cp dist/*.deb "${REPO_DIR}/pool/main/"
fi

echo "=== Generating Packages and Release files ==="
cd "${REPO_DIR}"
dpkg-scanpackages --arch amd64 pool/main > dists/stable/main/binary-amd64/Packages
gzip -k -f dists/stable/main/binary-amd64/Packages

dpkg-scanpackages --arch arm64 pool/main > dists/stable/main/binary-arm64/Packages
gzip -k -f dists/stable/main/binary-arm64/Packages

cat << 'EOF' > dists/stable/Release
Origin: Kazeshini
Label: Kazeshini
Suite: stable
Codename: stable
Architectures: amd64 arm64
Components: main
Description: Kazeshini Server Truth Engine APT Repository
EOF

if [ -n "${GPG_KEY_ID}" ]; then
    echo "=== Signing Release file with GPG key ${GPG_KEY_ID} ==="
    gpg --default-key "${GPG_KEY_ID}" -abs -o dists/stable/Release.gpg dists/stable/Release
    gpg --default-key "${GPG_KEY_ID}" --clearsign -o dists/stable/InRelease dists/stable/Release
else
    echo "=== GPG_KEY_ID not specified; Release file left unsigned for local testing ==="
fi

echo "APT repository generated successfully at ${REPO_DIR}"


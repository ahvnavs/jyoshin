#!/bin/bash
# scripts/build-rpm-repo.sh - Builds a signed RPM/DNF repository
set -euo pipefail

REPO_DIR="${1:-./dist/rpm}"
GPG_KEY_ID="${2:-}"

mkdir -p "${REPO_DIR}/x86_64"
mkdir -p "${REPO_DIR}/aarch64"

echo "=== Copying RPM packages to repository ==="
if compgen -G "dist/*x86_64.rpm" > /dev/null; then
    cp dist/*x86_64.rpm "${REPO_DIR}/x86_64/"
fi
if compgen -G "dist/*aarch64.rpm" > /dev/null; then
    cp dist/*aarch64.rpm "${REPO_DIR}/aarch64/"
fi

echo "=== Generating RPM repodata ==="
if command -v createrepo_c >/dev/null 2>&1; then
    createrepo_c "${REPO_DIR}/x86_64"
    createrepo_c "${REPO_DIR}/aarch64"
elif command -v createrepo >/dev/null 2>&1; then
    createrepo "${REPO_DIR}/x86_64"
    createrepo "${REPO_DIR}/aarch64"
else
    echo "Notice: createrepo or createrepo_c required on host to generate repomd.xml."
fi

if [ -n "${GPG_KEY_ID}" ]; then
    echo "=== Signing repomd.xml with GPG key ${GPG_KEY_ID} ==="
    gpg --detach-sign --armor --default-key "${GPG_KEY_ID}" "${REPO_DIR}/x86_64/repodata/repomd.xml"
    gpg --detach-sign --armor --default-key "${GPG_KEY_ID}" "${REPO_DIR}/aarch64/repodata/repomd.xml"
fi

echo "RPM repository generated successfully at ${REPO_DIR}"


# Kazeshini Real-System Verification Runbook (Phase 32)

This document provides exact, reproducible shell scripts to test Kazeshini on a real Linux host or virtual machine across Ubuntu, Debian, Fedora, Alpine, and Arch.

---

## 1. Ubuntu / Debian Host Verification (systemd + installer)

Run as an unprivileged user with sudo access:

```bash
# 1. Build and install locally
go build -o kazeshini ./cmd/kazeshini
go build -o kazeshini-actuator ./cmd/kazeshini-actuator
sudo ./scripts/install.sh --local-binary ./kazeshini

# 2. Verify systemd service status
sudo systemctl status kazeshini

# 3. Test CLI tools
kazeshini doctor
kazeshini briefing
kazeshini facts --json
kazeshini check run disk-inodes --fail-on warn
```

### Paste Format for Real Host Output:
```text
=== SYSTEM IDENTITY ===
Host: [hostname]
OS: [PRETTY_NAME from /etc/os-release]
Kernel: [uname -r]

=== SYSTEMCTL STATUS ===
[Paste: sudo systemctl status kazeshini | head -n 15]

=== KAZESHINI DOCTOR ===
[Paste: kazeshini doctor]

=== KAZESHINI BRIEFING ===
[Paste: kazeshini briefing | head -n 25]
```

---

## 2. Actuator Real-Host Execution & Failure Injection

The Actuator is disabled by default. Enable it explicitly for experimental testing:

```bash
# 1. Enable actuator service
sudo systemctl enable --now kazeshini-actuator

# 2. Plan installation of a harmless package (e.g. 'sl' or 'tree')
kazeshini software plan --install tree

# 3. Approve plan with ed25519 approver key
kazeshini-actuator approve --plan-file plan.json --key /etc/kazeshini/approver.key --out envelope.json

# 4. Submit envelope to actuator socket
sudo kazeshini-actuator submit --envelope envelope.json

# 5. Verify package status and audit log
tree --version
sudo kazeshini audit verify
```

### Failure Injection Test A: Package Lock Held
```bash
# Hold dpkg lock in background
sudo fuser -k /var/lib/dpkg/lock-frontend || true
sudo flock /var/lib/dpkg/lock-frontend sleep 60 &
LOCK_PID=$!

# Attempt plan execution: Must abort cleanly in preflight with "lock held"
sudo kazeshini-actuator submit --envelope envelope.json

# Clean up
kill $LOCK_PID
```

### Failure Injection Test B: Disk Full Preflight Abort
```bash
# Fill ephemeral test partition or simulate <200MB free space
# Verify actuator refuses to begin step execution
```

---

## 3. Kubernetes DaemonSet under Kind or K3s

```bash
# 1. Create a clean Kind cluster
kind create cluster --name kazeshini-test

# 2. Build and load distroless container image
docker build -t kazeshini:v0.1.0 .
kind load docker-image kazeshini:v0.1.0 --name kazeshini-test

# 3. Deploy DaemonSet
kubectl create namespace kazeshini-system
kubectl apply -f deploy/kubernetes/daemonset.yaml

# 4. Verify pod status
kubectl get pods -n kazeshini-system -o wide
kubectl logs -n kazeshini-system -l app.kubernetes.io/name=kazeshini --tail=20
```

### Paste Format for Kubernetes Output:
```text
=== KIND / K3S CLUSTER ===
[Paste: kubectl cluster-info]

=== POD STATUS ===
[Paste: kubectl get pods -n kazeshini-system -o wide]

=== DAEMONSET LOGS ===
[Paste: kubectl logs -n kazeshini-system -l app.kubernetes.io/name=kazeshini --tail=20]
```

---

## 4. Multi-Distribution Test Matrix

Run tests on each OS container:
```bash
for distro in ubuntu:22.04 debian:12 fedora:39 alpine:3.19 archlinux:latest; do
  echo "Testing on $distro..."
  docker run --rm -v $(pwd):/workspace -w /workspace $distro sh -c "
    if command -v apt-get >/dev/null; then apt-get update && apt-get install -y procps; fi
    ./kazeshini version
    ./kazeshini facts --json | grep host_id
  "
done
```


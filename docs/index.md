# Quick Start

Kazeshini tells you, on any Linux server with no setup, what is installed, what is running, what is exposed, what is out of date, and what changed, and how sure it is. Read-only, one binary.

---

## 3-Step Quick Start

### Step 1: Download the Static Binary
```bash
curl -fsSLO https://releases.example.org/kazeshini-linux-amd64
chmod +x kazeshini-linux-amd64
```

### Step 2: Verify Integrity (Offline or Checksum)
```bash
curl -fsSL https://releases.example.org/checksums.txt | sha256sum --check --ignore-missing
./kazeshini-linux-amd64 verify --checksum-file checksums.txt
```

### Step 3: Run (Zero Setup, No Root Required)
```bash
./kazeshini-linux-amd64
```

Kazeshini immediately prints the server overview and starts an ephemeral, loopback-bound web dashboard on 127.0.0.1.
To print and exit immediately:
```bash
./kazeshini-linux-amd64 --once
```


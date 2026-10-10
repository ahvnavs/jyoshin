# Jyōshin Roadmap

## Phase 1: Repository Foundation (Current)
- [x] Initial repository scaffolding and module initialization
- [x] Core domain model: Certainty, Evidence, Node, Edge, Finding
- [x] Safe unprivileged CLI (`serve`, `version`, `doctor`, `snapshot`)
- [x] Embedded UI placeholder and versioned REST endpoints (`/api/v1/health`, `/api/v1/version`)
- [x] Build tooling, cross-compilation (`linux/amd64`, `linux/arm64`), CI workflows, and CNCF governance docs

## Phase 2: Core Sensors & Read-Only Collectors (v0.2.0)
- [ ] Safe `/proc` collectors: processes, threads, file descriptors, CPU, memory
- [ ] Safe `/sys` collectors: network interfaces, storage devices
- [ ] Package manager inspectors (dpkg, rpm, pacman, apk)
- [ ] Language ecosystem inspectors (pip, npm, cargo, gem)
- [ ] Systemd unit and timer sensors
- [ ] Network socket table parsing (`/proc/net/tcp`, `udp`)

## Phase 3: Provenance Graph & Deterministic Rule Engine (v0.4.0)
- [ ] In-memory provenance graph assembly
- [ ] Edge construction: file $\to$ pkg $\to$ process $\to$ service $\to$ port $\to$ connection
- [ ] Declarative YAML rule engine evaluating graph patterns
- [ ] Finding generator with What, So What, Now What, Proof

## Phase 4: Embedded Store, Statistics & Diff Engine (v0.6.0)
- [ ] Embedded embedded persistence (pure Go KV / SQLite or BoltDB)
- [ ] Snapshot differencing (detect mutations across time)
- [ ] Linear regression resource forecaster
- [ ] Baseline anomaly detector

## Phase 5: Cyber-Retro Dark ASCII UI & Live Stream (v0.8.0)
- [ ] Full JetBrains Mono character grid UI
- [ ] SSE (Server-Sent Events) live graph/finding streams
- [ ] Keyboard navigation, filtering, export functionality

## Phase 6: Production Hardening & v1.0.0 Release
- [ ] Packaging: systemd unit, deb, rpm, alpine packages, standalone static archives
- [ ] Multi-distro compatibility matrix validation
- [ ] Zero-allocation and low-overhead profiling
- [ ] v1.0.0 General Availability


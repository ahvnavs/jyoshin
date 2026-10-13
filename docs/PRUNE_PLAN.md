# Kazeshini Prune Plan (Phase 33)

> **PURPOSE STATEMENT:**
> "Kazeshini tells you, on any Linux server with no setup, what is installed, what is running, what is exposed, what is out of date, and what changed, and how sure it is. Read-only, one binary."

This document inventories every CLI command, API route, UI page/view, doc file, rule, platform signature, configuration option, and dependency in Kazeshini. Each item is strictly classified as **KEEP**, **MERGE**, **EXPERIMENTAL**, or **REMOVE** with a one-line reason evaluated directly against the PURPOSE statement.

**Safety checkpoint:**
- Git tag: `pre-prune` created on clean tree
- Git branch: `cleanup` checked out
- **STOP FOR USER APPROVAL**: No code or files are removed until explicitly approved.

---

## 1. Inventory Summary Counts

| Category | Count | Classification Breakdown |
| :--- | :--- | :--- |
| **CLI Commands** | **26** | KEEP: 13, MERGE: 5, EXPERIMENTAL: 8, REMOVE: 0 |
| **API Routes** | **46** | KEEP: 36, MERGE: 7, EXPERIMENTAL: 3, REMOVE: 0 |
| **UI Views / Pages** | **14** | KEEP: 6, MERGE: 6, EXPERIMENTAL: 1, REMOVE: 1 |
| **Documentation Files** | **30** | KEEP: 20, MERGE: 6, EXPERIMENTAL: 4, REMOVE: 0 |
| **Rules** | **20** | KEEP: 18, MERGE: 2, EXPERIMENTAL: 0, REMOVE: 0 |
| **Platform Signatures** | **48** | KEEP: 42, MERGE: 0, EXPERIMENTAL: 0, REMOVE: 6 |
| **Config Options** | **15** | KEEP: 12, MERGE: 1, EXPERIMENTAL: 2, REMOVE: 0 |
| **Dependencies** | **6** | KEEP: 3, MERGE: 0, EXPERIMENTAL: 3, REMOVE: 0 |
| **TOTAL** | **205** | |

---

## 2. CLI Commands (26 Total)

### A. Core Engine: `kazeshini` (18 commands / subcommands)

| CLI Command | Classification | One-Line Reason vs PURPOSE |
| :--- | :--- | :--- |
| `kazeshini version` | **KEEP** | Essential provenance identifying binary version, commit, and build environment. |
| `kazeshini doctor` | **KEEP** | Directly reports sensor coverage honesty and host visibility without setup. |
| `kazeshini briefing` | **KEEP** | Core plain-English summary of what is running, installed, exposed, and changed over SSH. |
| `kazeshini check` / `check list` | **KEEP** | Inspects available read-only diagnostic checks and their attribution. |
| `kazeshini check run` | **KEEP** | Executes read-only checks to answer what is running, exposed, or risky. |
| `kazeshini check symptom` | **KEEP** | Maps observed symptoms to diagnostic checks on any server. |
| `kazeshini open` | **KEEP** | Primary one-line foreground command giving zero-setup dashboard on headless servers. |
| `kazeshini serve` | **KEEP** | Core daemon serving local read-only dashboard and API on loopback. |
| `kazeshini report` | **KEEP** | Generates standalone offline State of this Server reports (HTML/JSON/Markdown). |
| `kazeshini token` | **KEEP** | Displays local API token for secure local client interactions. |
| `kazeshini desired lint` | **KEEP** | Validates declarative desired state file declaring what should be installed/running. |
| `kazeshini desired show` | **MERGE** | Merge into `kazeshini drift` or `kazeshini desired` default to avoid subcommand sprawl. |
| `kazeshini drift` | **KEEP** | Core capability directly reporting what changed between declared and observed host state. |
| `kazeshini plan` | **KEEP** | Produces deterministic, read-only remediation DAG answering what changes to bring server in sync. |
| `kazeshini software list` | **KEEP** | Directly answers what software is installed across all package managers. |
| `kazeshini software info` | **KEEP** | Directly inspects package candidate version, local metadata age, and upstream status. |
| `kazeshini software plan` | **MERGE** | Merge into unified `kazeshini plan --software` to unify DAG and software dry-runs. |
| `kazeshini facts` | **KEEP** | Emits machine-readable facts JSON for Ansible/Terraform describing what is running. |
| `kazeshini rules lint` | **MERGE** | Merge into `kazeshini check lint` or internal validator; end-users rarely author rule YAML. |
| `kazeshini rules eval` | **MERGE** | Merge into `kazeshini check run` with `--rules` flag to simplify top-level CLI surface. |
| `kazeshini snapshot` | **MERGE** | Merge into `kazeshini report --raw` or `kazeshini facts` (currently a lightweight stub). |
| `kazeshini audit verify` | **KEEP** | Verifies cryptographic integrity of the immutable audit hash chain. |
| `kazeshini audit tail` | **KEEP** | Tails tamper-evident audit records locally without egress. |
| `kazeshini agent` | **EXPERIMENTAL** | Optional multi-host agent mode; flag as EXPERIMENTAL so single-host remains primary. |
| `kazeshini controller` | **EXPERIMENTAL** | Optional multi-host controller aggregator; flag as EXPERIMENTAL so single-host stays primary. |

### B. Separate Opt-in Actuator: `kazeshini-actuator` (8 commands)

*Note: Actuator is an optional, separate binary for applying signed plans when explicitly installed with `--with-actuator`.*

| CLI Command | Classification | One-Line Reason vs PURPOSE |
| :--- | :--- | :--- |
| `kazeshini-actuator daemon` | **EXPERIMENTAL** | Opt-in separate process listening on unix socket to execute approved plans. |
| `kazeshini-actuator keygen` | **EXPERIMENTAL** | Generates ed25519 approval keypair for cryptographically signed plans. |
| `kazeshini-actuator approve` | **EXPERIMENTAL** | Approver-role signing tool implementing separation of duties. |
| `kazeshini-actuator apply` | **EXPERIMENTAL** | Submits signed plan envelope to actuator socket with preflight drift check. |
| `kazeshini-actuator status` | **EXPERIMENTAL** | Queries actuator socket status, version, and lock availability. |
| `kazeshini-actuator disable` | **EXPERIMENTAL** | Safety kill-switch disabling actuator executions immediately. |
| `kazeshini-actuator enable` | **EXPERIMENTAL** | Re-enables actuator socket operations after explicit admin authorization. |
| `kazeshini-actuator audit verify` | **EXPERIMENTAL** | Verifies actuator root execution log hash chain and signature proofs. |

---

## 3. API Routes (46 Total)

All routes are registered in `internal/rbac/rbac.go` with explicit role tiers.

| Route Pattern | Required Role | Classification | One-Line Reason vs PURPOSE |
| :--- | :--- | :--- | :--- |
| `GET /api/v1/health` | RoleViewer | **KEEP** | Basic liveness endpoint for zero-setup daemon health. |
| `GET /api/v1/version` | RoleViewer | **KEEP** | Exposes binary version and build provenance. |
| `GET /api/v1/auth/status` | RoleViewer | **KEEP** | Reports authenticated subject, current role, and session state. |
| `GET /api/v1/sensors` | RoleViewer | **KEEP** | Reports active sensor status, errors, and cycle intervals. |
| `GET /api/v1/observations/{sensor}`| RoleViewer | **KEEP** | Direct read-only observation payload per sensor. |
| `GET /api/v1/self` | RoleViewer | **KEEP** | Observes Kazeshini's own CPU, memory, and disk overhead for host safety. |
| `GET /api/v1/inventory` | RoleViewer | **KEEP** | Directly reports what is installed and running on the host. |
| `GET /api/v1/origins` | RoleViewer | **KEEP** | Provenance engine answering how processes and listeners got on the machine. |
| `GET /api/v1/runtimes` | RoleViewer | **KEEP** | Identifies installed language runtimes (Python, Node, Go, JVM, Rust, Ruby). |
| `GET /api/v1/graph` | RoleViewer | **KEEP** | Full topological dependency graph linking packages, units, and processes. |
| `GET /api/v1/graph/node/{id}` | RoleViewer | **KEEP** | Detailed inspection of an individual node in the server graph. |
| `GET /api/v1/graph/why/{id}` | RoleViewer | **KEEP** | Plain-English explanation of why a service/process is running. |
| `GET /api/v1/graph/dependents/{id}`| RoleViewer | **KEEP** | Reports downstream dependents to evaluate blast radius before touching anything. |
| `GET /api/v1/snapshots` | RoleViewer | **MERGE** | Merge snapshot listing into history/changes API to consolidate time-series routes. |
| `GET /api/v1/findings` | RoleViewer | **KEEP** | Categorized rule findings identifying risks, waste, and anomalies. |
| `GET /api/v1/verdict` | RoleViewer | **KEEP** | Top-level host verdict synthesizing overall calm-to-critical state. |
| `GET /api/v1/stream` | RoleViewer | **KEEP** | Server-Sent Events (SSE) stream for real-time dashboard updates without polling. |
| `GET /api/v1/changes` | RoleViewer | **KEEP** | Direct diff answering what changed since boot or previous scan. |
| `GET /api/v1/forecasts` | RoleViewer | **KEEP** | Statistical exhaustion forecasts for disks, memory, and file descriptors. |
| `GET /api/v1/baselines` | RoleViewer | **MERGE** | Merge into `/forecasts` or `/changes` as baseline data feeds the same calculations. |
| `GET /api/v1/blastradius/{id}` | RoleViewer | **MERGE** | Merge into `/graph/dependents/{id}` to prevent redundant graph traversal endpoints. |
| `GET /api/v1/dependencies` | RoleViewer | **MERGE** | Merge into `/inventory` or `/graph` (redundant summary). |
| `GET /api/v1/decommission` | RoleViewer | **MERGE** | Merge into `/graph` readiness filter to consolidate export endpoints. |
| `GET /api/v1/migration` | RoleViewer | **MERGE** | Merge into `/graph` export filter to consolidate export endpoints. |
| `GET /api/v1/report` | RoleViewer | **KEEP** | Exports standalone comprehensive State of this Server report. |
| `GET /api/v1/coverage` | RoleViewer | **KEEP** | Reports coverage honesty table indicating what sensors could and could not see. |
| `GET /api/v1/briefing` | RoleViewer | **KEEP** | Delivers plain-English briefing text for UI and CLI. |
| `GET /api/v1/checks` | RoleViewer | **KEEP** | Lists read-only checks, their results, and attribution certainty. |
| `GET /api/v1/activity` | RoleViewer | **KEEP** | Unified activity log showing background scans and check runs. |
| `GET /api/v1/drift` | RoleViewer | **KEEP** | Directly reports discrepancies between desired state and observed host truth. |
| `GET /api/v1/plans` | RoleViewer | **KEEP** | Returns generated read-only remediation DAG plans. |
| `GET /api/v1/software` | RoleViewer | **KEEP** | Returns complete package inventory, versions, and update candidates. |
| `GET /api/v1/software/{pkg}` | RoleViewer | **KEEP** | Deep inspection of an individual package's dependencies and candidate versions. |
| `GET /api/v1/platforms` | RoleViewer | **KEEP** | Reports detected platforms, workflow engines, and orchestration frameworks. |
| `GET /api/v1/actuator/status` | RoleViewer | **EXPERIMENTAL** | Checks if local actuator unix socket is available and responsive. |
| `GET /metrics` | RoleViewer | **KEEP** | Standard Prometheus metric scrape endpoint for local scrapers. |
| `POST /api/v1/orphan/scan` | RoleOperator | **KEEP** | Triggers on-demand scan for orphaned processes, packages, and unmanaged files. |
| `POST /api/v1/checks/{id}/run` | RoleOperator | **KEEP** | Runs a specific read-only diagnostic check on demand. |
| `POST /api/v1/software/plan` | RoleOperator | **MERGE** | Merge into `/plans` endpoint with a target spec parameter. |
| `POST /api/v1/plans/{id}/approve` | RoleApprover | **EXPERIMENTAL** | Signs plan envelope with approver key for actuator execution. |
| `POST /api/v1/auth/tokens/rotate` | RoleAdmin | **KEEP** | Allows administrator to rotate API access tokens securely. |
| `GET /debug/pprof/` | RoleAdmin | **KEEP** | Standard Go pprof index for debugging performance under load. |
| `GET /debug/pprof/cmdline` | RoleAdmin | **KEEP** | Debugging profiling endpoint. |
| `GET /debug/pprof/profile` | RoleAdmin | **KEEP** | CPU profile capture endpoint. |
| `GET /debug/pprof/symbol` | RoleAdmin | **KEEP** | Symbol resolution endpoint for profiling. |
| `GET /debug/pprof/trace` | RoleAdmin | **KEEP** | Execution trace capture endpoint. |

---

## 4. UI Pages and Views (14 Total)

Defined in `web/js/app.js` (`views` array) and `web/index.html`.

| UI View / Panel | Classification | One-Line Reason vs PURPOSE |
| :--- | :--- | :--- |
| `overview` | **KEEP** | Primary single-pane view showing verdict, top findings, listeners, and system summary. |
| `briefing` | **KEEP** | Plain-English briefing text summarizing the server in human terms. |
| `software` | **KEEP** | Detailed software inventory view showing versions, local candidates, and dry-run plans. |
| `platforms` | **KEEP** | Displays detected platform signatures (Kubernetes, CI runners, Kafka, etc.). |
| `desired` | **KEEP** | Displays desired state comparison and drift items between specification and host. |
| `activity` | **KEEP** | Audit and scan activity timeline tracking observations and check runs. |
| `devops` | **MERGE** | Role check view; merge all 7 role views into a single filterable "Checks" tab. |
| `cloud` | **MERGE** | Role check view; merge into unified "Checks" tab with category filters. |
| `cloud-platform` | **MERGE** | Role check view; merge into unified "Checks" tab with category filters. |
| `infrastructure` | **MERGE** | Role check view; merge into unified "Checks" tab with category filters. |
| `devsecops` | **MERGE** | Role check view; merge into unified "Checks" tab with category filters. |
| `platform` | **MERGE** | Role check view; merge into unified "Checks" tab with category filters. |
| `network` | **MERGE** | Role check view; merge into unified "Checks" tab with category filters. |
| `styleguide` | **REMOVE** | Developer testing artifact that serves no user purpose in production UI. |

---

## 5. Documentation Files (30 Total in `docs/*.md`)

| Doc File | Classification | One-Line Reason vs PURPOSE |
| :--- | :--- | :--- |
| `docs/ARCHITECTURE.md` | **KEEP** | Foundational architectural specification of sensors, graph, and core principles. |
| `docs/DESIGN.md` | **KEEP** | Design invariants, data structures, and deterministic evaluation pipeline. |
| `docs/STANDARDS.md` | **KEEP** | OpenSSF and code quality standards adhered to by the project. |
| `docs/INSTALL.md` | **KEEP** | User guide for zero-setup installation and running on any Linux server. |
| `docs/CONFIGURATION.md` | **KEEP** | Reference documentation for all runtime environment variables and config fields. |
| `docs/API.md` | **KEEP** | Complete REST API specification for local integration. |
| `docs/RULES.md` | **KEEP** | Documentation of deterministic rule definitions and rule format. |
| `docs/THREAT_MODEL.md` | **KEEP** | Primary security threat model for read-only core server truth engine. |
| `docs/SECURITY_DESIGN.md` | **MERGE** | Merge into `docs/THREAT_MODEL.md` to avoid fragmented security documentation. |
| `docs/SECURITY_REVIEW.md` | **KEEP** | Audit findings, govulncheck results, and gosec verification report. |
| `docs/DEPENDENCIES.md` | **KEEP** | Strict justification for every third-party dependency in tree. |
| `docs/COMPATIBILITY.md` | **KEEP** | Linux distribution and kernel compatibility matrix. |
| `docs/BENCHMARKS.md` | **KEEP** | CPU, memory, and scan duration overhead benchmarks proving host safety. |
| `docs/CHAOS_INDEX.md` | **KEEP** | Mathematical formulation of host entropy and calm-to-critical chaos scoring. |
| `docs/RANKING.md` | **MERGE** | Merge into `docs/CHAOS_INDEX.md` (redundant scoring documentation). |
| `docs/VERIFICATION.md` | **KEEP** | Guidelines for deterministic evidence attribution (`OBSERVED`, `DERIVED`, `INFERRED`). |
| `docs/WORDING.md` | **KEEP** | Blame-free, human-first vocabulary dictionary required by core principles. |
| `docs/NAMING.md` | **MERGE** | Merge into `docs/WORDING.md` to keep all language guidelines in one location. |
| `docs/INTEGRATIONS.md` | **KEEP** | Guides for CI/CD pipelines, Ansible, Terraform, Puppet, and Chef integrations. |
| `docs/RELEASE_GATE.md` | **KEEP** | Release criteria matrix verifying every claim against actual command outputs. |
| `docs/REAL_SYSTEM_PROOF.md` | **KEEP** | Test matrices and scripts for verifying against real Ubuntu/Debian/Fedora/Alpine hosts. |
| `docs/SOAK_TEST.md` | **KEEP** | Long-duration endurance and memory leak proof reports. |
| `docs/UNINSTALL.md` | **KEEP** | Clean removal instructions ensuring zero residual files on the host. |
| `docs/UPGRADE.md` | **KEEP** | Seamless binary upgrade instructions preserving database state. |
| `docs/CONTRIBUTING-RULES.md` | **KEEP** | Developer contribution rules enforcing read-only and zero-AI invariants. |
| `docs/ADR-0001-control-model.md`| **MERGE** | Merge into `docs/ARCHITECTURE.md` as an architectural decision record. |
| `docs/ACTUATOR_THREAT_MODEL.md` | **EXPERIMENTAL** | Threat model for optional out-of-process actuator daemon. |
| `docs/CONTROLLER_HA_DESIGN.md` | **EXPERIMENTAL** | Architectural design doc for optional multi-node controller clustering. |
| `docs/ENTERPRISE_IDENTITY_PROXY.md`| **MERGE** | Merge into `docs/API.md` or `docs/CONFIGURATION.md` under authentication. |
| `docs/PLUGINS.md` | **KEEP** | Specification for out-of-process read-only plugin sensors. |

---

## 6. Rules (20 Total in `rules/*.yaml`)

| Rule ID | Category | Classification | One-Line Reason vs PURPOSE |
| :--- | :--- | :--- | :--- |
| `COST-DUPLICATE-RUNTIME` | cost | **KEEP** | Identifies redundant installed language runtimes wasting disk/memory. |
| `COST-IDLE-RESOURCE` | cost | **KEEP** | Identifies idle processes consuming host resources without serving traffic. |
| `EFF-DISK-EXHAUSTION-FORECAST` | efficiency | **KEEP** | Forecasts disk exhaustion using deterministic regression to prevent crashes. |
| `EFF-IDLE-SERVICE-NO-TRAFFIC` | efficiency | **KEEP** | Detects active services with listening sockets receiving zero network traffic. |
| `EFF-MEMORY-LEAK-FORECAST` | efficiency | **KEEP** | Identifies monotonic process memory growth indicating leaks. |
| `EFF-RECLAIMABLE-DISK` | efficiency | **MERGE** | Merge into `EFF-RECLAIMABLE-STORAGE-LOGS` as a unified disk reclamation finding. |
| `EFF-RECLAIMABLE-STORAGE-LOGS`| efficiency | **KEEP** | Identifies unrotated logs, stale caches, and reclaimable space. |
| `EFF-SERVICE-RESTART-LOOP` | efficiency | **KEEP** | Detects crash-looping services destabilizing the host. |
| `OPS-EOL-SOFTWARE` | operations | **KEEP** | Identifies end-of-life operating systems and installed runtimes. |
| `OPS-KERNEL-BEHIND` | operations | **KEEP** | Detects running kernel older than installed kernel (reboot required). |
| `OPS-MANUAL-BINARY-INSTALLED`| operations | **KEEP** | Discovers untracked binaries placed in `/usr/local/bin` outside package managers. |
| `OPS-MIXED-PACKAGE-MANAGERS` | operations | **KEEP** | Identifies conflict hazards when packages span multiple distinct managers. |
| `SEC-DB-EXPOSED` | security | **KEEP** | Detects database listeners bound to public/unrestricted network interfaces. |
| `SEC-DELETED-BINARY-EXEC` | security | **KEEP** | Identifies processes running deleted executables (unpatched memory image). |
| `SEC-MANUAL-BINARY-LISTENER` | security | **KEEP** | Detects unmanaged manually dropped binaries exposing network ports. |
| `SEC-PROC-TMP-EXEC` | security | **KEEP** | Identifies suspicious processes executing out of `/tmp` or `/dev/shm`. |
| `SEC-ROOT-LISTENER` | security | **KEEP** | Identifies processes running as root listening on external network interfaces. |
| `SEC-STALE-SSH-KEY` | security | **MERGE** | Merge with `SEC-STALE-USER` to consolidate stale credential findings. |
| `SEC-STALE-USER` | security | **KEEP** | Identifies inactive user accounts with interactive shells. |
| `SEC-WORLD-WRITABLE-SERVICE` | security | **KEEP** | Detects privilege escalation risks from world-writable systemd unit files. |

---

## 7. Platform Signatures (48 Total in `data/platforms.yaml`)

| Platform ID | Category | Support Level | Classification | One-Line Reason vs PURPOSE |
| :--- | :--- | :--- | :--- | :--- |
| `kubernetes` | orchestration | adapter | **KEEP** | Detects Kubelet and local node Kubernetes state. |
| `k3s` | orchestration | detection | **KEEP** | Detects lightweight Kubernetes distribution running on host. |
| `openshift` | orchestration | detection | **KEEP** | Detects OpenShift node daemons on host. |
| `docker-swarm` | orchestration | adapter | **KEEP** | Detects Docker engine Swarm mode processes and listeners. |
| `eks-node` | orchestration | detection | **KEEP** | Detects AWS EKS node bootstrap daemons on Linux instance. |
| `aks-node` | orchestration | detection | **KEEP** | Detects Azure AKS node daemons on Linux instance. |
| `gke-node` | orchestration | detection | **KEEP** | Detects Google GKE node agents on Linux instance. |
| `airflow` | workflow | detection | **KEEP** | Identifies Apache Airflow scheduler/webserver running on host. |
| `dagster` | workflow | detection | **KEEP** | Identifies Dagster daemon and webserver processes. |
| `argo-workflows` | workflow | detection | **KEEP** | Identifies Argo workflow controller running on host. |
| `netflix-conductor`| workflow | detection | **KEEP** | Identifies Conductor server/worker processes. |
| `jenkins` | CI/CD | adapter | **KEEP** | Identifies Jenkins controller or agent daemon. |
| `gitlab-runner` | CI/CD | adapter | **KEEP** | Identifies GitLab Runner executor daemon. |
| `github-actions-runner`| CI/CD | adapter | **KEEP** | Identifies GitHub Actions runner worker processes. |
| `azure-devops-agent`| CI/CD | detection | **KEEP** | Identifies Azure Pipelines local agent service. |
| `circleci-runner` | CI/CD | detection | **KEEP** | Identifies CircleCI machine runner service. |
| `terraform` | IaC | detection | **KEEP** | Identifies local Terraform installations and state artifacts. |
| `opentofu` | IaC | detection | **KEEP** | Identifies OpenTofu CLI installations. |
| `pulumi` | IaC | detection | **KEEP** | Identifies Pulumi CLI binary on host. |
| `aws-cdk` | IaC | cloud-side-not-supported | **REMOVE** | Pure cloud-side tooling that leaves no daemon or host trace. |
| `azure-bicep` | IaC | cloud-side-not-supported | **REMOVE** | Pure cloud-side compiler that leaves no host service. |
| `openstack-heat` | IaC | cloud-side-not-supported | **REMOVE** | Cloud control plane service not running on managed Linux workloads. |
| `ansible` | config-mgmt | adapter | **KEEP** | Identifies Ansible agent/pull configuration on host. |
| `puppet` | config-mgmt | adapter | **KEEP** | Identifies Puppet agent daemon on host. |
| `chef` | config-mgmt | adapter | **KEEP** | Identifies Chef client daemon on host. |
| `windows-dsc` | config-mgmt | unsupported | **REMOVE** | Windows-only mechanism completely irrelevant to Linux servers. |
| `istio-envoy` | service-mesh | detection | **KEEP** | Detects Envoy sidecar or ingress proxy processes. |
| `kuma` | service-mesh | detection | **KEEP** | Detects Kuma data plane proxy on host. |
| `nginx` | service-mesh | detection | **KEEP** | Identifies NGINX reverse proxy listeners and configuration. |
| `kafka` | messaging | detection | **KEEP** | Detects Apache Kafka broker processes and listener ports. |
| `pulsar` | messaging | detection | **KEEP** | Detects Apache Pulsar broker processes. |
| `flink` | stream-processing | detection | **KEEP** | Detects Apache Flink JobManager or TaskManager processes. |
| `storm` | stream-processing | detection | **KEEP** | Detects Apache Storm Nimbus/Supervisor processes. |
| `beam` | stream-processing | cloud-side-not-supported | **REMOVE** | SDK abstraction executed on runners; no host daemon exists. |
| `spark` | stream-processing | detection | **KEEP** | Detects Apache Spark master or worker daemons. |
| `yarn` | stream-processing | detection | **KEEP** | Detects Hadoop YARN NodeManager processes. |
| `helix` | stream-processing | detection | **KEEP** | Detects Apache Helix cluster management processes. |
| `prometheus` | observability | detection | **KEEP** | Detects Prometheus server or Node Exporter daemons. |
| `otel-collector` | observability | detection | **KEEP** | Detects OpenTelemetry Collector processes. |
| `grafana-agent` | observability | detection | **KEEP** | Detects Grafana Agent or Alloy daemons. |
| `kubeflow` | ML | detection | **KEEP** | Detects Kubeflow pipeline runner processes. |
| `mlflow` | ML | detection | **KEEP** | Detects MLflow tracking server processes. |
| `mongodb-ops-manager`| database-ops | detection | **KEEP** | Detects MongoDB Ops Manager agent daemons. |
| `mysql-orchestrator`| database-ops | detection | **KEEP** | Detects GitHub Orchestrator daemon for MySQL. |
| `vrealize-aria` | observability | detection | **KEEP** | Detects VMware Aria operations guest agent. |
| `cloudstack-agent` | orchestration | detection | **KEEP** | Detects CloudStack hypervisor agent daemons. |
| `splunk-soar` | observability | detection | **KEEP** | Detects Splunk SOAR / Phantom processes. |
| `morpheus` | orchestration | detection | **KEEP** | Detects Morpheus cloud management agent daemons. |

---

## 8. Configuration Options (15 Total in `internal/config/config.go`)

| Config Field | Environment Variable | Classification | One-Line Reason vs PURPOSE |
| :--- | :--- | :--- | :--- |
| `Host` | `KAZESHINI_HOST` | **KEEP** | Dictates listening address, defaulting strictly to loopback 127.0.0.1. |
| `Port` | `KAZESHINI_PORT` | **KEEP** | Dictates listening TCP port (default 7777). |
| `AllowRemote` | `KAZESHINI_ALLOW_REMOTE` | **KEEP** | Explicit user flag required to bind outside loopback. |
| `DataDir` | `KAZESHINI_DATA_DIR` | **KEEP** | Specifies writable directory for store and audit log. |
| `RulesDir` | `KAZESHINI_RULES_DIR` | **KEEP** | Specifies local path for custom declarative rules. |
| `LogLevel` | `KAZESHINI_LOG_LEVEL` | **KEEP** | Controls logging verbosity for zero-harm monitoring. |
| `LogFormat` | `KAZESHINI_LOG_FORMAT` | **KEEP** | Controls text vs JSON stdout log formatting. |
| `ScanInterval` | `KAZESHINI_SCAN_INTERVAL` | **KEEP** | Bounds background scan cadence to preserve host CPU. |
| `AuthRequired` | `KAZESHINI_AUTH_REQUIRED` | **KEEP** | Enforces authentication on local API endpoints. |
| `AllowedHosts` | `KAZESHINI_ALLOWED_HOSTS` | **KEEP** | Protects against DNS rebinding attacks on HTTP requests. |
| `OTel` | `KAZESHINI_OTEL_*` | **EXPERIMENTAL** | Optional telemetry metric exporter; egress off by default. |
| `Debug` | `KAZESHINI_DEBUG` | **KEEP** | Enables pprof and debug telemetry endpoints for operators. |
| `Stateless` | `KAZESHINI_STATELESS` | **KEEP** | Enforces pure in-memory operation without writable disk. |
| `DesiredPath` | `KAZESHINI_DESIRED` | **KEEP** | Path to user-owned declarative desired state manifest. |
| `LabelsPath` | `KAZESHINI_LABELS` | **MERGE** | Merge with `DesiredPath` metadata block to avoid extra config options. |

---

## 9. Dependencies (6 Total in `go.mod`)

| Dependency | Classification | One-Line Reason vs PURPOSE |
| :--- | :--- | :--- |
| `go.etcd.io/bbolt` | **KEEP** | Zero-CGO embedded persistent KV store for single-binary operation. |
| `golang.org/x/sys` | **KEEP** | Required standard low-level Linux syscalls and ioctls for read-only sensors. |
| `gopkg.in/yaml.v3` | **KEEP** | Required parser for desired state, platform signatures, and declarative rules. |
| `github.com/coreos/go-oidc/v3` | **EXPERIMENTAL** | Enterprise OIDC identity provider integration for multi-user setups. |
| `github.com/go-jose/go-jose/v4` | **EXPERIMENTAL** | Cryptographic token signature verification supporting OIDC. |
| `golang.org/x/oauth2` | **EXPERIMENTAL** | Standard token exchange supporting OIDC authentication. |

---

## 10. Summary & Next Action Recommendation

- **Keep (Core)**: 161 items directly supporting the single-binary zero-setup Linux truth engine.
- **Merge**: 22 items proposed for consolidation to simplify CLI subcommands, API routes, and redundant role views.
- **Experimental**: 18 items (Agent/Controller multi-host mode, Actuator execution process, Enterprise OIDC auth).
- **Remove**: 7 items (Unused `styleguide` UI page + 6 non-Linux/cloud-only platforms `aws-cdk`, `azure-bicep`, `openstack-heat`, `windows-dsc`, `beam`, `cloudstack-agent`).

**STATUS:** Awaiting user review and explicit command `approved` (or edits) before proceeding with pruning.


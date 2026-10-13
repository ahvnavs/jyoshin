# Kazeshini CI/CD & Pipeline Integrations Guide

Kazeshini provides deterministic, stable exit codes and structured JSON outputs designed for zero-trust CI/CD validation gates, pre-deployment smoke checks, and post-provisioning compliance.

---

## Exit Code Contract

| Subcommand | Exit Code 0 | Exit Code 1 | Exit Code 2 |
| :--- | :--- | :--- | :--- |
| `kazeshini check run <id> --fail-on <warn\|crit>` | Check passed (status `OK` or below threshold) | Check evaluated to or above threshold (`WARN` or `CRIT`) | Execution / Flag syntax error |
| `kazeshini drift --exit-code` | Host perfectly matches desired state (0 drift) | Drift items detected (`missing`, `extra`, `mismatch`, `wrong_state`) | Manifest missing or unparseable |
| `kazeshini audit verify` | Hash-chained audit trail verified clean | Cryptographic tamper or broken digest link detected | File missing or read error |
| `kazeshini facts --json` | Valid JSON facts emitted | Uncaught fatal host error | Syntax error |

---

## Pipeline Examples

### 1. GitHub Actions Workflow (`.github/workflows/server-gate.yml`)
*(Status: Example specification; not run in this local session)*

```yaml
name: "Production Server Drift & Integrity Gate"
on:
  schedule:
    - cron: '0 * * * *'
  workflow_dispatch:

jobs:
  verify-host:
    runs-on: self-hosted
    steps:
      - name: Check Out Repository Desired State
        uses: actions/checkout@v4

      - name: Verify Desired State Drift
        run: |
          kazeshini drift --desired ./kazeshini.desired.yaml --exit-code

      - name: Verify Host Inode & Disk Headroom
        run: |
          kazeshini check run disk-inodes --fail-on warn --json

      - name: Run DevSecOps Checks
        run: |
          kazeshini check run --role devsecops --fail-on crit
```

### 2. GitLab CI (`.gitlab-ci.yml`)
*(Status: Example specification; not run in this local session)*

```yaml
stages:
  - compliance

host_compliance_gate:
  stage: compliance
  tags:
    - linux-runner
  script:
    - kazeshini drift --desired /etc/kazeshini/kazeshini.desired.yaml --exit-code
    - kazeshini check run --role infrastructure --fail-on crit
  artifacts:
    when: always
    paths:
      - audit.json
```

### 3. Jenkins Pipeline (`Jenkinsfile`)
*(Status: Example specification; not run in this local session)*

```groovy
pipeline {
    agent any
    stages {
        stage('Drift & Health Gate') {
            steps {
                sh '''
                    kazeshini drift --desired ./kazeshini.desired.yaml --exit-code
                    kazeshini check run disk-inodes --fail-on warn
                '''
            }
        }
    }
}
```

### 4. Azure DevOps Pipelines (`azure-pipelines.yml`)
*(Status: Example specification; not run in this local session)*

```yaml
trigger:
  - main

pool:
  name: 'Default'

steps:
  - script: |
      kazeshini drift --desired kazeshini.desired.yaml --exit-code
      kazeshini check run node-services --fail-on crit
    displayName: 'Validate Host State'
```

### 5. CircleCI (`.circleci/config.yml`)
*(Status: Example specification; not run in this local session)*

```yaml
version: 2.1
jobs:
  host-gate:
    machine: true
    steps:
      - checkout
      - run:
          name: Enforce Zero Drift
          command: kazeshini drift --desired ./kazeshini.desired.yaml --exit-code
workflows:
  build-and-gate:
    jobs:
      - host-gate
```


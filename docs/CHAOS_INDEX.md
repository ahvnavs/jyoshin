# Chaos Index Specification

The **Chaos Index** is a deterministic, explainable scalar score in the range $[0, 100]$
quantifying the disorder, entropy, and operational risk of a Linux host without using ML or AI.

## Formula

$$\text{ChaosIndex} = \min\left(100, \; \text{round}\left(\sum_{f \in \text{Findings}} w(f) + \text{Penalty}_{\text{Orphans}} + \text{Penalty}_{\text{Exposure}}\right)\right)$$

### Finding Weights $w(f)$:
- **Critical Severity**: $20.0 \times \text{confidence}$
- **High Severity**: $10.0 \times \text{confidence}$
- **Medium Severity**: $4.0 \times \text{confidence}$
- **Low Severity**: $1.0 \times \text{confidence}$
- **Info Severity**: $0.0$

### System Entropy Penalties:
- **Unmanaged Orphan Binaries**: $+2.0$ per manual executable drop in system paths (max $+15.0$).
- **Public Port Exposure**: $+5.0$ per listening socket bound to `0.0.0.0` or `::` (max $+20.0$).
- **Zombie / Failed Services**: $+8.0$ per systemd unit in `failed` state.

## Interpretation
- **$0 - 15$ (CALM)**: Server is tidy, package-managed, and predictably configured.
- **$16 - 45$ (MODERATE)**: Mild drift, unmanaged local scripts, or minor over-provisioning.
- **$46 - 75$ (MESSY)**: Notable unmanaged binaries, unnecessary open ports, or multiple duplicate runtimes.
- **$76 - 100$ (CRITICAL)**: Critical databases exposed publicly, active crash loops, or security exposure.



---

## Scoring & Ranking Calculations

# Finding Ranking Specification

Kazeshini ranks findings deterministically according to potential operational,
security, or cost consequences.

## Ranking Formula

The finding ranking score $S \in [0, 100]$ is computed as:

$$S = \min(100.0, \; \text{Base}(\text{Severity}) \times \text{Multiplier}(\text{Exposure}) \times \text{Multiplier}(\text{BlastRadius}) \times \text{Confidence})$$

### 1. Base Score (Severity)
- **Critical**: 40.0
- **High**: 30.0
- **Medium**: 20.0
- **Low**: 10.0
- **Info**: 5.0

### 2. Exposure Multiplier
- **All Interfaces (`0.0.0.0` or `::`)**: 1.5
- **Private Network / Inter-node**: 1.2
- **Loopback (`127.0.0.1`)**: 1.0
- **Local Host Only**: 1.0

### 3. Blast Radius Multiplier
Calculated based on number of affected processes, services, or ports:
- $> 5$ affected nodes: 1.4
- $2 - 5$ affected nodes: 1.2
- Single node: 1.0

### 4. Confidence
- **OBSERVED** or **DERIVED**: $1.0$
- **INFERRED**: Given confidence score $c \in [0.0, 1.0]$.

## Deterministic Ordering

Findings are ordered by:
1. `Score` descending
2. `Severity` descending (critical > high > medium > low > info)
3. `Category` (security > cost > efficiency > operations > change)
4. `ID` ascending (lexicographical stable tie-breaker)


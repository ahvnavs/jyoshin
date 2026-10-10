# Finding Ranking Specification

Jyōshin ranks findings deterministically according to potential operational,
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


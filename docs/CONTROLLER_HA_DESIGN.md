# Kazeshini Controller High Availability (HA) Architecture Design

## 1. Overview
The Kazeshini Controller can be scaled horizontally to multiple stateless controller instances in active-passive or active-active configurations.

Under Non-Negotiable Directives:
- **Principle 15**: STATELESS BY DEFAULT. Controllers do not require durable local disks; state is stored in an externalized pluggable store (e.g. etcd, PostgreSQL, or S3/bbolt replica).
- **Principle 2 & 17**: NEVER AUTO-APPLY. Controllers do not originate arbitrary commands or auto-apply changes. They aggregate read-only state and hold user-approved, cryptographically signed plan envelopes.

---

## 2. Leader Election Abstraction

Horizontal controller coordination relies on a lease-based `LeaderElector` interface (`internal/fleet/ha.go`):

```go
type LeaderElector interface {
    Campaign(ctx context.Context) error
    IsLeader() bool
    StepDown(ctx context.Context) error
}
```

### Implementations:
1. **Kubernetes Lease**: Backed by `coordination.k8s.io/v1` `Lease` object with renewable TTL and heartbeat.
2. **File Lock Lease**: Backed by `flock`/atomic lockfile for bare-metal clustered deployments.

---

## 3. Externalized State Architecture

```
   [ Agent Host A ]       [ Agent Host B ]       [ Agent Host C ]
          \                      |                      /
           \ (mTLS outbound)     | (mTLS outbound)     / (mTLS outbound)
            v                    v                    v
      +----------------------------------------------------+
      |             Load Balancer / Ingress                |
      +----------------------------------------------------+
             /                                      \
            v                                        v
  +--------------------+                   +--------------------+
  | Controller Node 1  |                   | Controller Node 2  |
  |  (Leader / Active) |                   |     (Follower)     |
  +--------------------+                   +--------------------+
             \                                      /
              \                                    /
               v                                  v
      +----------------------------------------------------+
      |            Pluggable External State Store          |
      |   (Fleet Snapshots, Enrollment Tokens, Plans)      |
      +----------------------------------------------------+
```

1. **Snapshots**: Agents push snapshots over mTLS to any controller behind a round-robin load balancer. Controllers persist snapshots directly into the external store.
2. **Batch Rollouts**: Managed exclusively by the elected leader instance to avoid duplicate dispatch or race conditions during multi-host rollouts.
3. **Plan Pull**: Agents query any controller replica for envelopes targeted to their specific `machine-id`.


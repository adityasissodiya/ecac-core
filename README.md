# Core language & philosophy

* **Rust** for all correctness-critical components (memory safety, no GC pauses, strong type system, great crypto libs).
* Treat the system as a **signed, hash-linked op log** + **deterministic replay** into materialized state. CRDT handles data conflicts; a **policy filter** (deny-wins) removes unauthorized ops during replay.

---

# Replicated data & causality

* **Op-based CRDT**:

  * **automerge-rs** for a mature op graph with causal deps, IDs, and deterministic merges. Good for documents/structured records; lets you carry per-op metadata (author, cred hash, signature).
  * If your domain ops are simple (steps/status/measurements), you can implement a **custom op CRDT** (append-only DAG with causal parent IDs) and avoid generic doc CRDT overhead; your merge becomes “toposort → apply valid ops.”
* **Causal metadata**:

  * Use **hybrid logical clocks (HLC)** per node to break ties deterministically.
  * Every op includes: `op_id` (hash), `parents[]`, `hlc`, `author_pk`, `cred_ref`, `sig`.

---

# Cryptography & identities

* **Signatures**: **ed25519-dalek** (deterministic, widely used) or **ring** for FIPS-ish choices.
* **Hashing**: **BLAKE3** for the op IDs and hash-links (fast, strong).
* **Credentials (ABAC)**: **didkit** / **ssi** (SpruceID) for **W3C Verifiable Credentials** issuance/verification + **StatusList/RevocationList** support. Short-TTL VCs to minimize stale auth windows.
* **Group/read encryption (optional but correct)**: **OpenMLS** (TreeKEM) for per-category group keys; rotate on membership changes. If you scope v1 to *write-enforcement only*, keep this as Phase 2.

---

# Policy engine (authorization)

* **Cedar policy** (AWS Cedar) via **cedar-policy** crate:

  * Express RBAC/ABAC as policies over attributes (user, resource/step tags, action).
  * Use **deny-overrides** semantics; easier to align with “deny wins.”
  * Evaluate during **replay**, not just at accept time: compute **authorization epochs** per identity (intervals where a permission is valid), then **skip ops whose HLC ∈ revoked interval**.
* Alternative: **OPA/Rego** compiled to WASM if you prefer Rego, but Cedar has a cleaner Rust story and a policy verifier.

---

# Networking & sync

* **libp2p** (Rust) with **Gossipsub** for anti-entropy gossip and **Noise** for transport security; handles NAT traversal and peer discovery.
* **gRPC** (tonic) for DSM-style request/response APIs (capability/capacity queries, optimizer service).
* **QUIC** (quinn) if you want a server/relay path with congestion control and 0-RTT.
* **Serialization**: **Protobuf** for DSM APIs, **CBOR** (serde_cbor) for signed ops (canonical encoding before signing).

---

# Storage & determinism

* **RocksDB** (rust-rocksdb) for append-only op log + indices (by author, by step, by HLC).
* **sled** if you need simpler embedded, but RocksDB is battle-tested.
* Periodic **checkpoints** of materialized state; store the **root digest** and anchor to **Sigstore Rekor** (transparency log) for tamper evidence (optional but strong correctness signal).

---

# Replay / merge engine (deny-wins)

* Deterministic **topological sort** of the DAG (parents first; ties by `(HLC, op_id)`).
* Build **auth epochs** from credential/policy events (grant, revoke, expiry).
* Execute scan:

  1. If op.author not in a valid epoch for op.action & resource tags at op.HLC → **skip**.
  2. Else **apply** via the CRDT apply function.
* On arrival of a new **revocation**: **re-run replay from that epoch** (or incremental invalidation using an index `author → ops_after(revoke_hlc)`).

---

# Optimization/DSM tie-in

* **tonic** gRPC service for the **Matchmaking Data Transformer** and actor repositories.
* When capability/capacity/LCA answers arrive, treat them as **signed ops** too; the optimizer consumes **materialized, policy-clean state** only.
* Optimizer:

  * For correctness, prefer a **well-vetted NSGA-II** implementation. In Rust: **evox** (if stable), or wrap a mature Java library (**jMetal**) via gRPC microservice to avoid reimplementing algorithms incorrectly.
  * Deterministically seed RNGs and record seeds in the op log for reproducibility.

---

# Testing & verification (accuracy)

* **Property-based tests**: **proptest** to generate random interleavings (grants/revokes/edits/partitions) and assert invariants:

  * **Convergence**: same final state after any delivery order.
  * **Policy safety**: no op with `revoked_before(op)` affects state.
* **Model checking** (lightweight):

  * TLA+ spec of the replay/deny-wins algorithm for small traces; check invariants with **Apalache**.
* **Fuzzing**: **cargo-fuzz** on the replay engine.
* **Static analysis**: clippy + miri; **no unsafe** outside vetted crypto bindings.

---

# Observability & audit

* **Structured logs** (tracing crate) with op IDs and causal parents.
* **Tamper-evident audit**: audit events are just another signed op stream (viewed, synced, exported).
* **Metrics**: Prometheus exporters for convergence latency, rollback counts, replay duration.

---

# Minimal but correct client UI (optional)

* **Tauri + Rust** for a desktop UI that stays local-first (no Electron runtime nondeterminism).
* Show “effective state” vs “tentative changes” and surface **rollback events** to users explicitly.

---

# Security hygiene

* **Key storage**: OS keychain integration; YubiKey support (optional) via **yubihsm** / **pcsc** for signing.
* **Supply chain**: Reproducible builds, **cargo-auditable**, Sigstore signing of releases.
* **Time**: use **HLC**, do *not* trust wall clock for authorization ordering.

---

## Why not X?

* **Node/TS + Yjs**: great for DX, but signing, hash-linking, and deterministic replay under deny-wins get messy; memory safety and timing nondeterminism are worse.
* **Go**: solid for networking, weaker ecosystem for CRDTs and Cedar-class policy; Rust’s crypto and zero-cost abstractions make replay correctness easier to reason about.
* **SQL-only event store**: fine for persistence, but you still need op DAG + deterministic replay; RocksDB fits append + range scans better.

---

## Build order (sane path)

1. **Op schema + signer/verifier + hash-linked DAG** (Rust, BLAKE3, ed25519).
2. **Deterministic replay** with Cedar policies (deny-wins) over a **single-process** log; add property tests.
3. **libp2p gossip** + dedup + causal parent fetching; assert convergence under partition/heal.
4. **RocksDB persistence**, checkpoints, and audit anchoring.
5. **gRPC (tonic)** façade for DSM integration; pipe signed capability/capacity events through the same log.
6. (Optional) **OpenMLS** for read encryption.

This stack isn’t the fastest to build, but it gives you: signed ops, causal consistency, rigorous replay with deny-wins, verifiable credentials, deterministic behavior, and a clear path to prove (and test) the invariants you’ll claim in the paper.

# Trust Layer — PDV Compliant Blockchain Boundary

## What This Is
A strict, rejection-first, cryptographic trust boundary that enforces PDV (Pre-Deterministic Validation) guarantees before AKASHIC anchoring.

## PDV Alignment

### What PDV Means
- **P** — Pre-validation: every envelope is validated before it reaches L1
- **D** — Deterministic: same input always produces same hash, same state root, same replay result
- **V** — Verifiable: every step is cryptographically signed and independently replayable

### Core Guarantee
> Nothing non-deterministic, unsigned, or unreplayable can enter L1.

---

## System Flow

```
Gurukul TTS → IR + CET + Constraints
  → ExecutionAgent  → execution_hash = sha256(ir + cet + constraints)
  → ValidationAgent → recompute + verify (hard reject on any mismatch)
  → GenerateStateRoot → sha256(sorted execution_hashes)
  → RelayAgent      → sign state root (exec + val)
  → L1 Hard Gate    → independent re-verification of everything
  → Replay Engine   → recompute from scratch, match anchor exactly
```

---

## Envelope Structure (PDV Compliant)

```go
type Envelope struct {
    ExecutionID   string   // unique execution identifier
    InputHash     string   // sha256(IR)
    OutputHash    string   // sha256(CET)
    ExecutionHash string   // sha256(IR + CET + constraints) — deterministic
    TraceHash     string   // sha256(ExecutionHash) — chain integrity
    SignerIDs     []string // accountable agent identities
}
```

---

## Key Properties

| Property | How Enforced |
|---|---|
| Determinism | `ComputeExecutionHash` uses only IR+CET+constraints, no timestamps |
| Replayability | `replay.Verify` recomputes everything from raw inputs |
| Cryptographic integrity | ed25519 signatures on execution_hash by both agents |
| Strict rejection | All failures caught in `ValidationAgent` BEFORE anchor |
| Zero trust | L1 independently re-derives state root and verifies all signatures |

---

## File Structure

```
trust-layer/
├── agent/agent.go          — Agent identity, ed25519 key-pair, Sign
├── crypto/crypto.go        — Sign, Verify, MultiSig.VerifyBoth
├── engine/engine.go        — PDV Envelope, ComputeExecutionHash, GenerateStateRoot, all agents
├── l1-interface/l1.go      — PDV hard gate, strict SubmitAnchor
├── replay/replay.go        — Replay engine, ReplaySystem, failure logging
├── logger/logger.go        — Append-only structured JSON logs
├── review_packets/
│   ├── trust-layer.md              — Phase 1-7 review
│   ├── final-readiness.md          — Blockchain readiness review
│   └── pdv_trust_layer_phase2.md   — PDV compliance review
└── main.go                 — Full pipeline demo + all failure cases
```

---

## Failure Cases (All Rejected Before Anchor)

| Scenario | Caught At |
|---|---|
| Mismatched CET | `ValidationAgent.Validate` |
| Mismatched IR | `ValidationAgent.Validate` |
| Wrong input hash | `ValidationAgent.Validate` |
| Wrong output hash | `ValidationAgent.Validate` |
| Partial/bad signature | `ValidationAgent.Validate` |
| Corrupted state root | `l1.SubmitAnchor` |
| Missing validation sig | `l1.SubmitAnchor` |
| Tampered exec signature | `replay.Verify` |

---

## Determinism Proof

```
ComputeExecutionHash("ir:alice->bob", "cet:transfer:100", "max:1000")
  run1 → 001bfab6b797c0179e0a46497898cac1e2b6d2fbe82db2e9b5507036075c5411
  run2 → 001bfab6b797c0179e0a46497898cac1e2b6d2fbe82db2e9b5507036075c5411

GenerateStateRoot([env-1, env-2, env-3])
  A,B,C order → 5825a113f6d2be0d050f90e871f1e627eec13c23c3ebc22bda81f38990fc2f8e
  C,B,A order → 5825a113f6d2be0d050f90e871f1e627eec13c23c3ebc22bda81f38990fc2f8e
  deterministic=true
```

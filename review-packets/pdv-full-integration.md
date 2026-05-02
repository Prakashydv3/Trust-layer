# PDV Full Integration — Review Packet

## 1. Entry Point
`main.go` — KSML → PDV → KarmaChain → Bucket → AKASHIC → L1 → Replay → Reconstruction proof.

## 2. Three Core Files

| File | Responsibility |
|---|---|
| `ksml/ksml.go` | Canonical contract: strict JSON schema with typed Metadata{timestamp, source_system} |
| `karmachain/karmachain.go` | File-persistent append-only ledger with trace_id, reload + replay verification |
| `bucket/bucket.go` | Write gate: PDV FAIL → NO WRITE enforced |

## 3. Full Execution Flow

```
KSML JSON → ksml.ParseKSML()
  → validates: execution_id, intent, actor, parameters, constraints
  → validates: metadata.timestamp, metadata.source_system
  → DisallowUnknownFields() → reject unknown structure

IR{Operation, From, To, Amount} + CET{Steps} + constraints

ExecutionAgent  → execution_hash = sha256(ir.Canonical()|cet.Canonical()|constraints)
ValidationAgent → independently recompute → verify sig
ReplayAgent     → independently recompute

Equality Gate: exec_hash == val_hash == replay_hash → ACCEPT else HARD REJECT

KarmaChain.Append(execution_id, execution_hash, state_root, trace_id, replay_verified)
  → persisted to karmachain.json (append-only)

Bucket.Write(state_root, execution_id, trace_id, pdvAccepted=true)
  → persisted to bucket.json
  → PDV FAIL → write rejected

AKASHIC.Append(state_root, execution_id, trace_id)
  → state_n → state_n+1 via parent_state_hash
  → persisted to akashic.json

L1.SubmitAnchor → replay.Verify

Reconstruction: Load karmachain.json + bucket.json + akashic.json → verify chain integrity
```

## 4. Real Output (Logs)

```
[KSML Missing ID]         rejected=true
[KSML Unknown Field]      rejected=true
[KSML Missing timestamp]  rejected=true
[KSML Missing source_system] rejected=true
[Bucket PDV Fail]         write rejected=true
[PDV] {"trace_id":"trace-001","execution_id":"env-1","execution_hash":"120a3a25...","agent_agreement":true,"deterministic_flag":true,"replay_verified":true}
[PDV] {"trace_id":"trace-002","execution_id":"env-2","execution_hash":"dc354c53...","agent_agreement":true,"deterministic_flag":true,"replay_verified":true}
[PDV] {"trace_id":"trace-003","execution_id":"env-3","execution_hash":"bb075efc...","agent_agreement":true,"deterministic_flag":true,"replay_verified":true}
[StateRoot] A,B,C → 7c957f345a90636d2df1d2dbb1cdc9499fe9b5da0414dd8543723b88b0cc889d
[StateRoot] C,B,A → 7c957f345a90636d2df1d2dbb1cdc9499fe9b5da0414dd8543723b88b0cc889d
[StateRoot] deterministic=true
[L1] status=accepted
[ReplaySystem] run1 ok=true
[ReplaySystem] run2 ok=true
[ReplaySystem] same=true
[Replay] ok=true
[KarmaChain] loaded entries=3
[KarmaChain] replay verified=true
[Bucket] loaded records=3
[AKASHIC] loaded states=3
[AKASHIC] chain integrity=true
[Corrupted StateRoot] status=rejected
[Replay Tamper] correctly rejected
[Missing ValSig] status=rejected reason=missing validation signature
```

## 5. Failure Cases

| Scenario | Caught At | Result |
|---|---|---|
| KSML missing execution_id | `ksml.ParseKSML` | `rejected=true` |
| KSML unknown field | `ksml.ParseKSML` | `rejected=true` |
| KSML missing metadata.timestamp | `ksml.ParseKSML` | `rejected=true` |
| KSML missing metadata.source_system | `ksml.ParseKSML` | `rejected=true` |
| PDV fail → bucket write | `bucket.Write` | `write rejected=true` |
| Corrupted state root | `l1.SubmitAnchor` | `status=rejected` |
| Tampered exec signature | `replay.Verify` | `correctly rejected` |
| Missing validation sig | `l1.SubmitAnchor` | `status=rejected` |

## 6. Replay + Reconstruction Proof

```
KarmaChain persisted to karmachain.json → loaded entries=3 → replay verified=true
Bucket persisted to bucket.json         → loaded records=3
AKASHIC persisted to akashic.json       → loaded states=3 → chain integrity=true

Same KSML → same execution_hash (deterministic_flag=true)
Input order change → same state_root (deterministic=true)
```

## 7. Execution Instructions

```bash
git clone https://github.com/Prakashydv3/trust-layer.git
cd trust-layer
go run main.go
```

Persistent files created: `karmachain.json`, `bucket.json`, `akashic.json`

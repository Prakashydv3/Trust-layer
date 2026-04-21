# PDV Phase 3 — Review Packet

## 1. Entry Point
`main.go` — KSML boundary → 3-agent independent recompute → equality gate → PDV output → L1 anchor → replay proof.

## 2. Three Core Files

| File | Responsibility |
|---|---|
| `ksml/ksml.go` | Strict KSML schema validator — rejects malformed inputs before pipeline entry |
| `engine/engine.go` | ExecutionAgent, ValidationAgent, ReplayAgent — each independently computes execution_hash |
| `l1-interface/l1.go` | PDV hard gate — anchors only state_root + execution_hash, no validation dependency |

## 3. Full Execution Flow (PDV Aligned)

```
Gurukul TTS → raw inputs
  → ksml.ParseKSML(id, ir, cet, constraints)   ← reject if schema violation

ExecutionAgent.Execute(id, ir, cet, constraints)
  → execution_hash = sha256(ir + "|" + cet + "|" + constraints)
  → input_hash, output_hash, trace_hash
  → ed25519.Sign(execution_hash)

ValidationAgent.Validate(env, execSig, execPub, ir, cet, constraints)
  → independently recompute execution_hash     ← reject if mismatch
  → verify input_hash + output_hash            ← reject if mismatch
  → verify execSig                             ← reject if invalid

ReplayAgent.Recompute(ir, cet, constraints)
  → independently recompute execution_hash     ← no shared state

Equality Gate (Phase 3 CORE PDV):
  if exec_hash == val_hash == replay_hash → ACCEPT
  else → HARD REJECT

PDV Output:
  { execution_id, execution_hash, state_root, agent_signatures, agent_agreement: true, deterministic_flag: true }

GenerateStateRoot(envelopes)
  → sort by ExecutionID → sha256(all execution_hashes)

RelayAgent.BuildAnchor → L1.SubmitAnchor
  → anchors only state_root + execution_hash
  → independent re-verification, no upstream trust

replay.Verify(anchor, inputs)
  → recompute from IR+CET+constraints
  → regenerate state root
  → verify both signatures
```

## 4. Real Output (Logs)

```
[KSML Missing ID]   rejected=true err=KSML schema violation: missing execution_id
[KSML Bad IR]       rejected=true err=KSML schema violation: IR must start with 'ir:'
[KSML Bad CET]      rejected=true err=KSML schema violation: CET must start with 'cet:'
[Mismatched CET]    rejected=true
[Mismatched IR]     rejected=true
[Partial Signature] rejected=true
[KSML] 3 inputs validated
[PDV] {"execution_id":"env-1","execution_hash":"001bfab6...","agent_agreement":true,"deterministic_flag":true}
[PDV] {"execution_id":"env-2","execution_hash":"c9662e0e...","agent_agreement":true,"deterministic_flag":true}
[PDV] {"execution_id":"env-3","execution_hash":"74cdc6a4...","agent_agreement":true,"deterministic_flag":true}
[StateRoot] A,B,C → 5825a113f6d2be0d050f90e871f1e627eec13c23c3ebc22bda81f38990fc2f8e
[StateRoot] C,B,A → 5825a113f6d2be0d050f90e871f1e627eec13c23c3ebc22bda81f38990fc2f8e
[StateRoot] deterministic=true
[L1] status=accepted
[ReplaySystem] run1 ok=true
[ReplaySystem] run2 ok=true
[ReplaySystem] same=true
[Replay] ok=true
[Corrupted StateRoot] status=rejected reason=state root mismatch: non-deterministic or corrupted
[Replay Tamper]       correctly rejected
[Missing ValSig]      status=rejected reason=missing validation signature
```

## 5. Failure Cases

| Scenario | Caught At | Reason |
|---|---|---|
| Missing execution_id | `ksml.ParseKSML` | `KSML schema violation: missing execution_id` |
| IR missing prefix | `ksml.ParseKSML` | `KSML schema violation: IR must start with 'ir:'` |
| CET missing prefix | `ksml.ParseKSML` | `KSML schema violation: CET must start with 'cet:'` |
| Mismatched CET | `ValidationAgent.Validate` | `execution_hash mismatch` |
| Mismatched IR | `ValidationAgent.Validate` | `execution_hash mismatch` |
| Partial/bad signature | `ValidationAgent.Validate` | `signature verification failed` |
| Agent hash mismatch | Equality gate | `EQUALITY FAIL` |
| Corrupted state root | `l1.SubmitAnchor` | `state root mismatch` |
| Tampered exec sig | `replay.Verify` | `signature mismatch` |
| Missing validation sig | `l1.SubmitAnchor` | `missing validation signature` |

## 6. Determinism Proof

```
ComputeExecutionHash("ir:alice->bob", "cet:transfer:100", "max:1000")
  run1 → 001bfab6b797c0179e0a46497898cac1e2b6d2fbe82db2e9b5507036075c5411
  run2 → 001bfab6b797c0179e0a46497898cac1e2b6d2fbe82db2e9b5507036075c5411

GenerateStateRoot([env-1, env-2, env-3])
  A,B,C → 5825a113f6d2be0d050f90e871f1e627eec13c23c3ebc22bda81f38990fc2f8e
  C,B,A → 5825a113f6d2be0d050f90e871f1e627eec13c23c3ebc22bda81f38990fc2f8e
  deterministic=true
```

## 7. What Changed vs Previous Version

| Area | Before | After (Phase 3) |
|---|---|---|
| Input boundary | Raw strings passed directly | `ksml.ParseKSML` validates schema before pipeline entry |
| Agent count | 2 (exec + val) | 3 (exec + val + replay) — each independently recomputes |
| Equality gate | Not present | `exec_hash == val_hash == replay_hash` — hard reject on mismatch |
| Output contract | Print statements | Structured `PDVOutput` JSON with `agent_agreement` + `deterministic_flag` |
| L1 dependency | L1 verified hashes | L1 only anchors state_root + execution_hash, no validation dependency |

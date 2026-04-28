# PDV Phase 4 — Review Packet

## 1. Entry Point
`main.go` — Agent isolation tests → KSML validation → KSML→IR/CET → 3-agent equality gate → KarmaChain → PDV output → L1 anchor → replay proof.

## 2. Three Core Files

| File | Responsibility |
|---|---|
| `karmachain/karmachain.go` | Append-only ledger: execution_id, execution_hash, state_root, replay_verified |
| `agents/` (3 files) | Physically separated agents each with own ComputeHash — provably independent |
| `engine/engine.go` | Structured IR+CET, trace_id propagation through all agents and logs |

## 3. Full Execution Flow

```
KSML JSON → ksml.ParseKSML()              ← reject if schema violation
  → IR{Operation, From, To, Amount}
  → CET{Steps: [CheckBalance, Deduct, Credit]}
  → traceID propagated through all agents

ExecutionAgent.Execute(id, traceID, ir, cet, constraints)
  → execution_hash = sha256(ir.Canonical()|cet.Canonical()|constraints)
  → log: {trace_id, execution_id, signed}

ValidationAgent.Validate(env, sig, pub, ir, cet, constraints)
  → independently recompute execution_hash  ← hard reject if mismatch
  → log: {trace_id, execution_id, validated}

ReplayAgent.Recompute(id, traceID, ir, cet, constraints)
  → independently recompute execution_hash  ← no shared state
  → log: {trace_id, execution_id, recomputed}

Equality Gate: exec_hash == replay_hash → ACCEPT else HARD REJECT

KarmaChain.Append(execution_id, execution_hash, state_root, replay_verified=true)

PDVOutput{trace_id, execution_id, execution_hash, state_root, agent_hashes,
          agent_signatures, agent_agreement:true, deterministic_flag:true, replay_verified:true}

L1.SubmitAnchor → replay.Verify
```

## 4. Real Output

```
[Isolation] All identical → agreement=true
[Isolation] ExecutionAgent altered → agreement=false (want false)
[Isolation] ValidationAgent altered CET → rejected=true
[Isolation] ReplayAgent altered → agreement=false (want false)
[KSML Missing ID] rejected=true
[KSML Unknown Field] rejected=true
[KSML Empty Parameters] rejected=true
[PDV] {"trace_id":"trace-001","execution_id":"env-1","execution_hash":"120a3a25...","agent_agreement":true,"deterministic_flag":true,"replay_verified":true}
[PDV] {"trace_id":"trace-002","execution_id":"env-2","execution_hash":"dc354c53...","agent_agreement":true,"deterministic_flag":true,"replay_verified":true}
[PDV] {"trace_id":"trace-003","execution_id":"env-3","execution_hash":"bb075efc...","agent_agreement":true,"deterministic_flag":true,"replay_verified":true}
[KarmaChain] replay verified=true
[KarmaChain] entries=3
[StateRoot] A,B,C → 7c957f345a90636d2df1d2dbb1cdc9499fe9b5da0414dd8543723b88b0cc889d
[StateRoot] C,B,A → 7c957f345a90636d2df1d2dbb1cdc9499fe9b5da0414dd8543723b88b0cc889d
[StateRoot] deterministic=true
[L1] status=accepted
[ReplaySystem] run1 ok=true
[ReplaySystem] run2 ok=true
[ReplaySystem] same=true
[Replay] ok=true
[Corrupted StateRoot] status=rejected
[Replay Tamper] correctly rejected
[Missing ValSig] status=rejected reason=missing validation signature
```

## 5. Failure Cases

| Scenario | Caught At | Result |
|---|---|---|
| ExecutionAgent altered | Equality gate | `agreement=false` |
| ValidationAgent altered CET | `ValidationAgent.Validate` | `rejected=true` |
| ReplayAgent altered | Equality gate | `agreement=false` |
| KSML missing execution_id | `ksml.ParseKSML` | `rejected=true` |
| KSML unknown field | `ksml.ParseKSML` | `rejected=true` |
| KSML empty parameters | `ksml.ParseKSML` | `rejected=true` |
| Corrupted state root | `l1.SubmitAnchor` | `status=rejected` |
| Tampered exec signature | `replay.Verify` | `correctly rejected` |
| Missing validation sig | `l1.SubmitAnchor` | `status=rejected` |

## 6. Determinism Proof

```
Same IR+CET+constraints → same execution_hash across all 3 agents
GenerateStateRoot([env-1, env-2, env-3])
  A,B,C → 7c957f345a90636d2df1d2dbb1cdc9499fe9b5da0414dd8543723b88b0cc889d
  C,B,A → 7c957f345a90636d2df1d2dbb1cdc9499fe9b5da0414dd8543723b88b0cc889d
  deterministic=true
KarmaChain replay verified=true
```

## 7. Execution Instructions

```bash
git clone https://github.com/Prakashydv3/trust-layer.git
cd trust-layer
go run main.go
```

## 8. What Changed vs Phase 3

| Area | Before | After (Phase 4) |
|---|---|---|
| Agent separation | Agents in engine.go | Physically separated in `agents/` with own ComputeHash |
| KarmaChain | Not present | Append-only ledger with replay verification |
| Trace system | No trace_id | `trace_id` propagated KSML → agents → PDV output → logs |
| Agent isolation tests | Not present | 4 tests: all identical→ACCEPT, each altered→REJECT |
| PDV output | 6 fields | Full 9-field contract with trace_id, agent_hashes, replay_verified |

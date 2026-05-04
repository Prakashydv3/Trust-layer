# REVIEW_PACKET — PDV Infrastructure Hardening

## 1. Entry Point
`main.go` — KSML → Multi-node consensus → PDV equality gate → KarmaChain → Bucket → AKASHIC → L1 → Replay → Tamper tests

## 2. Full Execution Flow

```
KSML JSON → ksml.ParseKSML()          ← reject: missing fields, unknown keys, no version
  → IR{Operation, From, To, Amount}
  → CET{Steps}

nodes.RunConsensus(NodeA, NodeB, NodeC)
  → each node independently computes execution_hash
  → IF any mismatch → HARD REJECT

ExecutionAgent.Execute(id, traceID, ir, cet, constraints)
  → traceID == "" → HARD REJECT (mandatory contract)
  → execution_hash = sha256(ir.Canonical()|cet.Canonical()|constraints)

ValidationAgent.Validate(env, ...)
  → env.TraceID == "" → HARD REJECT
  → independently recompute execution_hash → verify sig

ReplayAgent.Recompute(id, traceID, ...)
  → traceID == "" → HARD REJECT

Equality Gate: execHash == valHash == replayHash → ACCEPT else HARD REJECT

KarmaChain.Append(entry)              ← hash-chained: prev_hash = sha256(prev_entry)
Bucket.Write(pdvAccepted=true)        ← PDV FAIL → NO WRITE
AKASHIC.Append(stateRoot, parentHash) ← branching DAG

L1 = storage only                     ← anchors state_root, does NOT verify
replay.Verify()                        ← independent truth verification, separate from L1
```

## 3. Tamper Test Proof

```
[KarmaChain] loaded entries=5 chain_valid=true
[KarmaChain Tamper] detected=true
```
KarmaChain uses `prev_hash = sha256(prev_entry_fields)`. Altering any byte in the file breaks the chain on next Load().

## 4. Branch Graph Proof

```
[AKASHIC] total states=6
[AKASHIC] lineage valid=true
[AKASHIC] branch lineage depth=3 valid=true
```
env-branch forks from env-2. GetLineage() traces back: env-branch → env-2 → env-1 → genesis (depth=3).

## 5. Multi-Node Simulation Logs

```
[Consensus] env-1 NodeA=120a3a25 NodeB=120a3a25 NodeC=120a3a25 match=true
[Consensus Match] nodes=3 agreement=true
[Consensus Mismatch] corrupt_node_detected=true
```
3 independent nodes each compute execution_hash. Corrupt node with different input → mismatch detected.

## 6. Equality Gate

```
[Equality] env-1 exec=120a3a25 val=120a3a25 replay=120a3a25 match=true
```
All 3 agent hashes printed explicitly. `execHash == valHash == replayHash` — no partial acceptance.

## 7. Execution Instructions

```bash
git clone https://github.com/Prakashydv3/trust-layer.git
cd trust-layer
go run main.go
```
Persistent files: `karmachain.json`, `bucket.json`, `akashic.json`

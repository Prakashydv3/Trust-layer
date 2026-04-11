# PDV Trust Layer Phase 2 — Review Packet

## 1. Entry Point
`main.go` — wires all agents, runs TTS-sourced PDV pipeline, all failure tests before anchor, 2-run determinism proof.

## 2. Three Core Files

| File | Responsibility |
|---|---|
| `engine/engine.go` | PDV Envelope (execution_hash, input_hash, output_hash, trace_hash, signer_ids), ComputeExecutionHash, GenerateStateRoot |
| `l1-interface/l1.go` | PDV hard gate — independently re-derives state root, verifies all hashes and both signatures |
| `replay/replay.go` | Recomputes IR→CET→execution_hash, regenerates state root, verifies signatures, logs exact mismatch reason |

## 3. Full Execution Flow (PDV Aligned)

```
Gurukul TTS → TTSRecord{ID, IR, CET, Constraints}
  → [TTS] records loaded: 3

ExecutionAgent.Execute(id, ir, cet, constraints)
  → input_hash  = sha256(ir)
  → output_hash = sha256(cet)
  → execution_hash = sha256(ir + "|" + cet + "|" + constraints)  ← deterministic, no randomness
  → trace_hash = sha256(execution_hash)
  → ed25519.Sign(execution_hash) = execSig
  → log: signed

ValidationAgent.Validate(envelope, execSig, execPub, ir, cet, constraints)
  → recompute execution_hash independently          ← hard reject if mismatch
  → verify input_hash == sha256(ir)                 ← hard reject if mismatch
  → verify output_hash == sha256(cet)               ← hard reject if mismatch
  → Verify(execSig, execution_hash, execPub)        ← hard reject if invalid
  → log: validated / execution_hash_mismatch / exec_sig_invalid

[repeat for all 3 envelopes]

engine.GenerateStateRoot(envelopes)
  → sort by ExecutionID (mandatory)
  → sha256(execHash1 + execHash2 + execHash3) = stateRoot

RelayAgent.BuildAnchor(envelopes, execAgent, valAgent)
  → GenerateStateRoot → stateRoot
  → execAgent.Sign(stateRoot) + valAgent.Sign(stateRoot)
  → Anchor{envelopes, stateRoot, MultiSig}
  → log: anchor_built

l1.SubmitAnchor(anchor)  ← PDV hard gate
  → reject: empty envelopes | missing execution_hash/input_hash/output_hash
  → reject: missing signatures | state root mismatch | signature mismatch
  → accept: all checks pass independently

replay.Verify(anchor, inputs)
  → recompute execution_hash from IR+CET+constraints
  → verify input_hash + output_hash
  → regenerate state root
  → VerifyBoth signatures against state root
  → log exact mismatch reason on failure
```

## 4. Real Output (Logs)

```
[TTS] records loaded: 3
[Mismatched CET]     rejected=true err=execution_hash mismatch: got 001bfab6... want 806492...
[Mismatched IR]      rejected=true err=execution_hash mismatch: got 001bfab6... want 705597...
[Partial Signature]  rejected=true err=validation rejected: signature verification failed
[Wrong Input Hash]   rejected=true err=input_hash mismatch
[Wrong Output Hash]  rejected=true err=output_hash mismatch
[Validated] env-1 exec_hash=001bfab6b797c017
[Validated] env-2 exec_hash=c9662e0e32998306
[Validated] env-3 exec_hash=74cdc6a42ea10adf
[StateRoot] run1 → 5825a113f6d2be0d050f90e871f1e627eec13c23c3ebc22bda81f38990fc2f8e
[StateRoot] run2 → 5825a113f6d2be0d050f90e871f1e627eec13c23c3ebc22bda81f38990fc2f8e
[StateRoot] deterministic=true
[L1] status=accepted
[ReplaySystem] run1 ok=true root=5825a113f6d2be0d...
[ReplaySystem] run2 ok=true root=5825a113f6d2be0d...
[ReplaySystem] same=true
[Replay] ok=true
[Corrupted StateRoot] status=rejected reason=state root mismatch: non-deterministic or corrupted
[Replay Tamper]       correctly rejected
[Missing ValSig]      status=rejected reason=missing validation signature
```

## 5. Failure Cases

| Scenario | Caught at | Reason |
|---|---|---|
| Mismatched CET | `ValidationAgent.Validate` | `execution_hash mismatch` |
| Mismatched IR | `ValidationAgent.Validate` | `execution_hash mismatch` |
| Partial/bad signature | `ValidationAgent.Validate` | `signature verification failed` |
| Wrong input hash | `ValidationAgent.Validate` | `input_hash mismatch` |
| Wrong output hash | `ValidationAgent.Validate` | `output_hash mismatch` |
| Corrupted state root | `l1.SubmitAnchor` | `state root mismatch` |
| Tampered exec signature | `replay.Verify` | `signature mismatch` |
| Missing validation sig | `l1.SubmitAnchor` | `missing validation signature` |

All failures caught BEFORE anchor is accepted.

## 6. Determinism Proof

Same IR + CET + constraints always produces the same execution_hash:
```
ComputeExecutionHash("ir:alice->bob", "cet:transfer:100", "max:1000")
  → 001bfab6b797c0179e0a46497898cac1e2b6d2fbe82db2e9b5507036075c5411  (run 1)
  → 001bfab6b797c0179e0a46497898cac1e2b6d2fbe82db2e9b5507036075c5411  (run 2)

GenerateStateRoot([env-1, env-2, env-3])
  → 5825a113f6d2be0d050f90e871f1e627eec13c23c3ebc22bda81f38990fc2f8e  (A,B,C order)
  → 5825a113f6d2be0d050f90e871f1e627eec13c23c3ebc22bda81f38990fc2f8e  (C,B,A order)
  deterministic=true
```
No timestamp, no randomness influences any hash. Hash derived ONLY from IR + CET + constraints.

## 7. What Changed vs Previous Version

| Area | Before | After (PDV) |
|---|---|---|
| Envelope | `{ID, Payload, Hash}` | `{ExecutionID, InputHash, OutputHash, ExecutionHash, TraceHash, SignerIDs}` |
| Hash source | `sha256(payload)` | `sha256(ir + cet + constraints)` — no raw data after hashing |
| Validation | Verify sig + re-hash payload | Recompute execution_hash + verify input_hash + output_hash + sig |
| Replay | Re-hash payload, verify sig | Recompute from IR+CET+constraints, verify all hashes + sigs, log exact reason |
| L1 gate | Check hash presence + sigs | Check execution_hash + input_hash + output_hash + state root + sigs independently |
| Failure surface | Tampered payload, bad sig | Mismatched CET, mismatched IR, partial sig, wrong input/output hash, corrupted state root |

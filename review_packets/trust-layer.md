# trust-layer — Review Packet

## 1. Entry Point
`main.go` — wires all agents, runs the happy path, and demonstrates every failure case.

## 2. Three Core Files

| File | Responsibility |
|---|---|
| `agent/agent.go` | Agent identity (ID, role, ed25519 key-pair, Sign) |
| `crypto/crypto.go` | Sign / Verify / MultiSig.VerifyBoth |
| `l1-interface/l1.go` | Strict L1 boundary — rejects any invalid anchor |

## 3. Execution Flow

```
ExecutionAgent.Execute(payload)
  → sha256(payload) = envelopeHash
  → ed25519.Sign(envelopeHash, execPrivKey) = execSig
  → log: signed

ValidationAgent.Validate(envelope, execSig, execPub)
  → Verify(execSig, envelopeHash, execPub)   ← rejects if invalid
  → sha256(payload) == envelopeHash           ← rejects if tampered
  → ed25519.Sign(envelopeHash, valPrivKey) = valSig
  → log: validated

RelayAgent.BuildAnchor(envelopes, execSig, valSig)
  → stateRoot = sha256(all envelope hashes)
  → Anchor{envelopes, stateRoot, MultiSig{execSig, valSig}}
  → log: anchor_built

l1.SubmitAnchor(anchor)
  → reject if: empty envelopes | empty stateRoot | missing sigs | stateRoot mismatch | sig invalid
  → accept if: all checks pass

replay.Verify(anchor)
  → re-hash every envelope payload
  → re-derive stateRoot
  → VerifyBoth(execSig, valSig)
  → fail if any check fails
```

## 4. Real Output

```
[L1] status=accepted
[Replay] ok=true
[Replay Tamper] correctly rejected
[L1 Bad] status=rejected reason=missing validation signature
[Val Bad Sig] err=validation rejected: signature verification failed: invalid or mismatched key
```

## 5. Failure Cases

| Scenario | Where caught | Reason returned |
|---|---|---|
| Invalid execution signature | `ValidationAgent.Validate` | `signature verification failed` |
| Missing validation signature | `l1.SubmitAnchor` | `missing validation signature` |
| Tampered execution signature | `replay.Verify` | `signature mismatch` |
| Empty envelope set | `l1.SubmitAnchor` | `empty envelope set` |
| State root mismatch | `l1.SubmitAnchor` | `state root mismatch` |
| Hash mismatch on replay | `replay.Verify` | `envelope X: hash mismatch` |

## 6. Proof

### Why identity is required
Anonymous execution cannot be audited or disputed. Every action is bound to a
key-pair so any forgery is detectable: you cannot produce a valid signature
without the private key.

### Hashing vs Signing
- **Hash** (sha256): proves data integrity — the bytes have not changed.
- **Signature** (ed25519): proves authenticity — only the holder of the private
  key could have produced this value over this data.

### Why multi-sig prevents single-point trust
If only one agent signs, a compromised agent can forge the entire pipeline.
Requiring both `execSig` and `valSig` means an attacker must compromise two
independent key-pairs simultaneously.

### Why L1 boundary must be strict
L1 state is immutable once written. Any invalid anchor that reaches the chain
cannot be rolled back. The boundary re-derives and re-verifies every invariant
independently of what upstream agents claim.

### Why logs must be immutable
Replay reconstructs the execution history from logs. Any overwrite would allow
history to be rewritten, breaking auditability and making replay results
untrustworthy.

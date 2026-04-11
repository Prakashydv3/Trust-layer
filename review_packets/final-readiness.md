# final-readiness — Review Packet

## 1. Full Execution Flow

```
Gurukul TTS → TTSRecord{ID, Text}
  → [TTS] records loaded: 3

ExecutionAgent.Execute(id, payload)
  → sha256(payload) = envelopeHash
  → ed25519.Sign(envelopeHash) = execSig
  → log: signed

ValidationAgent.Validate(envelope, execSig, execPub)  ← BEFORE anchor
  → Verify(execSig, envelopeHash, execPub)  ← reject if invalid sig
  → sha256(payload) == envelopeHash          ← reject if input hash mismatch
  → sha256(payload) == envelopeHash          ← reject if output hash mismatch
  → log: validated / exec_sig_invalid

[repeat for all 3 envelopes]

engine.GenerateStateRoot(envelopes)
  → sort envelopes by ID (mandatory for determinism)
  → sha256(hash1 + hash2 + hash3) = stateRoot

RelayAgent.BuildAnchor(envelopes, execAgent, valAgent)
  → GenerateStateRoot(envelopes)
  → execAgent.Sign(stateRoot) = execSig
  → valAgent.Sign(stateRoot) = valSig
  → Anchor{envelopes, stateRoot, MultiSig{execSig, valSig}}
  → log: anchor_built

l1.SubmitAnchor(anchor)
  → reject if: empty envelopes | missing sigs | stateRoot mismatch | sig invalid
  → accept if: all checks pass

replay.Verify(anchor)
  → re-hash every envelope payload
  → re-derive stateRoot via GenerateStateRoot
  → VerifyBoth(execSig, valSig) against stateRoot
```

## 2. State Root Proof

```
A,B,C → d418baced915c2e229af052bbd036df76f77bbe3e5a0231ab0ea67023ebc3064
C,B,A → d418baced915c2e229af052bbd036df76f77bbe3e5a0231ab0ea67023ebc3064
deterministic=true
```

Sort by execution_id is mandatory. Same input in any order always produces the same root.

## 3. Agent Behavior

| Agent | Action | Log Status |
|---|---|---|
| ExecutionAgent | sha256(payload) + ed25519.Sign | `signed` |
| ValidationAgent | Verify execSig → input hash check → output hash check | `validated` / `exec_sig_invalid` |
| RelayAgent | GenerateStateRoot → Sign stateRoot → BuildAnchor | `anchor_built` |

## 4. Replay Proof

```
[ReplaySystem] run1 ok=true root=d418baced915c2e229af052bbd036df76f77bbe3e5a0231ab0ea67023ebc3064
[ReplaySystem] run2 ok=true root=d418baced915c2e229af052bbd036df76f77bbe3e5a0231ab0ea67023ebc3064
[ReplaySystem] same=true
[Replay] ok=true
```

## 5. Failure Cases (all rejected BEFORE anchor)

| Scenario | Caught at | Error |
|---|---|---|
| Tampered envelope payload | `ValidationAgent.Validate` | `input hash mismatch` |
| Wrong input hash | `ValidationAgent.Validate` | `signature verification failed` |
| Wrong output hash | `ValidationAgent.Validate` | `signature verification failed` |
| Bad exec signature | `ValidationAgent.Validate` | `signature verification failed` |
| Tampered exec sig on replay | `replay.Verify` | `signature mismatch` |
| Missing validation sig | `l1.SubmitAnchor` | `missing validation signature` |

## 6. Real Output

```
[Tampered Envelope] rejected=true err=input hash mismatch: envelope hash does not match payload
[Wrong Input Hash]  rejected=true err=validation rejected: signature verification failed: invalid or mismatched key
[Wrong Output Hash] rejected=true err=validation rejected: signature verification failed: invalid or mismatched key
[Bad Exec Sig]      rejected=true err=validation rejected: signature verification failed: invalid or mismatched key
[Validated] env-1 hash=11fcfc2914465321
[Validated] env-2 hash=82e7c1da9ced4d2d
[Validated] env-3 hash=060a3471aead1648
[StateRoot] A,B,C → d418baced915c2e229af052bbd036df76f77bbe3e5a0231ab0ea67023ebc3064
[StateRoot] C,B,A → d418baced915c2e229af052bbd036df76f77bbe3e5a0231ab0ea67023ebc3064
[StateRoot] deterministic=true
[L1] status=accepted
[ReplaySystem] run1 ok=true root=d418baced915c2e229af052bbd036df76f77bbe3e5a0231ab0ea67023ebc3064
[ReplaySystem] run2 ok=true root=d418baced915c2e229af052bbd036df76f77bbe3e5a0231ab0ea67023ebc3064
[ReplaySystem] same=true
[Replay] ok=true
[Replay Tamper] correctly rejected
[L1 Bad] status=rejected reason=missing validation signature
```

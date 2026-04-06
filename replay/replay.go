package replay

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"trust-layer/crypto"
	"trust-layer/engine"
)

// Result describes the outcome of a replay attempt.
type Result struct {
	OK     bool
	Reason string
}

// Verify replays an anchor and checks hash correctness AND signature authenticity.
func Verify(anchor engine.Anchor) Result {
	for _, e := range anchor.Envelopes {
		h := sha256.Sum256([]byte(e.Payload))
		if hex.EncodeToString(h[:]) != hex.EncodeToString(e.Hash) {
			return Result{false, "envelope " + e.ID + ": hash mismatch"}
		}
	}
	if engine.GenerateStateRoot(anchor.Envelopes) != hex.EncodeToString(anchor.StateRoot) {
		return Result{false, "state root mismatch"}
	}
	ms := crypto.MultiSig{
		ExecutionSig:  anchor.Signatures.ExecutionSig,
		ValidationSig: anchor.Signatures.ValidationSig,
	}
	if err := ms.VerifyBoth(
		anchor.StateRoot,
		ed25519.PublicKey(anchor.ExecPub),
		ed25519.PublicKey(anchor.ValPub),
	); err != nil {
		return Result{false, "signature mismatch: " + err.Error()}
	}
	return Result{true, ""}
}

// ReplaySystem re-derives state root from raw envelopes and verifies each hash.
// Proves full system reproducibility: same envelopes always produce same root.
func ReplaySystem(envs []engine.Envelope) (bool, string) {
	for _, e := range envs {
		h := sha256.Sum256([]byte(e.Payload))
		if hex.EncodeToString(h[:]) != hex.EncodeToString(e.Hash) {
			return false, "envelope " + e.ID + ": hash mismatch"
		}
	}
	return true, engine.GenerateStateRoot(envs)
}

// VerifyWithTamperedSig demonstrates replay failure on signature mismatch.
func VerifyWithTamperedSig(anchor engine.Anchor) error {
	anchor.Signatures.ExecutionSig = []byte("tampered")
	r := Verify(anchor)
	if r.OK {
		return errors.New("replay should have failed but passed")
	}
	return nil
}

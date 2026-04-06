package l1interface

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"trust-layer/crypto"
	"trust-layer/engine"
)

// Response is the structured result returned by SubmitAnchor.
// L1 never trusts upstream blindly: every invariant is re-verified at this
// boundary. L1 state is immutable once written — this is the last gate.
type Response struct {
	Status string // "accepted" | "rejected"
	Reason string // populated on rejection
}

// SubmitAnchor is the strict L1 gate. Rejects any anchor that fails any invariant.
func SubmitAnchor(anchor engine.Anchor) Response {
	if err := validateAnchor(anchor); err != nil {
		return Response{Status: "rejected", Reason: err.Error()}
	}
	return Response{Status: "accepted"}
}

func validateAnchor(anchor engine.Anchor) error {
	if len(anchor.Envelopes) == 0 {
		return errors.New("empty envelope set")
	}
	if len(anchor.StateRoot) == 0 {
		return errors.New("invalid state root: empty")
	}
	if len(anchor.Signatures.ExecutionSig) == 0 {
		return errors.New("missing execution signature")
	}
	if len(anchor.Signatures.ValidationSig) == 0 {
		return errors.New("missing validation signature")
	}
	for _, e := range anchor.Envelopes {
		if len(e.Hash) == 0 {
			return errors.New("envelope " + e.ID + " has empty hash")
		}
	}
	// Re-derive state root deterministically and compare
	if engine.GenerateStateRoot(anchor.Envelopes) != hex.EncodeToString(anchor.StateRoot) {
		return errors.New("state root mismatch")
	}
	// Verify both signatures against the state root
	ms := crypto.MultiSig{
		ExecutionSig:  anchor.Signatures.ExecutionSig,
		ValidationSig: anchor.Signatures.ValidationSig,
	}
	return ms.VerifyBoth(anchor.StateRoot,
		ed25519.PublicKey(anchor.ExecPub),
		ed25519.PublicKey(anchor.ValPub),
	)
}

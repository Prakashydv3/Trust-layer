package l1interface

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"trust-layer/crypto"
	"trust-layer/engine"
)

// Response is the structured result returned by SubmitAnchor.
type Response struct {
	Status string // "accepted" | "rejected"
	Reason string // populated on rejection
}

// SubmitAnchor is the PDV hard gate. L1 independently verifies everything.
// Must NOT trust upstream. Rejects on any invariant violation.
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
		if e.ExecutionHash == "" {
			return errors.New("envelope " + e.ExecutionID + ": missing execution_hash")
		}
		if e.InputHash == "" {
			return errors.New("envelope " + e.ExecutionID + ": missing input_hash")
		}
		if e.OutputHash == "" {
			return errors.New("envelope " + e.ExecutionID + ": missing output_hash")
		}
	}
	// Re-derive state root deterministically — L1 never trusts upstream value
	if engine.GenerateStateRoot(anchor.Envelopes) != hex.EncodeToString(anchor.StateRoot) {
		return errors.New("state root mismatch: non-deterministic or corrupted")
	}
	// Verify both signatures against state root
	ms := crypto.MultiSig{
		ExecutionSig:  anchor.Signatures.ExecutionSig,
		ValidationSig: anchor.Signatures.ValidationSig,
	}
	return ms.VerifyBoth(anchor.StateRoot,
		ed25519.PublicKey(anchor.ExecPub),
		ed25519.PublicKey(anchor.ValPub),
	)
}

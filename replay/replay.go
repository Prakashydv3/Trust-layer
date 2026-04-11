package replay

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"trust-layer/crypto"
	"trust-layer/engine"
	"trust-layer/logger"
	"time"
)

// Result describes the outcome of a replay attempt.
type Result struct {
	OK     bool
	Reason string
}

// Verify replays an anchor: recomputes execution_hash, verifies signatures, regenerates state root.
// Must match anchor EXACTLY — any deviation is a hard reject with logged reason.
func Verify(anchor engine.Anchor, inputs []ReplayInput) Result {
	for _, e := range anchor.Envelopes {
		inp := findInput(inputs, e.ExecutionID)
		if inp == nil {
			return fail(e.ExecutionID, "no replay input provided")
		}
		// Recompute execution_hash from IR + CET + constraints
		recomputed := engine.ComputeExecutionHash(inp.IR, inp.CET, inp.Constraints)
		if recomputed != e.ExecutionHash {
			return fail(e.ExecutionID, "execution_hash mismatch: got "+e.ExecutionHash+" want "+recomputed)
		}
		// Verify input_hash
		if engine.HashHex(inp.IR) != e.InputHash {
			return fail(e.ExecutionID, "input_hash mismatch")
		}
		// Verify output_hash
		if engine.HashHex(inp.CET) != e.OutputHash {
			return fail(e.ExecutionID, "output_hash mismatch")
		}
	}
	// Regenerate state root and match anchor exactly
	recomputedRoot := engine.GenerateStateRoot(anchor.Envelopes)
	if recomputedRoot != hex.EncodeToString(anchor.StateRoot) {
		return Result{false, "state root mismatch"}
	}
	// Verify both signatures
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

// ReplaySystem re-derives state root from envelopes and replay inputs.
func ReplaySystem(envs []engine.Envelope, inputs []ReplayInput) (bool, string) {
	for _, e := range envs {
		inp := findInput(inputs, e.ExecutionID)
		if inp == nil {
			return false, "no replay input for " + e.ExecutionID
		}
		recomputed := engine.ComputeExecutionHash(inp.IR, inp.CET, inp.Constraints)
		if recomputed != e.ExecutionHash {
			return false, "envelope " + e.ExecutionID + ": execution_hash mismatch"
		}
	}
	return true, engine.GenerateStateRoot(envs)
}

// VerifyWithTamperedSig demonstrates replay failure on signature mismatch.
func VerifyWithTamperedSig(anchor engine.Anchor, inputs []ReplayInput) error {
	anchor.Signatures.ExecutionSig = []byte("tampered")
	r := Verify(anchor, inputs)
	if r.OK {
		return errors.New("replay should have failed but passed")
	}
	return nil
}

// ReplayInput holds the raw IR+CET+constraints needed to recompute execution_hash.
type ReplayInput struct {
	ExecutionID string
	IR          string
	CET         string
	Constraints string
}

func findInput(inputs []ReplayInput, id string) *ReplayInput {
	for i := range inputs {
		if inputs[i].ExecutionID == id {
			return &inputs[i]
		}
	}
	return nil
}

func fail(id, reason string) Result {
	logger.Append(logger.Entry{
		ExecutionID:     id,
		AgentID:         "replay",
		Hash:            "",
		SignatureStatus: "replay_failed: " + reason,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	})
	return Result{false, reason}
}

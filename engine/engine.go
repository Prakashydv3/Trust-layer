package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"trust-layer/agent"
	"trust-layer/crypto"
	"trust-layer/logger"
)

// Envelope is the atomic unit of execution.
type Envelope struct {
	ID      string
	Payload string
	Hash    []byte // sha256 of Payload
}

// Anchor is the final artifact submitted to L1.
type Anchor struct {
	Envelopes  []Envelope
	StateRoot  []byte // sha256 of all envelope hashes
	AgentID    string
	Signatures crypto.MultiSig
	ExecPub    []byte
	ValPub     []byte
}

// hash256 returns sha256 of data.
func hash256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// ExecutionAgent processes payloads into signed envelopes.
type ExecutionAgent struct{ A *agent.Agent }

func (e *ExecutionAgent) Execute(id, payload string) (Envelope, []byte, error) {
	h := hash256([]byte(payload))
	sig := e.A.Sign(h)
	env := Envelope{ID: id, Payload: payload, Hash: h}
	logger.Append(logger.Entry{
		ExecutionID:     id,
		AgentID:         e.A.AgentID,
		Hash:            hex.EncodeToString(h),
		SignatureStatus: "signed",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	})
	return env, sig, nil
}

// ValidationAgent verifies the execution signature before accepting an envelope.
// Verification happens BEFORE hash validation: authenticity must be confirmed
// first, otherwise we may waste work validating data from an untrusted source.
type ValidationAgent struct{ A *agent.Agent }

func (v *ValidationAgent) Validate(env Envelope, execSig []byte, execPub []byte) ([]byte, error) {
	if err := crypto.Verify(env.Hash, execSig, execPub); err != nil {
		logger.Append(logger.Entry{
			ExecutionID:     env.ID,
			AgentID:         v.A.AgentID,
			Hash:            hex.EncodeToString(env.Hash),
			SignatureStatus: "exec_sig_invalid",
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
		})
		return nil, fmt.Errorf("validation rejected: %w", err)
	}
	// Re-hash to confirm integrity
	expected := hash256([]byte(env.Payload))
	if hex.EncodeToString(expected) != hex.EncodeToString(env.Hash) {
		return nil, errors.New("hash mismatch")
	}
	valSig := v.A.Sign(env.Hash)
	logger.Append(logger.Entry{
		ExecutionID:     env.ID,
		AgentID:         v.A.AgentID,
		Hash:            hex.EncodeToString(env.Hash),
		SignatureStatus: "validated",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	})
	return valSig, nil
}

// RelayAgent assembles the Anchor with both signatures.
type RelayAgent struct{ A *agent.Agent }

func (r *RelayAgent) BuildAnchor(
	envs []Envelope,
	execSig, valSig []byte,
	execAgent, valAgent *agent.Agent,
) (Anchor, error) {
	if len(envs) == 0 {
		return Anchor{}, errors.New("relay: empty envelope set")
	}
	// Build state root from all envelope hashes
	var combined []byte
	for _, e := range envs {
		combined = append(combined, e.Hash...)
	}
	stateRoot := hash256(combined)

	anchor := Anchor{
		Envelopes: envs,
		StateRoot: stateRoot,
		AgentID:   r.A.AgentID,
		Signatures: crypto.MultiSig{
			ExecutionSig:  execSig,
			ValidationSig: valSig,
		},
		ExecPub: execAgent.PublicKey,
		ValPub:  valAgent.PublicKey,
	}
	logger.Append(logger.Entry{
		ExecutionID:     "anchor-" + envs[0].ID,
		AgentID:         r.A.AgentID,
		Hash:            hex.EncodeToString(stateRoot),
		SignatureStatus: "anchor_built",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	})
	return anchor, nil
}

package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
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

func hash256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// GenerateStateRoot sorts envelopes by ID then hashes all envelope hashes.
// Sorting is mandatory: same input in any order must always produce the same root.
func GenerateStateRoot(envs []Envelope) string {
	sorted := make([]Envelope, len(envs))
	copy(sorted, envs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	var combined []byte
	for _, e := range sorted {
		combined = append(combined, e.Hash...)
	}
	h := sha256.Sum256(combined)
	return hex.EncodeToString(h[:])
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
// Authenticity is confirmed first — no point validating data from an untrusted source.
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
	// Verify input hash (re-derive from payload)
	inputHash := hash256([]byte(env.Payload))
	if hex.EncodeToString(inputHash) != hex.EncodeToString(env.Hash) {
		return nil, errors.New("input hash mismatch: envelope hash does not match payload")
	}
	// Verify output hash (same as input for pure execution — payload is the output)
	outputHash := hash256([]byte(env.Payload))
	if hex.EncodeToString(outputHash) != hex.EncodeToString(env.Hash) {
		return nil, errors.New("output hash mismatch: envelope hash does not match output")
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

// RelayAgent assembles the Anchor with both signatures over the state root.
type RelayAgent struct{ A *agent.Agent }

func (r *RelayAgent) BuildAnchor(
	envs []Envelope,
	execAgent, valAgent *agent.Agent,
) (Anchor, error) {
	if len(envs) == 0 {
		return Anchor{}, errors.New("relay: empty envelope set")
	}
	stateRootHex := GenerateStateRoot(envs)
	stateRoot, _ := hex.DecodeString(stateRootHex)
	// Both agents sign the state root — covers all envelopes, not just one
	execSig := execAgent.Sign(stateRoot)
	valSig := valAgent.Sign(stateRoot)
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
		Hash:            stateRootHex,
		SignatureStatus: "anchor_built",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	})
	return anchor, nil
}

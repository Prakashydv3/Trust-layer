package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"trust-layer/agent"
	"trust-layer/crypto"
	"trust-layer/logger"
)

// IR is the structured Intermediate Representation.
// All hashes derive ONLY from this structure — no raw strings.
type IR struct {
	Operation string `json:"operation"`
	From      string `json:"from"`
	To        string `json:"to"`
	Amount    string `json:"amount"`
}

// CET is the structured Canonical Execution Tree.
type CET struct {
	Steps []string `json:"steps"`
}

// Canonical returns a deterministic string representation of IR.
func (ir IR) Canonical() string {
	return ir.Operation + ":" + ir.From + "->" + ir.To + ":" + ir.Amount
}

// Canonical returns a deterministic string representation of CET.
func (cet CET) Canonical() string {
	h := sha256.Sum256([]byte(strings.Join(cet.Steps, ",")))
	return hex.EncodeToString(h[:])
}

// Envelope is the PDV-compliant atomic unit of execution.
// All fields are hash-derived — no raw data dependency after hashing.
type Envelope struct {
	ExecutionID   string
	InputHash     string // sha256 of IR.Canonical()
	OutputHash    string // sha256 of CET.Canonical()
	ExecutionHash string // sha256(IR.Canonical() + CET.Canonical() + constraints)
	TraceHash     string // sha256(ExecutionHash) — chain integrity
	SignerIDs     []string
}

// Anchor is the final PDV artifact submitted to L1.
type Anchor struct {
	Envelopes  []Envelope
	StateRoot  []byte
	AgentID    string
	Signatures crypto.MultiSig
	ExecPub    []byte
	ValPub     []byte
}

func hash256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func hashHex(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// HashHex is the exported version for use by replay and l1 packages.
func HashHex(data string) string { return hashHex(data) }

// ComputeExecutionHash derives execution_hash deterministically from
// structured IR + CET + constraints only. No timestamp, no randomness.
func ComputeExecutionHash(ir IR, cet CET, constraints string) string {
	combined := ir.Canonical() + "|" + cet.Canonical() + "|" + constraints
	return hashHex(combined)
}

// ComputeExecutionHashRaw is kept for agent packages that work with raw strings.
func ComputeExecutionHashRaw(ir, cet, constraints string) string {
	combined := ir + "|" + cet + "|" + constraints
	return hashHex(combined)
}

// GenerateStateRoot sorts envelopes by ExecutionID then hashes all ExecutionHashes.
// Sorting is mandatory: same input in any order must always produce the same root.
func GenerateStateRoot(envs []Envelope) string {
	sorted := make([]Envelope, len(envs))
	copy(sorted, envs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ExecutionID < sorted[j].ExecutionID })
	var combined []byte
	for _, e := range sorted {
		h, _ := hex.DecodeString(e.ExecutionHash)
		combined = append(combined, h...)
	}
	h := sha256.Sum256(combined)
	return hex.EncodeToString(h[:])
}

// ExecutionAgent produces PDV-compliant envelopes from structured IR+CET inputs.
type ExecutionAgent struct{ A *agent.Agent }

func (e *ExecutionAgent) Execute(id string, ir IR, cet CET, constraints string) (Envelope, []byte, error) {
	inputHash := hashHex(ir.Canonical())
	outputHash := hashHex(cet.Canonical())
	execHash := ComputeExecutionHash(ir, cet, constraints)
	traceHash := hashHex(execHash)

	execHashBytes, _ := hex.DecodeString(execHash)
	sig := e.A.Sign(execHashBytes)

	env := Envelope{
		ExecutionID:   id,
		InputHash:     inputHash,
		OutputHash:    outputHash,
		ExecutionHash: execHash,
		TraceHash:     traceHash,
		SignerIDs:     []string{e.A.AgentID},
	}
	logger.Append(logger.Entry{
		ExecutionID:     id,
		AgentID:         e.A.AgentID,
		Hash:            execHash,
		SignatureStatus: "signed",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	})
	return env, sig, nil
}

// ValidationAgent recomputes execution_hash from structured IR/CET and verifies.
type ValidationAgent struct{ A *agent.Agent }

func (v *ValidationAgent) Validate(env Envelope, execSig []byte, execPub []byte, ir IR, cet CET, constraints string) ([]byte, error) {
	recomputed := ComputeExecutionHash(ir, cet, constraints)
	if recomputed != env.ExecutionHash {
		logger.Append(logger.Entry{
			ExecutionID:     env.ExecutionID,
			AgentID:         v.A.AgentID,
			Hash:            env.ExecutionHash,
			SignatureStatus: "execution_hash_mismatch",
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
		})
		return nil, fmt.Errorf("execution_hash mismatch: got %s want %s", env.ExecutionHash, recomputed)
	}
	if hashHex(ir.Canonical()) != env.InputHash {
		return nil, errors.New("input_hash mismatch")
	}
	if hashHex(cet.Canonical()) != env.OutputHash {
		return nil, errors.New("output_hash mismatch")
	}
	execHashBytes, _ := hex.DecodeString(env.ExecutionHash)
	if err := crypto.Verify(execHashBytes, execSig, execPub); err != nil {
		logger.Append(logger.Entry{
			ExecutionID:     env.ExecutionID,
			AgentID:         v.A.AgentID,
			Hash:            env.ExecutionHash,
			SignatureStatus: "exec_sig_invalid",
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
		})
		return nil, fmt.Errorf("validation rejected: %w", err)
	}
	valSig := v.A.Sign(execHashBytes)
	logger.Append(logger.Entry{
		ExecutionID:     env.ExecutionID,
		AgentID:         v.A.AgentID,
		Hash:            env.ExecutionHash,
		SignatureStatus: "validated",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	})
	return valSig, nil
}

// RelayAgent assembles the PDV Anchor — both agents sign the same execution_hash via state root.
type RelayAgent struct{ A *agent.Agent }

// ReplayAgent independently recomputes execution_hash from structured inputs.
type ReplayAgent struct{ A *agent.Agent }

func (r *ReplayAgent) Recompute(id string, ir IR, cet CET, constraints string) string {
	hash := ComputeExecutionHash(ir, cet, constraints)
	logger.Append(logger.Entry{
		ExecutionID:     id,
		AgentID:         r.A.AgentID,
		Hash:            hash,
		SignatureStatus: "recomputed",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	})
	return hash
}

func (r *RelayAgent) BuildAnchor(
	envs []Envelope,
	execAgent, valAgent *agent.Agent,
) (Anchor, error) {
	if len(envs) == 0 {
		return Anchor{}, errors.New("relay: empty envelope set")
	}
	stateRootHex := GenerateStateRoot(envs)
	stateRoot, _ := hex.DecodeString(stateRootHex)
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
		ExecutionID:     "anchor-" + envs[0].ExecutionID,
		AgentID:         r.A.AgentID,
		Hash:            stateRootHex,
		SignatureStatus: "anchor_built",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	})
	return anchor, nil
}

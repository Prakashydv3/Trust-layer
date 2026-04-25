package agents

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
	"trust-layer/agent"
	"trust-layer/logger"
)

// ExecutionAgent independently computes execution_hash from IR+CET+constraints.
// Uses its own compute function — does NOT call shared engine hash directly.
type ExecutionAgent struct{ A *agent.Agent }

func (e *ExecutionAgent) ComputeHash(ir, cet, constraints string) string {
	combined := ir + "|" + cet + "|" + constraints
	h := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(h[:])
}

func (e *ExecutionAgent) Execute(id, ir, cet, constraints string) (string, []byte) {
	execHash := e.ComputeHash(ir, cet, constraints)
	execHashBytes, _ := hex.DecodeString(execHash)
	sig := e.A.Sign(execHashBytes)
	logger.Append(logger.Entry{
		ExecutionID:     id,
		AgentID:         e.A.AgentID,
		Hash:            execHash,
		SignatureStatus: "exec_computed",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	})
	return execHash, sig
}

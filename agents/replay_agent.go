package agents

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
	"trust-layer/agent"
	"trust-layer/logger"
)

// ReplayAgent independently recomputes execution_hash.
// Uses its own compute function — no shared state with other agents.
type ReplayAgent struct{ A *agent.Agent }

func (r *ReplayAgent) ComputeHash(ir, cet, constraints string) string {
	combined := ir + "|" + cet + "|" + constraints
	h := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(h[:])
}

func (r *ReplayAgent) Recompute(id, ir, cet, constraints string) string {
	hash := r.ComputeHash(ir, cet, constraints)
	logger.Append(logger.Entry{
		ExecutionID:     id,
		AgentID:         r.A.AgentID,
		Hash:            hash,
		SignatureStatus: "replay_computed",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	})
	return hash
}

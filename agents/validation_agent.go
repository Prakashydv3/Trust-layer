package agents

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
	"trust-layer/agent"
	"trust-layer/crypto"
	"trust-layer/logger"
)

// ValidationAgent independently recomputes execution_hash.
// Uses its own compute function — no shared state with ExecutionAgent.
type ValidationAgent struct{ A *agent.Agent }

func (v *ValidationAgent) ComputeHash(ir, cet, constraints string) string {
	combined := ir + "|" + cet + "|" + constraints
	h := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(h[:])
}

func (v *ValidationAgent) Validate(id, ir, cet, constraints string, execHash string, execSig []byte, execPub []byte) (string, error) {
	recomputed := v.ComputeHash(ir, cet, constraints)
	if recomputed != execHash {
		logger.Append(logger.Entry{
			ExecutionID:     id,
			AgentID:         v.A.AgentID,
			Hash:            execHash,
			SignatureStatus: "val_hash_mismatch",
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
		})
		return "", errors.New("validation: execution_hash mismatch")
	}
	execHashBytes, _ := hex.DecodeString(execHash)
	if err := crypto.Verify(execHashBytes, execSig, execPub); err != nil {
		logger.Append(logger.Entry{
			ExecutionID:     id,
			AgentID:         v.A.AgentID,
			Hash:            execHash,
			SignatureStatus: "val_sig_invalid",
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
		})
		return "", errors.New("validation: signature invalid")
	}
	logger.Append(logger.Entry{
		ExecutionID:     id,
		AgentID:         v.A.AgentID,
		Hash:            recomputed,
		SignatureStatus: "val_computed",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	})
	return recomputed, nil
}

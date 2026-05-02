package akashic

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
)

const AkashicFile = "akashic.json"

// State represents one node in the AKASHIC state graph.
type State struct {
	StateRoot       string `json:"state_root"`
	ParentStateHash string `json:"parent_state_hash"`
	ExecutionID     string `json:"execution_id"`
	TraceID         string `json:"trace_id"`
}

var mu sync.Mutex

// Append adds a new state to the linear chain.
// parent_state_hash = sha256 of previous state_root (or "genesis" for first).
func Append(stateRoot, executionID, traceID string) error {
	mu.Lock()
	defer mu.Unlock()

	// Compute parent hash from last state
	parentHash := "genesis"
	states, _ := loadLocked()
	if len(states) > 0 {
		h := sha256.Sum256([]byte(states[len(states)-1].StateRoot))
		parentHash = hex.EncodeToString(h[:])
	}

	s := State{
		StateRoot:       stateRoot,
		ParentStateHash: parentHash,
		ExecutionID:     executionID,
		TraceID:         traceID,
	}
	f, err := os.OpenFile(AkashicFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	line, _ := json.Marshal(s)
	_, err = f.Write(append(line, '\n'))
	return err
}

// Load reads all states from the akashic file.
func Load() ([]State, error) {
	mu.Lock()
	defer mu.Unlock()
	return loadLocked()
}

func loadLocked() ([]State, error) {
	f, err := os.Open(AkashicFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []State{}, nil
		}
		return nil, err
	}
	defer f.Close()
	var states []State
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var s State
		if err := json.Unmarshal(scanner.Bytes(), &s); err != nil {
			return nil, err
		}
		states = append(states, s)
	}
	return states, nil
}

// VerifyChain checks parent_state_hash integrity across the chain.
func VerifyChain(states []State) error {
	for i := 1; i < len(states); i++ {
		h := sha256.Sum256([]byte(states[i-1].StateRoot))
		expected := hex.EncodeToString(h[:])
		if states[i].ParentStateHash != expected {
			return errors.New("akashic: chain broken at " + states[i].ExecutionID)
		}
	}
	return nil
}

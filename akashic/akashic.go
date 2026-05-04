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

// State is one node in the AKASHIC state graph.
// parent_state_hash links to parent — supports branching (multiple children per parent).
type State struct {
	StateHash       string `json:"state_hash"`        // sha256(state_root + execution_id)
	StateRoot       string `json:"state_root"`
	ParentStateHash string `json:"parent_state_hash"` // "genesis" for root
	ExecutionID     string `json:"execution_id"`
	TraceID         string `json:"trace_id"`
}

var mu sync.Mutex

// computeStateHash derives a unique hash for this state node.
func computeStateHash(stateRoot, executionID string) string {
	h := sha256.Sum256([]byte(stateRoot + "|" + executionID))
	return hex.EncodeToString(h[:])
}

// Append adds a new state node. parentStateHash="" means root (genesis).
func Append(stateRoot, executionID, traceID, parentStateHash string) error {
	mu.Lock()
	defer mu.Unlock()
	if parentStateHash == "" {
		parentStateHash = "genesis"
	}
	s := State{
		StateHash:       computeStateHash(stateRoot, executionID),
		StateRoot:       stateRoot,
		ParentStateHash: parentStateHash,
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

// VerifyLineage checks every state traces back to genesis.
func VerifyLineage(states []State) error {
	index := make(map[string]State)
	for _, s := range states {
		index[s.StateHash] = s
	}
	for _, s := range states {
		if s.ParentStateHash == "genesis" {
			continue
		}
		if _, ok := index[s.ParentStateHash]; !ok {
			return errors.New("akashic: lineage broken for " + s.ExecutionID +
				" parent=" + s.ParentStateHash[:8])
		}
	}
	return nil
}

// GetLineage returns the full path from a state back to genesis.
func GetLineage(states []State, stateHash string) ([]State, error) {
	index := make(map[string]State)
	for _, s := range states {
		index[s.StateHash] = s
	}
	var path []State
	current := stateHash
	for current != "genesis" {
		s, ok := index[current]
		if !ok {
			return nil, errors.New("akashic: lineage broken at " + current[:8])
		}
		path = append([]State{s}, path...)
		current = s.ParentStateHash
	}
	return path, nil
}

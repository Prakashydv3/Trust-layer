package karmachain

import (
	"errors"
	"sync"
	"time"
)

// Entry is one immutable KarmaChain record.
type Entry struct {
	ExecutionID    string
	ExecutionHash  string
	StateRoot      string
	ReplayVerified bool
	Timestamp      string
}

// KarmaChain is an append-only internal ledger.
// No mutation allowed — replay must regenerate exact same chain.
type KarmaChain struct {
	mu      sync.Mutex
	entries []Entry
}

var chain = &KarmaChain{}

// Append adds a new entry to the chain. No overwrites allowed.
func Append(executionID, executionHash, stateRoot string, replayVerified bool) {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	chain.entries = append(chain.entries, Entry{
		ExecutionID:    executionID,
		ExecutionHash:  executionHash,
		StateRoot:      stateRoot,
		ReplayVerified: replayVerified,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	})
}

// Get returns all entries — read only.
func Get() []Entry {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	result := make([]Entry, len(chain.entries))
	copy(result, chain.entries)
	return result
}

// VerifyReplay checks that replayed entries match the stored chain exactly.
func VerifyReplay(replayed []Entry) error {
	chain.mu.Lock()
	defer chain.mu.Unlock()
	if len(replayed) != len(chain.entries) {
		return errors.New("karmachain: replay length mismatch")
	}
	for i, e := range chain.entries {
		if replayed[i].ExecutionID != e.ExecutionID {
			return errors.New("karmachain: execution_id mismatch at index " + string(rune('0'+i)))
		}
		if replayed[i].ExecutionHash != e.ExecutionHash {
			return errors.New("karmachain: execution_hash mismatch for " + e.ExecutionID)
		}
		if replayed[i].StateRoot != e.StateRoot {
			return errors.New("karmachain: state_root mismatch for " + e.ExecutionID)
		}
	}
	return nil
}

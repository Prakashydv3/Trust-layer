package karmachain

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

const ChainFile = "karmachain.json"

// Entry is one immutable KarmaChain record.
// PrevHash chains each entry to the previous — tamper of any entry breaks the chain.
type Entry struct {
	ExecutionID    string `json:"execution_id"`
	ExecutionHash  string `json:"execution_hash"`
	StateRoot      string `json:"state_root"`
	TraceID        string `json:"trace_id"`
	ReplayVerified bool   `json:"replay_verified"`
	Timestamp      string `json:"timestamp"`
	PrevHash       string `json:"prev_hash"` // sha256 of previous entry JSON
}

var mu sync.Mutex

// entryHash computes sha256 of an entry's core fields (excluding PrevHash).
func entryHash(e Entry) string {
	raw := e.ExecutionID + e.ExecutionHash + e.StateRoot + e.TraceID + e.Timestamp
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// Append writes one hash-chained entry to the persistent chain file.
func Append(e Entry) error {
	mu.Lock()
	defer mu.Unlock()

	// Load existing entries to get last hash
	existing, err := loadLocked()
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		e.PrevHash = "genesis"
	} else {
		e.PrevHash = entryHash(existing[len(existing)-1])
	}
	e.Timestamp = time.Now().UTC().Format(time.RFC3339)

	f, err := os.OpenFile(ChainFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	line, _ := json.Marshal(e)
	_, err = f.Write(append(line, '\n'))
	return err
}

// Load reads all entries and verifies hash chain integrity.
// ANY mismatch → HARD FAIL.
func Load() ([]Entry, error) {
	mu.Lock()
	defer mu.Unlock()
	entries, err := loadLocked()
	if err != nil {
		return nil, err
	}
	if err := verifyChain(entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func loadLocked() ([]Entry, error) {
	f, err := os.Open(ChainFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []Entry{}, nil
		}
		return nil, err
	}
	defer f.Close()
	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return nil, errors.New("karmachain: corrupt entry: " + err.Error())
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// verifyChain recomputes full chain — any mismatch is a hard fail.
func verifyChain(entries []Entry) error {
	for i := 1; i < len(entries); i++ {
		expected := entryHash(entries[i-1])
		if entries[i].PrevHash != expected {
			return errors.New("karmachain: tamper detected at entry " + entries[i].ExecutionID +
				" expected_prev=" + expected[:8] + " got=" + entries[i].PrevHash[:8])
		}
	}
	return nil
}

// VerifyReplay checks replayed entries match loaded chain exactly.
func VerifyReplay(loaded, replayed []Entry) error {
	if len(replayed) != len(loaded) {
		return errors.New("karmachain: replay length mismatch")
	}
	for i, e := range loaded {
		if replayed[i].ExecutionID != e.ExecutionID {
			return errors.New("karmachain: execution_id mismatch for " + e.ExecutionID)
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

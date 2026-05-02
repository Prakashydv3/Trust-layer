package karmachain

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"sync"
)

const ChainFile = "karmachain.json"

// Entry is one immutable KarmaChain record.
type Entry struct {
	ExecutionID    string `json:"execution_id"`
	ExecutionHash  string `json:"execution_hash"`
	StateRoot      string `json:"state_root"`
	TraceID        string `json:"trace_id"`
	ReplayVerified bool   `json:"replay_verified"`
	Timestamp      string `json:"timestamp"`
}

var mu sync.Mutex

// Append writes one entry to the persistent chain file (append-only).
func Append(e Entry) error {
	mu.Lock()
	defer mu.Unlock()
	f, err := os.OpenFile(ChainFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	line, _ := json.Marshal(e)
	_, err = f.Write(append(line, '\n'))
	return err
}

// Load reads all entries from the persistent chain file.
func Load() ([]Entry, error) {
	mu.Lock()
	defer mu.Unlock()
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

// VerifyReplay checks that replayed entries match the loaded chain exactly.
func VerifyReplay(loaded, replayed []Entry) error {
	if len(replayed) != len(loaded) {
		return errors.New("karmachain: replay length mismatch")
	}
	for i, e := range loaded {
		if replayed[i].ExecutionID != e.ExecutionID {
			return errors.New("karmachain: execution_id mismatch for index " + string(rune('0'+i)))
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

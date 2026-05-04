package bucket

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

const BucketFile = "bucket.json"

// Record is one finalized execution stored in Bucket.
type Record struct {
	StateRoot   string `json:"state_root"`
	ExecutionID string `json:"execution_id"`
	TraceID     string `json:"trace_id"`
	Timestamp   string `json:"timestamp"`
	RecordHash  string `json:"record_hash"` // sha256(state_root+execution_id+trace_id)
}

func computeRecordHash(stateRoot, executionID, traceID string) string {
	h := sha256.Sum256([]byte(stateRoot + "|" + executionID + "|" + traceID))
	return hex.EncodeToString(h[:])
}

var mu sync.Mutex

// Write stores a finalized PDV-passed execution.
// PDV FAIL → NO WRITE enforced by caller passing pdvAccepted flag.
func Write(stateRoot, executionID, traceID string, pdvAccepted bool) error {
	if !pdvAccepted {
		return errors.New("bucket: write rejected — PDV not accepted")
	}
	mu.Lock()
	defer mu.Unlock()
	f, err := os.OpenFile(BucketFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	r := Record{
		StateRoot:   stateRoot,
		ExecutionID: executionID,
		TraceID:     traceID,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		RecordHash:  computeRecordHash(stateRoot, executionID, traceID),
	}
	line, _ := json.Marshal(r)
	_, err = f.Write(append(line, '\n'))
	return err
}

// Load reads all records and verifies record_hash integrity.
func Load() ([]Record, error) {
	mu.Lock()
	defer mu.Unlock()
	f, err := os.Open(BucketFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []Record{}, nil
		}
		return nil, err
	}
	defer f.Close()
	var records []Record
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var r Record
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			return nil, err
		}
		// Verify record_hash integrity
		expected := computeRecordHash(r.StateRoot, r.ExecutionID, r.TraceID)
		if r.RecordHash != expected {
			return nil, errors.New("bucket: tamper detected for " + r.ExecutionID +
				" expected=" + expected[:8] + " got=" + r.RecordHash[:8])
		}
		records = append(records, r)
	}
	return records, nil
}

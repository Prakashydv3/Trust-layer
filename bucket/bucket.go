package bucket

import (
	"bufio"
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
	}
	line, _ := json.Marshal(r)
	_, err = f.Write(append(line, '\n'))
	return err
}

// Load reads all records from the bucket file.
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
		records = append(records, r)
	}
	return records, nil
}

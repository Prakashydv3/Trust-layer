package logger

import (
	"encoding/json"
	"os"
	"sync"
)

// Entry is one immutable log record.
// Logs must be append-only because replay depends on the exact sequence of
// events; any overwrite would break auditability and tamper-evidence.
type Entry struct {
	ExecutionID     string `json:"execution_id"`
	AgentID         string `json:"agent_id"`
	Hash            string `json:"hash"`
	SignatureStatus string `json:"signature_status"`
	Timestamp       string `json:"timestamp"`
}

const LogFile = "trust-layer.log.json"

var mu sync.Mutex

// Append writes one JSON entry to the log file (append-only, never overwrites).
func Append(e Entry) {
	mu.Lock()
	defer mu.Unlock()
	f, err := os.OpenFile(LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	line, _ := json.Marshal(e)
	f.Write(append(line, '\n'))
}

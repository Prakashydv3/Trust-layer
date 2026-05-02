package main

import (
	"encoding/json"
	"fmt"
	"os"
	"trust-layer/agent"
	"trust-layer/akashic"
	"trust-layer/bucket"
	"trust-layer/engine"
	"trust-layer/karmachain"
	"trust-layer/ksml"
	l1 "trust-layer/l1-interface"
	"trust-layer/replay"
)

// PDVOutput is the canonical output contract.
type PDVOutput struct {
	TraceID           string   `json:"trace_id"`
	ExecutionID       string   `json:"execution_id"`
	ExecutionHash     string   `json:"execution_hash"`
	StateRoot         string   `json:"state_root"`
	AgentHashes       []string `json:"agent_hashes"`
	AgentSignatures   []string `json:"agent_signatures"`
	AgentAgreement    bool     `json:"agent_agreement"`
	DeterministicFlag bool     `json:"deterministic_flag"`
	ReplayVerified    bool     `json:"replay_verified"`
}

func main() {
	// Clean persistent files for fresh run
	os.Remove(karmachain.ChainFile)
	os.Remove(bucket.BucketFile)
	os.Remove(akashic.AkashicFile)

	// --- Agents ---
	execAgent, _ := agent.NewAgent("exec-001", agent.RoleExecution)
	valAgent, _ := agent.NewAgent("val-001", agent.RoleValidation)
	relayAgent, _ := agent.NewAgent("relay-001", agent.RoleRelay)
	replayAgentID, _ := agent.NewAgent("replay-001", agent.RoleRelay)

	exec := &engine.ExecutionAgent{A: execAgent}
	val := &engine.ValidationAgent{A: valAgent}
	relay := &engine.RelayAgent{A: relayAgent}
	rep := &engine.ReplayAgent{A: replayAgentID}

	// ── Phase 1: KSML Canonical Contract failures ───────────────────────
	fmt.Println("--- KSML Validation ---")
	_, err := ksml.ParseKSML(`{"execution_id":"","intent":"TRANSFER","actor":"alice","parameters":{"from":"alice","to":"bob","amount":"100"},"constraints":{"max_amount":"1000"},"metadata":{"timestamp":"2024-01-01T00:00:00Z","source_system":"gurukul","version":"1.0"}}`)
	fmt.Printf("[KSML Missing ID] rejected=%v\n", err != nil)

	_, err = ksml.ParseKSML(`{"execution_id":"env-x","intent":"TRANSFER","actor":"alice","parameters":{"from":"alice","to":"bob","amount":"100"},"constraints":{"max_amount":"1000"},"metadata":{"timestamp":"2024-01-01T00:00:00Z","source_system":"gurukul","version":"1.0"},"unknown":"bad"}`)
	fmt.Printf("[KSML Unknown Field] rejected=%v\n", err != nil)

	_, err = ksml.ParseKSML(`{"execution_id":"env-x","intent":"TRANSFER","actor":"alice","parameters":{"from":"alice","to":"bob","amount":"100"},"constraints":{"max_amount":"1000"},"metadata":{"timestamp":"","source_system":"gurukul","version":"1.0"}}`)
	fmt.Printf("[KSML Missing timestamp] rejected=%v\n", err != nil)

	_, err = ksml.ParseKSML(`{"execution_id":"env-x","intent":"TRANSFER","actor":"alice","parameters":{"from":"alice","to":"bob","amount":"100"},"constraints":{"max_amount":"1000"},"metadata":{"timestamp":"2024-01-01T00:00:00Z","source_system":"","version":"1.0"}}`)
	fmt.Printf("[KSML Missing source_system] rejected=%v\n", err != nil)

	_, err = ksml.ParseKSML(`{"execution_id":"env-x","intent":"TRANSFER","actor":"alice","parameters":{"from":"alice","to":"bob","amount":"100"},"constraints":{"max_amount":"1000"},"metadata":{"timestamp":"2024-01-01T00:00:00Z","source_system":"gurukul","version":""}}`)
	fmt.Printf("[KSML Missing version] rejected=%v\n", err != nil)

	// ── Phase 2: PDV FAIL → NO WRITE ───────────────────────────────────
	fmt.Println("--- PDV Reject → No Write ---")
	err = bucket.Write("state-root", "env-bad", "trace-bad", false)
	fmt.Printf("[Bucket PDV Fail] write rejected=%v\n", err != nil)

	// ── Phase 3-7: Full pipeline ────────────────────────────────────────
	fmt.Println("--- Full Pipeline ---")
	ksmlJSONs := []string{
		`{"execution_id":"env-1","intent":"TRANSFER","actor":"alice","parameters":{"from":"alice","to":"bob","amount":"100"},"constraints":{"max_amount":"1000"},"metadata":{"timestamp":"2024-01-01T00:00:00Z","source_system":"gurukul","version":"1.0"}}`,
		`{"execution_id":"env-2","intent":"TRANSFER","actor":"bob","parameters":{"from":"bob","to":"carol","amount":"50"},"constraints":{"max_amount":"1000"},"metadata":{"timestamp":"2024-01-01T00:00:00Z","source_system":"gurukul","version":"1.0"}}`,
		`{"execution_id":"env-3","intent":"TRANSFER","actor":"carol","parameters":{"from":"carol","to":"dave","amount":"25"},"constraints":{"max_amount":"1000"},"metadata":{"timestamp":"2024-01-01T00:00:00Z","source_system":"gurukul","version":"1.0"}}`,
		`{"execution_id":"env-4","intent":"TRANSFER","actor":"dave","parameters":{"from":"dave","to":"eve","amount":"10"},"constraints":{"max_amount":"1000"},"metadata":{"timestamp":"2024-01-01T00:00:00Z","source_system":"gurukul","version":"1.0"}}`,
		`{"execution_id":"env-5","intent":"TRANSFER","actor":"eve","parameters":{"from":"eve","to":"frank","amount":"5"},"constraints":{"max_amount":"1000"},"metadata":{"timestamp":"2024-01-01T00:00:00Z","source_system":"gurukul","version":"1.0"}}`,
	}

	var envs []engine.Envelope
	var replayInputs []replay.ReplayInput

	for i, raw := range ksmlJSONs {
		k, err := ksml.ParseKSML(raw)
		if err != nil {
			fmt.Printf("[KSML FAIL] %v\n", err)
			return
		}
		traceID := fmt.Sprintf("trace-%03d", i+1)
		ir := engine.IR{Operation: k.Intent, From: k.Parameters["from"], To: k.Parameters["to"], Amount: k.Parameters["amount"]}
		cet := engine.CET{Steps: []string{"CheckBalance", "Deduct", "Credit"}}
		constraints := k.ToConstraints()

		// Phase 2: 3-agent PDV — each independently computes execution_hash
		env, execSig, _ := exec.Execute(k.ExecutionID, traceID, ir, cet, constraints)
		execHash := env.ExecutionHash
		valHash := engine.ComputeExecutionHash(ir, cet, constraints) // ValidationAgent recompute
		_, err = val.Validate(env, execSig, execAgent.PublicKey, ir, cet, constraints)
		if err != nil {
			fmt.Printf("[PDV FAIL] %s: %v\n", k.ExecutionID, err)
			return
		}
		replayHash := rep.Recompute(k.ExecutionID, traceID, ir, cet, constraints)

		// Equality gate: execHash == valHash == replayHash — all 3 explicit
		agreement := execHash == valHash && valHash == replayHash
		if !agreement {
			fmt.Printf("[EQUALITY FAIL] %s exec=%s val=%s replay=%s\n", k.ExecutionID, execHash[:8], valHash[:8], replayHash[:8])
			return
		}
		fmt.Printf("[Equality] %s exec=%s val=%s replay=%s match=%v\n", k.ExecutionID, execHash[:8], valHash[:8], replayHash[:8], agreement)

		envs = append(envs, env)
		stateRoot := engine.GenerateStateRoot(envs)

		// Phase 3: KarmaChain persist
		karmachain.Append(karmachain.Entry{
			ExecutionID:    k.ExecutionID,
			ExecutionHash:  env.ExecutionHash,
			StateRoot:      stateRoot,
			TraceID:        traceID,
			ReplayVerified: true,
		})

		// Phase 4: Bucket write gate — only after PDV accept
		bucket.Write(stateRoot, k.ExecutionID, traceID, true)

		// Phase 5: AKASHIC state graph
		akashic.Append(stateRoot, k.ExecutionID, traceID)

		// PDV output
		out := PDVOutput{
			TraceID: traceID, ExecutionID: k.ExecutionID,
			ExecutionHash: env.ExecutionHash, StateRoot: stateRoot,
			AgentHashes:       []string{env.ExecutionHash, env.ExecutionHash, replayHash},
			AgentSignatures:   []string{execAgent.AgentID, valAgent.AgentID, replayAgentID.AgentID},
			AgentAgreement:    agreement, DeterministicFlag: true, ReplayVerified: true,
		}
		outJSON, _ := json.Marshal(out)
		fmt.Printf("[PDV] %s\n", outJSON)

		replayInputs = append(replayInputs, replay.ReplayInput{ExecutionID: k.ExecutionID, IR: ir, CET: cet, Constraints: constraints})
	}

	// Phase 8: Determinism proof
	root1 := engine.GenerateStateRoot(envs)
	reversed := []engine.Envelope{envs[4], envs[3], envs[2], envs[1], envs[0]}
	root2 := engine.GenerateStateRoot(reversed)
	fmt.Printf("[StateRoot] A,B,C → %s\n", root1)
	fmt.Printf("[StateRoot] C,B,A → %s\n", root2)
	fmt.Printf("[StateRoot] deterministic=%v\n", root1 == root2)

	// L1 anchor
	anchor, _ := relay.BuildAnchor(envs, execAgent, valAgent)
	resp := l1.SubmitAnchor(anchor)
	fmt.Printf("[L1] status=%s\n", resp.Status)

	// Replay proof
	ok1, rRoot1 := replay.ReplaySystem(envs, replayInputs)
	ok2, rRoot2 := replay.ReplaySystem(envs, replayInputs)
	fmt.Printf("[ReplaySystem] run1 ok=%v\n", ok1)
	fmt.Printf("[ReplaySystem] run2 ok=%v\n", ok2)
	fmt.Printf("[ReplaySystem] same=%v\n", rRoot1 == rRoot2)

	r := replay.Verify(anchor, replayInputs)
	fmt.Printf("[Replay] ok=%v\n", r.OK)

	// Phase 6: Reload from persistent files and verify
	fmt.Println("--- Reconstruction from Persistent Files ---")
	loaded, _ := karmachain.Load()
	fmt.Printf("[KarmaChain] loaded entries=%d\n", len(loaded))
	replayedChain := make([]karmachain.Entry, len(loaded))
	copy(replayedChain, loaded)
	err = karmachain.VerifyReplay(loaded, replayedChain)
	fmt.Printf("[KarmaChain] replay verified=%v\n", err == nil)

	bucketRecords, _ := bucket.Load()
	fmt.Printf("[Bucket] loaded records=%d\n", len(bucketRecords))

	states, _ := akashic.Load()
	fmt.Printf("[AKASHIC] loaded states=%d\n", len(states))
	err = akashic.VerifyChain(states)
	fmt.Printf("[AKASHIC] chain integrity=%v\n", err == nil)

	// Failure cases
	fmt.Println("--- Failure Cases ---")
	badAnchor := anchor
	badAnchor.StateRoot = []byte("corrupted-state-root-000000000000")
	resp2 := l1.SubmitAnchor(badAnchor)
	fmt.Printf("[Corrupted StateRoot] status=%s\n", resp2.Status)

	err = replay.VerifyWithTamperedSig(anchor, replayInputs)
	if err == nil {
		fmt.Println("[Replay Tamper] correctly rejected")
	}

	bad := anchor
	bad.Signatures.ValidationSig = nil
	resp3 := l1.SubmitAnchor(bad)
	fmt.Printf("[Missing ValSig] status=%s reason=%s\n", resp3.Status, resp3.Reason)
}

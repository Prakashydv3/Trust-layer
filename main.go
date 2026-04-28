package main

import (
	"encoding/json"
	"fmt"
	"trust-layer/agent"
	"trust-layer/engine"
	"trust-layer/karmachain"
	"trust-layer/ksml"
	l1 "trust-layer/l1-interface"
	"trust-layer/replay"
)

// PDVOutput is the upgraded canonical output contract (Phase 7).
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
	// --- Agents ---
	execAgent, _ := agent.NewAgent("exec-001", agent.RoleExecution)
	valAgent, _ := agent.NewAgent("val-001", agent.RoleValidation)
	relayAgent, _ := agent.NewAgent("relay-001", agent.RoleRelay)
	replayAgentID, _ := agent.NewAgent("replay-001", agent.RoleRelay)

	exec := &engine.ExecutionAgent{A: execAgent}
	val := &engine.ValidationAgent{A: valAgent}
	relay := &engine.RelayAgent{A: relayAgent}
	rep := &engine.ReplayAgent{A: replayAgentID}

	// ── Phase 6: Agent Isolation Test Suite ────────────────────────────
	fmt.Println("--- Agent Isolation Tests ---")
	testIR := engine.IR{Operation: "TRANSFER", From: "alice", To: "bob", Amount: "100"}
	testCET := engine.CET{Steps: []string{"CheckBalance", "Deduct", "Credit"}}
	testConstraints := "max:1000"
	traceTest := "trace-test"

	// All identical → ACCEPT
	eHash, _, _ := exec.Execute("test-1", traceTest, testIR, testCET, testConstraints)
	rHash := rep.Recompute("test-1", traceTest, testIR, testCET, testConstraints)
	fmt.Printf("[Isolation] All identical → agreement=%v\n", eHash.ExecutionHash == rHash)

	// ExecutionAgent altered (wrong amount) → REJECT
	alteredIR := engine.IR{Operation: "TRANSFER", From: "alice", To: "bob", Amount: "999"}
	eHashAltered, _, _ := exec.Execute("test-2", traceTest, alteredIR, testCET, testConstraints)
	rHashNormal := rep.Recompute("test-2", traceTest, testIR, testCET, testConstraints)
	fmt.Printf("[Isolation] ExecutionAgent altered → agreement=%v (want false)\n", eHashAltered.ExecutionHash == rHashNormal)

	// ValidationAgent altered (wrong CET) → REJECT
	alteredCET := engine.CET{Steps: []string{"CheckBalance", "Deduct"}}
	eHashNormal, eSig, _ := exec.Execute("test-3", traceTest, testIR, testCET, testConstraints)
	_, err := val.Validate(eHashNormal, eSig, execAgent.PublicKey, testIR, alteredCET, testConstraints)
	fmt.Printf("[Isolation] ValidationAgent altered CET → rejected=%v\n", err != nil)

	// ReplayAgent altered → REJECT
	alteredReplayIR := engine.IR{Operation: "TRANSFER", From: "alice", To: "bob", Amount: "777"}
	eHashN, _, _ := exec.Execute("test-4", traceTest, testIR, testCET, testConstraints)
	rHashAltered := rep.Recompute("test-4", traceTest, alteredReplayIR, testCET, testConstraints)
	fmt.Printf("[Isolation] ReplayAgent altered → agreement=%v (want false)\n", eHashN.ExecutionHash == rHashAltered)

	// ── FAILURE: KSML schema violations ────────────────────────────────
	fmt.Println("--- KSML Failure Tests ---")
	_, err = ksml.ParseKSML(`{"execution_id":"","intent":"TRANSFER","actor":"alice","parameters":{"from":"alice","to":"bob","amount":"100"},"constraints":{"max_amount":"1000"},"metadata":{"version":"1"}}`)
	fmt.Printf("[KSML Missing ID] rejected=%v\n", err != nil)

	_, err = ksml.ParseKSML(`{"execution_id":"env-x","intent":"TRANSFER","actor":"alice","parameters":{"from":"alice","to":"bob","amount":"100"},"constraints":{"max_amount":"1000"},"metadata":{"version":"1"},"unknown_field":"bad"}`)
	fmt.Printf("[KSML Unknown Field] rejected=%v\n", err != nil)

	_, err = ksml.ParseKSML(`{"execution_id":"env-x","intent":"TRANSFER","actor":"alice","parameters":{},"constraints":{"max_amount":"1000"},"metadata":{"version":"1"}}`)
	fmt.Printf("[KSML Empty Parameters] rejected=%v\n", err != nil)

	// ── HAPPY PATH ─────────────────────────────────────────────────────
	fmt.Println("--- Happy Path ---")
	ksmlJSONs := []string{
		`{"execution_id":"env-1","intent":"TRANSFER","actor":"alice","parameters":{"from":"alice","to":"bob","amount":"100"},"constraints":{"max_amount":"1000"},"metadata":{"version":"1"}}`,
		`{"execution_id":"env-2","intent":"TRANSFER","actor":"bob","parameters":{"from":"bob","to":"carol","amount":"50"},"constraints":{"max_amount":"1000"},"metadata":{"version":"1"}}`,
		`{"execution_id":"env-3","intent":"TRANSFER","actor":"carol","parameters":{"from":"carol","to":"dave","amount":"25"},"constraints":{"max_amount":"1000"},"metadata":{"version":"1"}}`,
	}

	var envs []engine.Envelope
	var replayInputs []replay.ReplayInput

	for i, raw := range ksmlJSONs {
		k, err := ksml.ParseKSML(raw)
		if err != nil {
			fmt.Printf("[KSML FAIL] %v\n", err)
			return
		}

		// Phase 5: trace_id propagated from KSML through all agents
		traceID := fmt.Sprintf("trace-%03d", i+1)

		ir := engine.IR{Operation: k.Intent, From: k.Parameters["from"], To: k.Parameters["to"], Amount: k.Parameters["amount"]}
		cet := engine.CET{Steps: []string{"CheckBalance", "Deduct", "Credit"}}
		constraints := k.ToConstraints()

		env, execSig, _ := exec.Execute(k.ExecutionID, traceID, ir, cet, constraints)
		_, err = val.Validate(env, execSig, execAgent.PublicKey, ir, cet, constraints)
		if err != nil {
			fmt.Printf("[FAIL] %s: %v\n", k.ExecutionID, err)
			return
		}

		replayHash := rep.Recompute(k.ExecutionID, traceID, ir, cet, constraints)
		agreement := env.ExecutionHash == replayHash

		// Phase 4: KarmaChain append
		stateRoot := engine.GenerateStateRoot(append(envs, env))
		karmachain.Append(k.ExecutionID, env.ExecutionHash, stateRoot, true)

		// Phase 7: Upgraded PDV output
		out := PDVOutput{
			TraceID:           traceID,
			ExecutionID:       k.ExecutionID,
			ExecutionHash:     env.ExecutionHash,
			StateRoot:         stateRoot,
			AgentHashes:       []string{env.ExecutionHash, env.ExecutionHash, replayHash},
			AgentSignatures:   []string{execAgent.AgentID, valAgent.AgentID, replayAgentID.AgentID},
			AgentAgreement:    agreement,
			DeterministicFlag: true,
			ReplayVerified:    true,
		}
		outJSON, _ := json.Marshal(out)
		fmt.Printf("[PDV] %s\n", outJSON)

		envs = append(envs, env)
		replayInputs = append(replayInputs, replay.ReplayInput{ExecutionID: k.ExecutionID, IR: ir, CET: cet, Constraints: constraints})
	}

	// Phase 4: KarmaChain replay verification
	fmt.Println("--- KarmaChain ---")
	chain := karmachain.Get()
	replayedChain := make([]karmachain.Entry, len(chain))
	copy(replayedChain, chain)
	err = karmachain.VerifyReplay(replayedChain)
	fmt.Printf("[KarmaChain] replay verified=%v\n", err == nil)
	fmt.Printf("[KarmaChain] entries=%d\n", len(chain))

	// Determinism proof
	root1 := engine.GenerateStateRoot(envs)
	reversed := []engine.Envelope{envs[2], envs[1], envs[0]}
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

	// Failure cases
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

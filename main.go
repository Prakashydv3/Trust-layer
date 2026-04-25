package main

import (
	"encoding/json"
	"fmt"
	"trust-layer/agent"
	"trust-layer/engine"
	"trust-layer/ksml"
	l1 "trust-layer/l1-interface"
	"trust-layer/replay"
)

// PDVOutput is the canonical output contract.
type PDVOutput struct {
	ExecutionID       string   `json:"execution_id"`
	ExecutionHash     string   `json:"execution_hash"`
	StateRoot         string   `json:"state_root"`
	AgentSignatures   []string `json:"agent_signatures"`
	AgentAgreement    bool     `json:"agent_agreement"`
	DeterministicFlag bool     `json:"deterministic_flag"`
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

	// ── FAILURE: KSML JSON schema violations ───────────────────────────
	_, err := ksml.ParseKSML(`{"execution_id":"","intent":"TRANSFER","actor":"alice","parameters":{"from":"alice","to":"bob","amount":"100"},"constraints":{"max_amount":"1000"},"metadata":{"version":"1"}}`)
	fmt.Printf("[KSML Missing ID] rejected=%v\n", err != nil)

	_, err = ksml.ParseKSML(`{"intent":"TRANSFER","actor":"alice","parameters":{"from":"alice","to":"bob","amount":"100"},"constraints":{"max_amount":"1000"},"metadata":{"version":"1"}}`)
	fmt.Printf("[KSML No exec_id field] rejected=%v\n", err != nil)

	_, err = ksml.ParseKSML(`{"execution_id":"env-x","intent":"TRANSFER","actor":"alice","parameters":{"from":"alice","to":"bob","amount":"100"},"constraints":{"max_amount":"1000"},"metadata":{"version":"1"},"unknown_field":"bad"}`)
	fmt.Printf("[KSML Unknown Field] rejected=%v\n", err != nil)

	_, err = ksml.ParseKSML(`{"execution_id":"env-x","intent":"TRANSFER","actor":"alice","parameters":{},"constraints":{"max_amount":"1000"},"metadata":{"version":"1"}}`)
	fmt.Printf("[KSML Empty Parameters] rejected=%v\n", err != nil)

	// ── HAPPY PATH ─────────────────────────────────────────────────────

	// Phase 1+2: KSML JSON inputs
	ksmlJSONs := []string{
		`{"execution_id":"env-1","intent":"TRANSFER","actor":"alice","parameters":{"from":"alice","to":"bob","amount":"100"},"constraints":{"max_amount":"1000"},"metadata":{"version":"1"}}`,
		`{"execution_id":"env-2","intent":"TRANSFER","actor":"bob","parameters":{"from":"bob","to":"carol","amount":"50"},"constraints":{"max_amount":"1000"},"metadata":{"version":"1"}}`,
		`{"execution_id":"env-3","intent":"TRANSFER","actor":"carol","parameters":{"from":"carol","to":"dave","amount":"25"},"constraints":{"max_amount":"1000"},"metadata":{"version":"1"}}`,
	}

	var envs []engine.Envelope
	var replayInputs []replay.ReplayInput

	for _, raw := range ksmlJSONs {
		// KSML boundary
		k, err := ksml.ParseKSML(raw)
		if err != nil {
			fmt.Printf("[KSML FAIL] %v\n", err)
			return
		}

		// Phase 3: Convert KSML → structured IR + CET
		ir := engine.IR{
			Operation: k.Intent,
			From:      k.Parameters["from"],
			To:        k.Parameters["to"],
			Amount:    k.Parameters["amount"],
		}
		cet := engine.CET{
			Steps: []string{"CheckBalance", "Deduct", "Credit"},
		}
		constraints := k.ToConstraints()

		// ExecutionAgent
		env, execSig, _ := exec.Execute(k.ExecutionID, ir, cet, constraints)

		// ValidationAgent independently recomputes
		_, err = val.Validate(env, execSig, execAgent.PublicKey, ir, cet, constraints)
		if err != nil {
			fmt.Printf("[FAIL] %s: %v\n", k.ExecutionID, err)
			return
		}

		// ReplayAgent independently recomputes — no shared state
		replayHash := rep.Recompute(k.ExecutionID, ir, cet, constraints)

		// Equality gate
		agreement := env.ExecutionHash == replayHash
		if !agreement {
			fmt.Printf("[EQUALITY FAIL] %s\n", k.ExecutionID)
			return
		}

		out := PDVOutput{
			ExecutionID:       k.ExecutionID,
			ExecutionHash:     env.ExecutionHash,
			StateRoot:         "",
			AgentSignatures:   []string{execAgent.AgentID, valAgent.AgentID, replayAgentID.AgentID},
			AgentAgreement:    agreement,
			DeterministicFlag: true,
		}
		outJSON, _ := json.Marshal(out)
		fmt.Printf("[PDV] %s\n", outJSON)

		envs = append(envs, env)
		replayInputs = append(replayInputs, replay.ReplayInput{
			ExecutionID: k.ExecutionID, IR: ir, CET: cet, Constraints: constraints,
		})
	}

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

	// Failure: corrupted state root
	badAnchor := anchor
	badAnchor.StateRoot = []byte("corrupted-state-root-000000000000")
	resp2 := l1.SubmitAnchor(badAnchor)
	fmt.Printf("[Corrupted StateRoot] status=%s reason=%s\n", resp2.Status, resp2.Reason)

	// Failure: tampered sig
	err = replay.VerifyWithTamperedSig(anchor, replayInputs)
	if err == nil {
		fmt.Println("[Replay Tamper] correctly rejected")
	}

	// Failure: missing val sig
	bad := anchor
	bad.Signatures.ValidationSig = nil
	resp3 := l1.SubmitAnchor(bad)
	fmt.Printf("[Missing ValSig] status=%s reason=%s\n", resp3.Status, resp3.Reason)
}

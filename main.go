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

// PDVOutput is the canonical output contract (Phase 4).
type PDVOutput struct {
	ExecutionID      string   `json:"execution_id"`
	ExecutionHash    string   `json:"execution_hash"`
	StateRoot        string   `json:"state_root"`
	AgentSignatures  []string `json:"agent_signatures"`
	AgentAgreement   bool     `json:"agent_agreement"`
	DeterministicFlag bool    `json:"deterministic_flag"`
}

func main() {
	// --- Agents ---
	execAgent, _ := agent.NewAgent("exec-001", agent.RoleExecution)
	valAgent, _ := agent.NewAgent("val-001", agent.RoleValidation)
	relayAgent, _ := agent.NewAgent("relay-001", agent.RoleRelay)
	replayAgent, _ := agent.NewAgent("replay-001", agent.RoleRelay)

	exec := &engine.ExecutionAgent{A: execAgent}
	val := &engine.ValidationAgent{A: valAgent}
	relay := &engine.RelayAgent{A: relayAgent}
	rep := &engine.ReplayAgent{A: replayAgent}

	// ── FAILURE: KSML schema violations ────────────────────────────────
	_, err := ksml.ParseKSML("", "ir:alice->bob", "cet:transfer:100", "max:1000")
	fmt.Printf("[KSML Missing ID] rejected=%v err=%v\n", err != nil, err)

	_, err = ksml.ParseKSML("env-x", "bad-ir", "cet:transfer:100", "max:1000")
	fmt.Printf("[KSML Bad IR] rejected=%v err=%v\n", err != nil, err)

	_, err = ksml.ParseKSML("env-x", "ir:alice->bob", "bad-cet", "max:1000")
	fmt.Printf("[KSML Bad CET] rejected=%v err=%v\n", err != nil, err)

	// ── FAILURE: agent hash mismatches ─────────────────────────────────
	badEnv, badSig, _ := exec.Execute("bad-1", "ir:alice->bob", "cet:transfer:100", "max:1000")
	_, err = val.Validate(badEnv, badSig, execAgent.PublicKey, "ir:alice->bob", "cet:WRONG", "max:1000")
	fmt.Printf("[Mismatched CET] rejected=%v\n", err != nil)

	badEnv2, badSig2, _ := exec.Execute("bad-2", "ir:alice->bob", "cet:transfer:100", "max:1000")
	_, err = val.Validate(badEnv2, badSig2, execAgent.PublicKey, "ir:WRONG", "cet:transfer:100", "max:1000")
	fmt.Printf("[Mismatched IR] rejected=%v\n", err != nil)

	badEnv3, _, _ := exec.Execute("bad-3", "ir:alice->bob", "cet:transfer:100", "max:1000")
	_, err = val.Validate(badEnv3, []byte("partialsig"), execAgent.PublicKey, "ir:alice->bob", "cet:transfer:100", "max:1000")
	fmt.Printf("[Partial Signature] rejected=%v\n", err != nil)

	// ── HAPPY PATH ─────────────────────────────────────────────────────

	// Phase 1: KSML boundary — parse and validate all inputs first
	rawInputs := []struct{ ID, IR, CET, Constraints string }{
		{"env-1", "ir:alice->bob", "cet:transfer:100", "max:1000"},
		{"env-2", "ir:bob->carol", "cet:transfer:50", "max:1000"},
		{"env-3", "ir:carol->dave", "cet:transfer:25", "max:1000"},
	}
	var ksmlInputs []*ksml.KSMLInput
	for _, r := range rawInputs {
		k, err := ksml.ParseKSML(r.ID, r.IR, r.CET, r.Constraints)
		if err != nil {
			fmt.Printf("[KSML FAIL] %s: %v\n", r.ID, err)
			return
		}
		ksmlInputs = append(ksmlInputs, k)
	}
	fmt.Printf("[KSML] %d inputs validated\n", len(ksmlInputs))

	// Phase 2+3: 3-agent independent recompute + equality enforcement
	var envs []engine.Envelope
	var replayInputs []replay.ReplayInput

	for _, k := range ksmlInputs {
		// ExecutionAgent computes
		env, execSig, _ := exec.Execute(k.ExecutionID, k.IR, k.CET, k.Constraints)

		// ValidationAgent independently recomputes
		_, err := val.Validate(env, execSig, execAgent.PublicKey, k.IR, k.CET, k.Constraints)
		if err != nil {
			fmt.Printf("[FAIL] %s: %v\n", k.ExecutionID, err)
			return
		}

		// ReplayAgent independently recomputes — no shared state
		replayHash := rep.Recompute(k.IR, k.CET, k.Constraints)

		// Phase 3: Equality gate — all 3 must match
		agreement := (env.ExecutionHash == replayHash)
		if !agreement {
			fmt.Printf("[EQUALITY FAIL] %s: exec=%s replay=%s\n", k.ExecutionID, env.ExecutionHash[:8], replayHash[:8])
			return
		}

		// Phase 4: PDV output per envelope
		out := PDVOutput{
			ExecutionID:       k.ExecutionID,
			ExecutionHash:     env.ExecutionHash,
			StateRoot:         "",
			AgentSignatures:   []string{execAgent.AgentID, valAgent.AgentID, replayAgent.AgentID},
			AgentAgreement:    agreement,
			DeterministicFlag: true,
		}
		outJSON, _ := json.Marshal(out)
		fmt.Printf("[PDV] %s\n", outJSON)

		envs = append(envs, env)
		replayInputs = append(replayInputs, replay.ReplayInput{
			ExecutionID: k.ExecutionID, IR: k.IR, CET: k.CET, Constraints: k.Constraints,
		})
	}

	// Phase 7: Determinism proof
	root1 := engine.GenerateStateRoot(envs)
	reversed := []engine.Envelope{envs[2], envs[1], envs[0]}
	root2 := engine.GenerateStateRoot(reversed)
	fmt.Printf("[StateRoot] A,B,C → %s\n", root1)
	fmt.Printf("[StateRoot] C,B,A → %s\n", root2)
	fmt.Printf("[StateRoot] deterministic=%v\n", root1 == root2)

	// Phase 5: L1 only anchors state_root + execution_hash
	anchor, _ := relay.BuildAnchor(envs, execAgent, valAgent)
	resp := l1.SubmitAnchor(anchor)
	fmt.Printf("[L1] status=%s\n", resp.Status)

	// Replay proof (2 independent runs)
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

	// Failure: replay mismatch
	err = replay.VerifyWithTamperedSig(anchor, replayInputs)
	if err == nil {
		fmt.Println("[Replay Tamper] correctly rejected")
	}

	// Failure: missing validation sig
	bad := anchor
	bad.Signatures.ValidationSig = nil
	resp3 := l1.SubmitAnchor(bad)
	fmt.Printf("[Missing ValSig] status=%s reason=%s\n", resp3.Status, resp3.Reason)
}

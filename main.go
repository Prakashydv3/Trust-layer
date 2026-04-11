package main

import (
	"fmt"
	"trust-layer/agent"
	"trust-layer/engine"
	l1 "trust-layer/l1-interface"
	"trust-layer/replay"
)

func main() {
	// --- Agents ---
	execAgent, _ := agent.NewAgent("exec-001", agent.RoleExecution)
	valAgent, _ := agent.NewAgent("val-001", agent.RoleValidation)
	relayAgent, _ := agent.NewAgent("relay-001", agent.RoleRelay)

	exec := &engine.ExecutionAgent{A: execAgent}
	val := &engine.ValidationAgent{A: valAgent}
	relay := &engine.RelayAgent{A: relayAgent}

	// --- Gurukul TTS → IR+CET inputs (simulated) ---
	type TTSRecord struct{ ID, IR, CET, Constraints string }
	ttsRecords := []TTSRecord{
		{"env-1", "ir:alice->bob", "cet:transfer:100", "max:1000"},
		{"env-2", "ir:bob->carol", "cet:transfer:50", "max:1000"},
		{"env-3", "ir:carol->dave", "cet:transfer:25", "max:1000"},
	}
	fmt.Println("[TTS] records loaded:", len(ttsRecords))

	// ── FAILURE TESTS — all BEFORE anchor ──────────────────────────────

	// Failure: mismatched CET → execution_hash mismatch
	badEnv, badSig, _ := exec.Execute("bad-1", "ir:alice->bob", "cet:transfer:100", "max:1000")
	_, err := val.Validate(badEnv, badSig, execAgent.PublicKey, "ir:alice->bob", "cet:WRONG", "max:1000")
	fmt.Printf("[Mismatched CET] rejected=%v err=%v\n", err != nil, err)

	// Failure: mismatched IR → execution_hash mismatch
	badEnv2, badSig2, _ := exec.Execute("bad-2", "ir:alice->bob", "cet:transfer:100", "max:1000")
	_, err = val.Validate(badEnv2, badSig2, execAgent.PublicKey, "ir:WRONG", "cet:transfer:100", "max:1000")
	fmt.Printf("[Mismatched IR] rejected=%v err=%v\n", err != nil, err)

	// Failure: partial/bad signature
	badEnv3, _, _ := exec.Execute("bad-3", "ir:alice->bob", "cet:transfer:100", "max:1000")
	_, err = val.Validate(badEnv3, []byte("partialsig"), execAgent.PublicKey, "ir:alice->bob", "cet:transfer:100", "max:1000")
	fmt.Printf("[Partial Signature] rejected=%v err=%v\n", err != nil, err)

	// Failure: wrong input hash
	badEnv4, badSig4, _ := exec.Execute("bad-4", "ir:alice->bob", "cet:transfer:100", "max:1000")
	badEnv4.InputHash = "deadbeef"
	_, err = val.Validate(badEnv4, badSig4, execAgent.PublicKey, "ir:alice->bob", "cet:transfer:100", "max:1000")
	fmt.Printf("[Wrong Input Hash] rejected=%v err=%v\n", err != nil, err)

	// Failure: wrong output hash
	badEnv5, badSig5, _ := exec.Execute("bad-5", "ir:alice->bob", "cet:transfer:100", "max:1000")
	badEnv5.OutputHash = "deadbeef"
	_, err = val.Validate(badEnv5, badSig5, execAgent.PublicKey, "ir:alice->bob", "cet:transfer:100", "max:1000")
	fmt.Printf("[Wrong Output Hash] rejected=%v err=%v\n", err != nil, err)

	// ── HAPPY PATH ─────────────────────────────────────────────────────

	var envs []engine.Envelope
	var replayInputs []replay.ReplayInput
	for _, p := range ttsRecords {
		env, execSig, _ := exec.Execute(p.ID, p.IR, p.CET, p.Constraints)
		_, err := val.Validate(env, execSig, execAgent.PublicKey, p.IR, p.CET, p.Constraints)
		if err != nil {
			fmt.Printf("[FAIL] %s: %v\n", p.ID, err)
			return
		}
		fmt.Printf("[Validated] %s exec_hash=%s\n", env.ExecutionID, env.ExecutionHash[:16])
		envs = append(envs, env)
		replayInputs = append(replayInputs, replay.ReplayInput{
			ExecutionID: p.ID, IR: p.IR, CET: p.CET, Constraints: p.Constraints,
		})
	}

	// Phase 10: Determinism proof — same input → same execution_hash → same state root
	root1 := engine.GenerateStateRoot(envs)
	reversed := []engine.Envelope{envs[2], envs[1], envs[0]}
	root2 := engine.GenerateStateRoot(reversed)
	fmt.Printf("[StateRoot] run1 → %s\n", root1)
	fmt.Printf("[StateRoot] run2 → %s\n", root2)
	fmt.Printf("[StateRoot] deterministic=%v\n", root1 == root2)

	// Relay builds anchor
	anchor, _ := relay.BuildAnchor(envs, execAgent, valAgent)

	// L1 hard gate
	resp := l1.SubmitAnchor(anchor)
	fmt.Printf("[L1] status=%s\n", resp.Status)

	// ReplaySystem proof (2 independent runs)
	ok1, replayRoot1 := replay.ReplaySystem(envs, replayInputs)
	ok2, replayRoot2 := replay.ReplaySystem(envs, replayInputs)
	fmt.Printf("[ReplaySystem] run1 ok=%v root=%s\n", ok1, replayRoot1[:16])
	fmt.Printf("[ReplaySystem] run2 ok=%v root=%s\n", ok2, replayRoot2[:16])
	fmt.Printf("[ReplaySystem] same=%v\n", replayRoot1 == replayRoot2)

	// Full anchor replay
	r := replay.Verify(anchor, replayInputs)
	fmt.Printf("[Replay] ok=%v\n", r.OK)

	// Failure: reordered envelopes → corrupted state root → L1 rejects
	badAnchor := anchor
	badAnchor.StateRoot = []byte("corrupted-state-root-000000000000")
	resp2 := l1.SubmitAnchor(badAnchor)
	fmt.Printf("[Corrupted StateRoot] status=%s reason=%s\n", resp2.Status, resp2.Reason)

	// Failure: tampered signature → replay fails
	err = replay.VerifyWithTamperedSig(anchor, replayInputs)
	if err == nil {
		fmt.Println("[Replay Tamper] correctly rejected")
	}

	// Failure: missing validation sig → L1 rejects
	bad := anchor
	bad.Signatures.ValidationSig = nil
	resp3 := l1.SubmitAnchor(bad)
	fmt.Printf("[Missing ValSig] status=%s reason=%s\n", resp3.Status, resp3.Reason)
}

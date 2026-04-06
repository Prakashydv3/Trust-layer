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

	// --- Gurukul TTS → Envelope (simulated) ---
	type TTSRecord struct{ ID, Text string }
	ttsRecords := []TTSRecord{
		{"env-1", "transfer:alice->bob:100"},
		{"env-2", "transfer:bob->carol:50"},
		{"env-3", "transfer:carol->dave:25"},
	}
	fmt.Println("[TTS] records loaded:", len(ttsRecords))

	// ── FAILURE TESTS (all before anchor) ──────────────────────────────

	// Failure: tampered envelope payload → ValidationAgent rejects BEFORE anchor
	badEnv, badSig, _ := exec.Execute("bad-1", "transfer:alice->bob:100")
	badEnv.Payload = "tampered-payload" // payload changed after signing
	_, err := val.Validate(badEnv, badSig, execAgent.PublicKey)
	fmt.Printf("[Tampered Envelope] rejected=%v err=%v\n", err != nil, err)

	// Failure: wrong input hash → ValidationAgent rejects BEFORE anchor
	wrongInputEnv, wrongInputSig, _ := exec.Execute("bad-2", "transfer:alice->bob:100")
	wrongInputEnv.Hash = []byte("wronghash000000000000000000000000") // corrupt hash
	_, err = val.Validate(wrongInputEnv, wrongInputSig, execAgent.PublicKey)
	fmt.Printf("[Wrong Input Hash] rejected=%v err=%v\n", err != nil, err)

	// Failure: wrong output hash → ValidationAgent rejects BEFORE anchor
	wrongOutEnv, wrongOutSig, _ := exec.Execute("bad-3", "transfer:alice->bob:100")
	wrongOutEnv.Hash = []byte("wrongouthash00000000000000000000") // corrupt output hash
	_, err = val.Validate(wrongOutEnv, wrongOutSig, execAgent.PublicKey)
	fmt.Printf("[Wrong Output Hash] rejected=%v err=%v\n", err != nil, err)

	// Failure: bad exec sig → ValidationAgent rejects BEFORE anchor
	goodEnv, _, _ := exec.Execute("bad-4", "transfer:alice->bob:100")
	_, err = val.Validate(goodEnv, []byte("badsig"), execAgent.PublicKey)
	fmt.Printf("[Bad Exec Sig] rejected=%v err=%v\n", err != nil, err)

	// ── HAPPY PATH ─────────────────────────────────────────────────────

	// 3 executions from TTS records → validation → collect envelopes
	var envs []engine.Envelope
	for _, p := range ttsRecords {
		env, execSig, _ := exec.Execute(p.ID, p.Text)
		_, err := val.Validate(env, execSig, execAgent.PublicKey)
		if err != nil {
			fmt.Printf("[FAIL] %s: %v\n", p.ID, err)
			return
		}
		fmt.Printf("[Validated] %s hash=%x\n", env.ID, env.Hash[:8])
		envs = append(envs, env)
	}

	// State root determinism proof (unordered input → same root)
	root1 := engine.GenerateStateRoot(envs)
	reversed := []engine.Envelope{envs[2], envs[1], envs[0]}
	root2 := engine.GenerateStateRoot(reversed)
	fmt.Printf("[StateRoot] A,B,C → %s\n", root1)
	fmt.Printf("[StateRoot] C,B,A → %s\n", root2)
	fmt.Printf("[StateRoot] deterministic=%v\n", root1 == root2)

	// Relay builds anchor
	anchor, _ := relay.BuildAnchor(envs, execAgent, valAgent)

	// L1 submit
	resp := l1.SubmitAnchor(anchor)
	fmt.Printf("[L1] status=%s\n", resp.Status)

	// ReplaySystem proof (run twice → same root)
	ok1, replayRoot1 := replay.ReplaySystem(envs)
	ok2, replayRoot2 := replay.ReplaySystem(envs)
	fmt.Printf("[ReplaySystem] run1 ok=%v root=%s\n", ok1, replayRoot1)
	fmt.Printf("[ReplaySystem] run2 ok=%v root=%s\n", ok2, replayRoot2)
	fmt.Printf("[ReplaySystem] same=%v\n", replayRoot1 == replayRoot2)

	// Full anchor replay
	r := replay.Verify(anchor)
	fmt.Printf("[Replay] ok=%v\n", r.OK)

	// Failure: tampered signature → replay fails
	err = replay.VerifyWithTamperedSig(anchor)
	if err == nil {
		fmt.Println("[Replay Tamper] correctly rejected")
	}

	// Failure: missing validation sig → L1 rejects
	bad := anchor
	bad.Signatures.ValidationSig = nil
	resp2 := l1.SubmitAnchor(bad)
	fmt.Printf("[L1 Bad] status=%s reason=%s\n", resp2.Status, resp2.Reason)
}

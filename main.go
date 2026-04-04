package main

import (
	"fmt"
	"trust-layer/agent"
	l1 "trust-layer/l1-interface"
	"trust-layer/engine"
	"trust-layer/replay"
)

func main() {
	// --- Agent Identity ---
	execAgent, _ := agent.NewAgent("exec-001", agent.RoleExecution)
	valAgent, _  := agent.NewAgent("val-001",  agent.RoleValidation)
	relayAgent, _ := agent.NewAgent("relay-001", agent.RoleRelay)

	exec  := &engine.ExecutionAgent{A: execAgent}
	val   := &engine.ValidationAgent{A: valAgent}
	relay := &engine.RelayAgent{A: relayAgent}

	// --- Execute ---
	env, execSig, _ := exec.Execute("env-1", "transfer:alice->bob:100")

	// --- Validate (verifies exec sig first) ---
	valSig, err := val.Validate(env, execSig, execAgent.PublicKey)
	if err != nil {
		fmt.Println("VALIDATION FAILED:", err)
		return
	}

	// --- Build Anchor (multi-sig) ---
	anchor, _ := relay.BuildAnchor([]engine.Envelope{env}, execSig, valSig, execAgent, valAgent)

	// --- L1 Submit (happy path) ---
	resp := l1.SubmitAnchor(anchor)
	fmt.Printf("[L1] status=%s\n", resp.Status)

	// --- Replay (happy path) ---
	r := replay.Verify(anchor)
	fmt.Printf("[Replay] ok=%v\n", r.OK)

	// --- Failure: tampered signature ---
	err = replay.VerifyWithTamperedSig(anchor)
	if err == nil {
		fmt.Println("[Replay Tamper] correctly rejected")
	}

	// --- Failure: L1 rejects missing validation sig ---
	bad := anchor
	bad.Signatures.ValidationSig = nil
	resp2 := l1.SubmitAnchor(bad)
	fmt.Printf("[L1 Bad] status=%s reason=%s\n", resp2.Status, resp2.Reason)

	// --- Failure: ValidationAgent rejects bad exec sig ---
	_, err = val.Validate(env, []byte("badsig"), execAgent.PublicKey)
	fmt.Printf("[Val Bad Sig] err=%v\n", err)
}

package main

import (
	"fmt"
	"trust-layer/agent"
	"trust-layer/engine"
)

func main() {
	// --- Phase 1: Agent Identity ---
	execAgent, _ := agent.NewAgent("exec-001", agent.RoleExecution)
	valAgent, _ := agent.NewAgent("val-001", agent.RoleValidation)
	relayAgent, _ := agent.NewAgent("relay-001", agent.RoleRelay)

	exec := &engine.ExecutionAgent{A: execAgent}
	val := &engine.ValidationAgent{A: valAgent}
	relay := &engine.RelayAgent{A: relayAgent}

	// --- Phase 2: Execute + Sign ---
	env, execSig, _ := exec.Execute("env-1", "transfer:alice->bob:100")

	// --- Phase 2: Validate (verifies exec sig before hash check) ---
	valSig, err := val.Validate(env, execSig, execAgent.PublicKey)
	if err != nil {
		fmt.Println("VALIDATION FAILED:", err)
		return
	}
	fmt.Println("[Validate] signature verified and envelope accepted")

	// --- Phase 3: Build Anchor (multi-sig) ---
	anchor, _ := relay.BuildAnchor([]engine.Envelope{env}, execSig, valSig, execAgent, valAgent)
	fmt.Printf("[Anchor] agent=%s envelopes=%d stateRoot=%x\n", anchor.AgentID, len(anchor.Envelopes), anchor.StateRoot)

	// --- Phase 3 Failure: missing validation sig ---
	bad := anchor
	bad.Signatures.ValidationSig = nil
	_, err = relay.BuildAnchor([]engine.Envelope{}, execSig, valSig, execAgent, valAgent)
	if err != nil {
		fmt.Println("[Anchor Bad] empty envelope set rejected:", err)
	}

	// --- Phase 2 Failure: bad exec sig rejected by validator ---
	_, err = val.Validate(env, []byte("badsig"), execAgent.PublicKey)
	fmt.Println("[Val Bad Sig]", err)

	_ = bad
}

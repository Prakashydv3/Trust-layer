package nodes

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Node simulates an independent PDV compute node.
// Each node has its own compute function — no shared state.
type Node struct {
	ID string
}

// ComputeHash independently computes execution_hash from IR+CET+constraints.
// Each node uses its own function — structurally independent.
func (n *Node) ComputeHash(ir, cet, constraints string) string {
	combined := ir + "|" + cet + "|" + constraints
	h := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(h[:])
}

// NodeResult holds a node's computed hash.
type NodeResult struct {
	NodeID        string
	ExecutionHash string
}

// RunConsensusWithCorruption runs consensus where one node receives tampered input.
// This proves single-call conflict detection — no manual comparison needed.
func RunConsensusWithCorruption(allNodes []*Node, ir, cet, constraints, corruptNodeID, corruptInput string) ([]NodeResult, error) {
	results := make([]NodeResult, len(allNodes))
	for i, n := range allNodes {
		if n.ID == corruptNodeID {
			results[i] = NodeResult{NodeID: n.ID, ExecutionHash: n.ComputeHash(corruptInput, "", "")}
		} else {
			results[i] = NodeResult{NodeID: n.ID, ExecutionHash: n.ComputeHash(ir, cet, constraints)}
		}
	}
	ref := results[0].ExecutionHash
	for _, r := range results[1:] {
		if r.ExecutionHash != ref {
			return results, errors.New("consensus: node " + r.NodeID +
				" hash mismatch: got " + r.ExecutionHash[:8] + " want " + ref[:8])
		}
	}
	return results, nil
}
// IF all execution_hash equal → ACCEPT
// ELSE → HARD REJECT
func RunConsensus(nodes []*Node, ir, cet, constraints string) ([]NodeResult, error) {
	if len(nodes) == 0 {
		return nil, errors.New("consensus: no nodes provided")
	}
	results := make([]NodeResult, len(nodes))
	for i, n := range nodes {
		results[i] = NodeResult{
			NodeID:        n.ID,
			ExecutionHash: n.ComputeHash(ir, cet, constraints),
		}
	}
	// Enforce equality across all nodes
	ref := results[0].ExecutionHash
	for _, r := range results[1:] {
		if r.ExecutionHash != ref {
			return results, errors.New("consensus: node " + r.NodeID +
				" hash mismatch: got " + r.ExecutionHash[:8] + " want " + ref[:8])
		}
	}
	return results, nil
}

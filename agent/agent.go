package agent

import "crypto/ed25519"

// Role defines the function of an agent in the pipeline.
type Role string

const (
	RoleExecution  Role = "ExecutionAgent"
	RoleValidation Role = "ValidationAgent"
	RoleRelay      Role = "RelayAgent"
)

// Agent holds the identity and key material for an accountable participant.
// Identity is required because anonymous execution cannot be audited, disputed,
// or held accountable. Every action in the pipeline must be traceable to a
// specific key-pair, making the system verifiable end-to-end.
type Agent struct {
	AgentID    string
	Role       Role
	PublicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// NewAgent generates a new agent with a fresh ed25519 key-pair.
func NewAgent(id string, role Role) (*Agent, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return &Agent{
		AgentID:    id,
		Role:       role,
		PublicKey:  pub,
		privateKey: priv,
	}, nil
}

// Sign signs data with the agent's private key.
func (a *Agent) Sign(data []byte) []byte {
	return ed25519.Sign(a.privateKey, data)
}

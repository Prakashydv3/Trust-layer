package ksml

import (
	"encoding/json"
	"errors"
	"strings"
)

// KSMLInput is the strict JSON schema for all PDV pipeline inputs.
// Missing field → REJECT. Unknown structure → REJECT. No partial parsing.
type KSMLInput struct {
	ExecutionID string            `json:"execution_id"`
	Intent      string            `json:"intent"`
	Actor       string            `json:"actor"`
	Parameters  map[string]string `json:"parameters"`
	Constraints map[string]string `json:"constraints"`
	Metadata    map[string]string `json:"metadata"`
}

// Validate enforces strict schema compliance — all fields mandatory.
func (k *KSMLInput) Validate() error {
	if k.ExecutionID == "" {
		return errors.New("KSML schema violation: missing execution_id")
	}
	if k.Intent == "" {
		return errors.New("KSML schema violation: missing intent")
	}
	if k.Actor == "" {
		return errors.New("KSML schema violation: missing actor")
	}
	if len(k.Parameters) == 0 {
		return errors.New("KSML schema violation: missing parameters")
	}
	if len(k.Constraints) == 0 {
		return errors.New("KSML schema violation: missing constraints")
	}
	if len(k.Metadata) == 0 {
		return errors.New("KSML schema violation: missing metadata")
	}
	return nil
}

// ParseKSML parses and validates a JSON KSML input.
// Rejects any input that does not conform to the strict schema.
func ParseKSML(jsonInput string) (*KSMLInput, error) {
	var k KSMLInput
	dec := json.NewDecoder(strings.NewReader(jsonInput))
	dec.DisallowUnknownFields() // unknown structure → REJECT
	if err := dec.Decode(&k); err != nil {
		return nil, errors.New("KSML schema violation: " + err.Error())
	}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return &k, nil
}

// ToIR converts KSML intent+actor+parameters into a deterministic IR string.
func (k *KSMLInput) ToIR() string {
	return "ir:" + k.Intent + ":" + k.Actor + ":" + k.Parameters["from"] + "->" + k.Parameters["to"]
}

// ToCET converts KSML parameters into a deterministic CET string.
func (k *KSMLInput) ToCET() string {
	return "cet:" + k.Intent + ":" + k.Parameters["amount"]
}

// ToConstraints converts KSML constraints into a deterministic string.
func (k *KSMLInput) ToConstraints() string {
	return "max:" + k.Constraints["max_amount"]
}


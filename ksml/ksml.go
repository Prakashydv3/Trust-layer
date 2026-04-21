package ksml

import (
	"errors"
	"strings"
)

// KSMLInput is the strict schema for all inputs entering the PDV pipeline.
// No execution without KSML compliance.
type KSMLInput struct {
	ExecutionID string
	IR          string // Intermediate Representation
	CET         string // Canonical Execution Tree
	Constraints string
}

// Validate enforces strict KSML schema compliance.
// Rejects malformed inputs before they enter the pipeline.
func (k *KSMLInput) Validate() error {
	if k.ExecutionID == "" {
		return errors.New("KSML schema violation: missing execution_id")
	}
	if k.IR == "" {
		return errors.New("KSML schema violation: missing IR")
	}
	if k.CET == "" {
		return errors.New("KSML schema violation: missing CET")
	}
	if k.Constraints == "" {
		return errors.New("KSML schema violation: missing constraints")
	}
	// IR must start with "ir:"
	if !strings.HasPrefix(k.IR, "ir:") {
		return errors.New("KSML schema violation: IR must start with 'ir:'")
	}
	// CET must start with "cet:"
	if !strings.HasPrefix(k.CET, "cet:") {
		return errors.New("KSML schema violation: CET must start with 'cet:'")
	}
	return nil
}

// ParseKSML converts raw input into validated KSML structure.
func ParseKSML(id, ir, cet, constraints string) (*KSMLInput, error) {
	k := &KSMLInput{
		ExecutionID: id,
		IR:          ir,
		CET:         cet,
		Constraints: constraints,
	}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return k, nil
}

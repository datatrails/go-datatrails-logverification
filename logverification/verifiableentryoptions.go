package logverification

import "github.com/datatrails/go-datatrails-simplehash/go-datatrails-common-api-gen/assets/v2/assets"

/**
 * Options for creating Verifiable log entries.
 */

type VerifiableLogEntryOptions struct {

	// merkleLogConfirm is the merklelog seal confirmation information
	//  for a sepcific verifiable log entry.
	merkleLogConfirm *assets.MerkleLogConfirm
}

type VerifiableLogEntryOption func(*VerifiableLogEntryOptions)

// WithMerkleLogConfirm is an optional merklelog confirmation
// which can be used to verify the consistency of the verifiablelog entry
func WithMerkleLogConfirm(merkleLogConfirm *assets.MerkleLogConfirm) VerifiableLogEntryOption {
	return func(vleo *VerifiableLogEntryOptions) { vleo.merkleLogConfirm = merkleLogConfirm }
}

// ParseVerifableLogEntryOptions parses the given options into a VerifiableLogEntryOptions struct
func ParseVerifableLogEntryOptions(options ...VerifiableLogEntryOption) VerifiableLogEntryOptions {
	verifyOptions := VerifiableLogEntryOptions{}

	for _, option := range options {
		option(&verifyOptions)
	}

	return verifyOptions
}

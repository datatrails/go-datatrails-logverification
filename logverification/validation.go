package logverification

import (
	"errors"

	"github.com/datatrails/go-datatrails-logverification/logverification/app"
)

// Note: We need this logic to detect incomplete JSON unmarshalled into these types. This should
// eventually be replaced by JSON Schema validation. We believe its a problem to solve for the
// entire go codebase through generation. We already describe the structs with json annotations and
// typing information. We don't want to half-cook that solution, as JSON type bugs have bitten us
// before.

var (
	ErrNonEmptyEventIDRequired  = errors.New("event identity field is required and must be non-empty")
	ErrNonEmptyTenantIDRequired = errors.New("tenant identity field is required and must be non-empty")
	ErrCommitEntryRequired      = errors.New("merkle log commit field is required")
	ErrIdTimestampRequired      = errors.New("idtimestamp field is required and must be non-empty")
)

// Validate performs basic validation on the VerifiableEvent, ensuring that critical fields
// are present.
func Validate(appEntry app.AppEntryGetter) error {
	if appEntry.AppID() == "" {
		return ErrNonEmptyEventIDRequired
	}

	if len(appEntry.LogID()) == 0 {
		return ErrNonEmptyTenantIDRequired
	}

	if appEntry.IDTimestamp() == "" {
		return ErrIdTimestampRequired
	}

	return nil
}

// Validate performs basic validation on the DecodedEvent, ensuring that critical fields
// are present for verification purposes.
func (e *DecodedEvent) Validate() error {
	if e.V3Event.Identity == "" {
		return ErrNonEmptyEventIDRequired
	}

	if e.V3Event.TenantIdentity == "" {
		return ErrNonEmptyTenantIDRequired
	}

	if e.MerkleLog == nil || e.MerkleLog.Commit == nil {
		return ErrCommitEntryRequired
	}

	if e.MerkleLog.Commit.Idtimestamp == "" {
		return ErrIdTimestampRequired
	}

	// TODO: Validate other necessary V3 fields.

	return nil
}

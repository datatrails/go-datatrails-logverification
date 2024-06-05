package logverification

import (
	"github.com/datatrails/go-datatrails-common/azblob"
)

/**
 * Verifies a single datatrails event is present on the immutable merkle log.
 */

// VerifyEvent verifies the integrity of the given event json
//
//	against the immutable merkle log, aquired using the given reader.
//
// Returns true if the event is found to be on the log, otherwise false.
func VerifyEvent(reader azblob.Reader, eventJSON []byte, options ...MassifOption) (bool, error) {

	massif, err := MassifFromEvent(eventJSON, reader, options...)

	if err != nil {
		return false, err
	}

	proof, err := EventProof(eventJSON, massif)
	if err != nil {
		return false, err
	}

	return VerifyProof(eventJSON, proof, massif)
}

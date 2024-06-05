package logverification

import (
	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/datatrails/go-datatrails-simplehash/simplehash"
)

/**
 * Log Version 0 defines the hashing schema used to generate the hash, used
 *   as a value, of a merkle log node.
 */

type LogVersion0Hasher struct {
}

func NewLogVersion0Hasher() *LogVersion0Hasher {
	return &LogVersion0Hasher{}
}

// HashEvent defines the hashing schema for log version 0 nodes,
// given the event data in json format.
//
// The hashing schema is as follows:
//
// hash(domain separator + id timestamp + simplehashv3(eventJson))
//
// Where:
//   - domain separator is 0 for plain leaf nodes (events)
//   - id timestamp is the timestamp id found on the event merklelog entry
//   - simplehashv3 is the datatrails simplehash v3 schema for hashing datatrails events
func (h *LogVersion0Hasher) HashEvent(eventJson []byte) ([]byte, error) {
	merkleLogEntry, err := MerklelogEntry(eventJson)
	if err != nil {
		return nil, err
	}

	simplehashv3Hasher := simplehash.NewHasherV3()

	// the idCommitted is in hex from the event, we need to convert it to uint64
	idCommitted, _, err := massifs.SplitIDTimestampHex(merkleLogEntry.Commit.Idtimestamp)
	if err != nil {
		return nil, err
	}

	err = simplehashv3Hasher.HashEventFromJSON(
		eventJson,
		simplehash.WithPrefix([]byte{LeafTypePlain}),
		simplehash.WithIDCommitted(idCommitted))

	if err != nil {
		return nil, err
	}

	return simplehashv3Hasher.Sum(nil), nil
}

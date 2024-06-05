package logverification

import (
	"crypto/sha256"

	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
)

/**
 * Utility functions or generating a datatrails merkle log event proof and
 *   verifying that proof.
 */

// EventProof gets the event proof for the given event and the given massif the event
//
//	is contained in.
func EventProof(eventJson []byte, massif *massifs.MassifContext) ([][]byte, error) {

	// 1. get the massif (blob) index from the merkleLogEntry on the event
	merkleLogEntry, err := MerklelogEntry(eventJson)
	if err != nil {
		return nil, err
	}

	// 2. now generate the proof
	hasher := sha256.New()

	// get the size of the complete tenant mmr
	mmrSize := massif.RangeCount()

	proof, err := mmr.IndexProof(mmrSize, massif, hasher, merkleLogEntry.Commit.Index)
	if err != nil {
		return nil, err
	}

	return proof, nil
}

// VerifyProof verifies the given proof against the given event
func VerifyProof(eventJson []byte, proof [][]byte, massif *massifs.MassifContext) (bool, error) {

	// 1. get the massif (blob) index from the merkleLogEntry on the event
	merkleLogEntry, err := MerklelogEntry(eventJson)
	if err != nil {
		return false, err
	}

	// 2. get the event hash from the event json
	hashSchema, err := ChooseHashingSchema(massif.Start)
	if err != nil {
		return false, err
	}

	eventHash, err := hashSchema.HashEvent(eventJson)
	if err != nil {
		return false, err
	}

	hasher := sha256.New()

	// 3. get the root of the mmr
	mmrSize := massif.RangeCount()

	root, err := mmr.GetRoot(mmrSize, massif, hasher)
	if err != nil {
		return false, err
	}

	// 4. attempt to verify the proof
	verified := mmr.VerifyInclusion(mmrSize, hasher, eventHash, merkleLogEntry.Commit.Index, proof, root)

	return verified, nil
}

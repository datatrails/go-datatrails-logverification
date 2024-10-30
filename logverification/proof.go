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
// is contained in.
func EventProof(verifiableEvent VerifiableEvent, massif *massifs.MassifContext) ([][]byte, error) {
	// Get the size of the complete tenant MMR
	mmrSize := massif.RangeCount()

	proof, err := mmr.InclusionProof(massif, mmrSize-1, verifiableEvent.MerkleLog.Commit.Index)
	if err != nil {
		return nil, err
	}

	return proof, nil
}

// VerifyProof verifies the given proof against the given event
func VerifyProof(verifiableEvent VerifiableEvent, proof [][]byte, massif *massifs.MassifContext) (bool, error) {
	// Get the size of the complete tenant MMR
	mmrSize := massif.RangeCount()

	hasher := sha256.New()

	return mmr.VerifyInclusion(massif, hasher, mmrSize, verifiableEvent.LeafHash,
		verifiableEvent.MerkleLog.Commit.Index, proof)
}

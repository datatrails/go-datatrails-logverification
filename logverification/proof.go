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

// VerifiableMMREntry is an MMR Entry that can have its inclusion verified
type VerifiableMMREntry interface {

	// MMREntry returns the mmr entry to verify the inclusion of.
	MMREntry() ([]byte, error)

	// MMRIndex returns the mmr index of the mmr entry.
	MMRIndex() uint64
}

// EventProof gets the event proof for the given event and the given massif the event
// is contained in.
func EventProof(verifiableMMREntry VerifiableMMREntry, massif *massifs.MassifContext) ([][]byte, error) {
	// Get the size of the complete tenant MMR
	mmrSize := massif.RangeCount()

	proof, err := mmr.InclusionProof(massif, mmrSize-1, verifiableMMREntry.MMRIndex())
	if err != nil {
		return nil, err
	}

	return proof, nil
}

// VerifyProof verifies the given proof against the given event
func VerifyProof(verifiableMMREntry VerifiableMMREntry, proof [][]byte, massif *massifs.MassifContext) (bool, error) {
	// Get the size of the complete tenant MMR
	mmrSize := massif.RangeCount()

	hasher := sha256.New()

	mmrEntry, err := verifiableMMREntry.MMREntry()
	if err != nil {
		return false, err
	}

	return mmr.VerifyInclusion(massif, hasher, mmrSize, mmrEntry,
		verifiableMMREntry.MMRIndex(), proof)
}

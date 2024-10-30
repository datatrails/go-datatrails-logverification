package logverification

import (
	"context"
	"errors"
	"fmt"
	"hash"

	"github.com/datatrails/go-datatrails-common/azblob"
	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
)

// VerifyConsistency takes two log states, and verifies that log state B is appended onto log state A
// MMRState is an abstraction, but it is assumed that logStateA comes from a local, trusted copy of the data
// rather than a fresh download from DataTrails.
//
// This function assumes the two log states are from the same massif.
//
// NOTE: the log state's signatures are not verified in this function, it is expected that the signature verification
// is done as a separate step to the consistency verification.
func VerifyConsistency(
	ctx context.Context,
	hasher hash.Hash,
	reader azblob.Reader,
	tenantID string,
	logStateA *massifs.MMRState,
	logStateB *massifs.MMRState,
) (bool, error) {

	if logStateA.Peaks == nil || logStateB.Peaks == nil {
		return false, errors.New("VerifyConsistency failed: the roots for both log state A and log state B need to be set")
	}

	if len(logStateA.Peaks) == 0 || len(logStateB.Peaks) == 0 {
		return false, errors.New("VerifyConsistency failed: the roots for both log state A and log state B need to be set")
	}

	massifReader := massifs.NewMassifReader(logger.Sugar, reader)

	// last massif in the merkle log for log state B
	massifContextB, err := Massif(logStateB.MMRSize-1, massifReader, tenantID, DefaultMassifHeight)
	if err != nil {
		return false, fmt.Errorf("VerifyConsistency failed: unable to get the last massif for log state B: %w", err)
	}

	// We check a proof of consistency between logStateA and logStateB.
	// This will be a proof that logStateB includes all elements from logStateA,
	// and includes them in the same positions.

	// In order to verify the proof we verify that the inclusion proofs of each of
	// the peaks from the old log matches a peak in the new log.
	// Because a proof of inclusion requires that the proof reproduces the peak,
	// and because all nodes in the old tree have proofs that pass through the
	// old peaks and then reach the new peaks, we know it is not possible for
	// the children to verify unless their peaks also verify.  So we don't need
	// to check every hash.

	verified, _ /*peaksB*/, err := mmr.CheckConsistency(massifContextB, hasher, logStateA.MMRSize, logStateB.MMRSize, logStateA.Peaks)

	// A tampered node can not be proven unless the entire log is re-built.  If
	// a log is re-built, any proof held by a relying party will not verify. And
	// as it is signed, it is evidence the log was re-built by someone with
	// access to our signing key.
	// In the case of a tamper (or corruption) without re-build, the proof of inclusion will fail.
	// Examining the parent and sibling of an individually tampered node will reveal the tamper.
	// This means we are always fail safe in the case of a tampered node - a
	// party relying on the log can guarantee the will never use unverifiable
	// data.
	return verified, err
}

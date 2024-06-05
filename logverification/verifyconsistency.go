package logverification

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"hash"

	"github.com/datatrails/go-datatrails-common/azblob"
	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
)

// VerifyConsistency takes two log states, and verifies that log state B is appended onto log state A
//
// NOTE: the log state's signatures are not verified in this function, it is expected that the signature verification
// is done as a separate step to the consistency verification.
//
// NOTE: it is expected that both logStateA and logStateB have had their root recalculated.
func VerifyConsistency(
	ctx context.Context,
	hasher hash.Hash,
	reader azblob.Reader,
	tenantID string,
	logStateA *massifs.MMRState,
	logStateB *massifs.MMRState,
) (bool, error) {

	if logStateA.Root == nil || logStateB.Root == nil {
		return false, errors.New("VerifyConsistency failed: the roots for both log state A and log state B need to be set")
	}

	if len(logStateA.Root) == 0 || len(logStateB.Root) == 0 {
		return false, errors.New("VerifyConsistency failed: the roots for both log state A and log state B need to be set")
	}

	massifReader := massifs.NewMassifReader(logger.Sugar, reader)

	// last massif in the merkle log for log state A
	massifContextA, err := Massif(logStateA.MMRSize-1, massifReader, tenantID, DefaultMassifHeight, WithNonLeafNode(true))
	if err != nil {
		return false, fmt.Errorf("VerifyConsistency failed: unable to get the last massif for log state A: %w", err)
	}

	// last massif in the merkle log for log state B
	massifContextB, err := Massif(logStateB.MMRSize-1, massifReader, tenantID, DefaultMassifHeight, WithNonLeafNode(true))
	if err != nil {
		return false, fmt.Errorf("VerifyConsistency failed: unable to get the last massif for log state B: %w", err)
	}

	// We construct a proof of consistency between logStateA and logStateB.
	//  This will be a proof that logStateB derives from logStateA.
	consistencyProof, err := mmr.IndexConsistencyProof(logStateA.MMRSize, logStateB.MMRSize, massifContextB, hasher)
	if err != nil {
		return false, fmt.Errorf("VerifyConsistency failed: unable to generate consistency proof: %w", err)
	}

	// In order to verify the proof we take the hashes of all of the peaks in logStateA.
	// The hash of each of these peaks guarantees the integrity of all of its child nodes, so we
	// don't need to check every hash.

	// Peaks returned as MMR positions (1-based), not MMR indices (0-based). The location of these
	// is deterministic: Given an MMR of a particular size, the peaks will always be in the same place.
	logPeaksA := mmr.Peaks(logStateA.MMRSize)

	// Get the hashes of all of the peaks.
	logPeakHashesA, err := mmr.PeakBagRHS(massifContextA, hasher, 0, logPeaksA)
	if err != nil {
		return false, errors.New("error")
	}

	// Lastly, verify the consistency proof using the peak hashes from our backed-up log. If this
	// returns true, then we can confidently say that everything in the backed-up log is in the state
	// of the log described by this signed state.
	verified := mmr.VerifyConsistency(hasher, logPeakHashesA, consistencyProof, logStateA.Root, logStateB.Root)
	return verified, nil
}

// VerifyConsistencyFromMassifs takes a massif context providing access to data from the past, and a massif
// context providing access to the current version of the log. It returns whether or not the
// new version of the log is consistent with the previous version (i.e. it contains all of the
// same nodes in the same positions.)
func VerifyConsistencyFromMassifs(
	ctx context.Context,
	verificationKey ecdsa.PublicKey,
	hasher hash.Hash,
	blobReader azblob.Reader,
	massifContextBefore *massifs.MassifContext,
	massifContextNow *massifs.MassifContext,
	logStateNow *massifs.MMRState,
) (bool, error) {
	// Grab some core info about our backed up merkle log, which we'll need to prove consistency
	mmrSizeBefore := massifContextBefore.Count()
	rootBefore, err := mmr.GetRoot(mmrSizeBefore, massifContextBefore, hasher)
	if err != nil {
		return false, fmt.Errorf("VerifyConsistency failed: unable to get root for massifContextBefore: %w", err)
	}

	// We construct a proof of consistency between the backed up MMR log and the head of the log.
	consistencyProof, err := mmr.IndexConsistencyProof(mmrSizeBefore, logStateNow.MMRSize, massifContextNow, hasher)
	if err != nil {
		return false, errors.New("error")
	}

	// In order to verify the proof we take the hashes of all of the peaks in the backed up log.
	// The hash of each of these peaks guarantees the integrity of all of its child nodes, so we
	// don't need to check every hash.

	// Peaks returned as MMR positions (1-based), not MMR indices (0-based). The location of these
	// is deterministic: Given an MMR of a particular size, the peaks will always be in the same place.
	backupLogPeaks := mmr.Peaks(mmrSizeBefore)

	// Get the hashes of all of the peaks.
	backupLogPeakHashes, err := mmr.PeakBagRHS(massifContextNow, hasher, 0, backupLogPeaks)
	if err != nil {
		return false, errors.New("error")
	}

	// Lastly, verify the consistency proof using the peak hashes from our backed-up log. If this
	// returns true, then we can confidently say that everything in the backed-up log is in the state
	// of the log described by this signed state.
	verified := mmr.VerifyConsistency(hasher, backupLogPeakHashes, consistencyProof, rootBefore, logStateNow.Root)
	return verified, nil
}

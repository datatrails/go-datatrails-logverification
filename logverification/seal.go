package logverification

import (
	"context"
	"fmt"
	"hash"

	"github.com/datatrails/go-datatrails-common/azblob"
	"github.com/datatrails/go-datatrails-common/cbor"
	"github.com/datatrails/go-datatrails-common/cose"
	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
)

/**
 * log signed root (seal) utilities.
 */

// SignedLogState gets the signed state of the log for the massif at the given massif Index.
func SignedLogState(
	ctx context.Context,
	reader azblob.Reader,
	hasher hash.Hash,
	codec cbor.CBORCodec,
	tenantID string,
	massifIndex uint64,
) (*cose.CoseSign1Message, error) {

	sealReader := massifs.NewSignedRootReader(logger.Sugar, reader, codec)

	// Fetch the signed and unsigned state of the log
	//  at the massif given the massif index.
	signedState, logState, err := sealReader.GetLatestMassifSignedRoot(ctx, tenantID, uint32(massifIndex))
	if err != nil {
		return nil, fmt.Errorf("SignedLogState failed: unable to get latest signed root: %w", err)
	}

	massifReader := massifs.NewMassifReader(logger.Sugar, reader)
	massifContext, err := massifReader.GetMassif(ctx, tenantID, massifIndex)
	if err != nil {
		return nil, fmt.Errorf("SignedLogState failed: unable to get massif from storage for massif index: %v, err: %w",
			massifIndex, err)
	}

	// The log state at time of sealing is the Payload. It included the peaks, but this is removed
	// from the stored log state. This forces a verifier to recompute the merkle peaks from their view
	// of the data. If verification succeeds when this computed root is added to signedStateNow, then
	// we can be confident that DataTrails signed this state, and that the root matches your data.

	logState.Peaks, err = mmr.PeakHashes(&massifContext, logState.MMRSize)
	if err != nil {
		return nil, fmt.Errorf("SignedLogState failed: unable to get root for massifContextNow: %w", err)
	}

	signedState.Payload, err = codec.MarshalCBOR(logState)
	if err != nil {
		return nil, fmt.Errorf("SignedLogState failed: unable to cbor encode log state: %w", err)
	}

	return signedState, nil
}

// LogState returns the unsigned state of the log, given a signed state.
func LogState(signedState *cose.CoseSign1Message, codec cbor.CBORCodec) (*massifs.MMRState, error) {

	unsignedState := &massifs.MMRState{}
	err := codec.UnmarshalInto(signedState.Payload, unsignedState)
	if err != nil {
		return nil, err
	}

	return unsignedState, nil
}

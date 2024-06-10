//go:build integration && azurite

package logverification

import (
	"context"
	"crypto/sha256"
	"testing"

	"crypto/ecdsa"
	"errors"
	"fmt"
	"hash"

	"github.com/datatrails/go-datatrails-logverification/integrationsupport"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/stretchr/testify/require"

	"github.com/datatrails/go-datatrails-common/azblob"
	"github.com/datatrails/go-datatrails-common/cbor"
	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
	"github.com/datatrails/go-datatrails-merklelog/mmrtesting"
)

// A user wanting to convince themselves that DataTrails faithfully maintains the long-term
// integrity of their data might do something like this:
//  0. Keep backups of the merkle log data for their tenancy, to check that previous entries
//     are still in the latest version of the log.
//  1. Fetch the current signed state of the log which includes entries appended since (0)
//  2. Checking the *consistency* of the new signed log state against the state you're confident in
//     means that every node (leaves and intermediate hash nodes) are included in the new state,
//     and at the same positions, and you can trust this as the new head of the log.
//  3. Get the hashes of peaks in your trusted log state and verify using a consistency proof based
//     on a published signed state.
func TestVerifyConsistency(t *testing.T) {
	testContext, testGenerator, _ := integrationsupport.NewAzuriteTestContext(t, "TestVerifyConsistency")

	// - Public key to verify the signature of the signed state (ephemeral keys are used for this demo)
	// - Massif context that represents the backed-up merkle log data for a point in the past (containing 7 events)
	// - Massif context that represents the head of the log (after 4 additional events appended)
	//
	// (!) A MassifContext provides access to the log entries in a single massif. A massif is a
	// logical chunk of the merkle log, stored in an Azure blob.
	publicVerificationKey, backupMassifContext, newMassifContext := integrationsupport.SetupTest(t, testContext, testGenerator)

	hasher := sha256.New()
	codec, err := massifs.NewRootSignerCodec()
	require.NoError(t, err)

	// First we verify the signature. In order to trust the data, we want to see that DataTrails has
	// committed to the state of the merkle log by signing it.
	logStateNow, signatureVerificationErr := verifySignature(
		context.Background(), publicVerificationKey, hasher, codec, testContext.Storer,
		&newMassifContext,
	)
	require.NoError(t, signatureVerificationErr)

	// Then we verify the consistency of the data between our previously trusted log state
	// (accessible through backupMassifContext) and the current state (accessible through
	// newMassifContext.)

	// backupMassifContext points to the following merkle log with 7 leaves.
	//
	//	    6
	//	  /   \
	//	 2     5     9
	//	/ \   / \   / \
	// 0   1 3   4 7   8 10   <- Leaf Nodes

	// newMassifContext points to the following merkle log with 11 leaves. You can see the exact
	// structure of backupMassifContext within it (ending at leaf mmr index 10.) This illustrates
	// what it means for the merkle trees to be consistent.
	//
	//	         14
	//	        /  \
	//	       /    \
	//	      /      \
	//	     /        \
	//	    6          13
	//	  /   \       /   \
	//	 2     5     9     12     17
	//	/ \   / \   / \   /  \   /  \
	// 0   1 3   4 7   8 10  11 15  16  18 <- Leaf Nodes
	verified, err := VerifyConsistencyFromMassifs(
		context.Background(), publicVerificationKey, hasher, testContext.Storer, &backupMassifContext,
		&newMassifContext, logStateNow,
	)
	require.NoError(t, err)

	require.True(t, verified)
}

func verifySignature(
	ctx context.Context,
	verificationKey ecdsa.PublicKey,
	hasher hash.Hash,
	codec cbor.CBORCodec,
	blobReader azblob.Reader,
	massifContextNow *massifs.MassifContext,
) (*massifs.MMRState, error) {
	sealReader := massifs.NewSignedRootReader(logger.Sugar, blobReader, codec)

	// Fetch the latest signed state of the log
	signedStateNow, logStateNow, err := sealReader.GetLatestMassifSignedRoot(ctx, mmrtesting.DefaultGeneratorTenantIdentity, 0)
	if err != nil {
		return nil, fmt.Errorf("verifySignature failed: unable to get latest signed root: %w", err)
	}

	// The log state at time of sealing is the Payload. It included the root, but this is removed
	// from the stored log state. This forces a verifier to recompute the merkle root from their view
	// of the data. If verification succeeds when this computed root is added to signedStateNow, then
	// we can be confident that DataTrails signed this state, and that the root matches your data.
	logStateNow.Root, err = mmr.GetRoot(logStateNow.MMRSize, massifContextNow, hasher)
	if err != nil {
		return nil, fmt.Errorf("VerifyConsistency failed: unable to get root for massifContextNow: %w", err)
	}

	signedStateNow.Payload, err = codec.MarshalCBOR(logStateNow)
	if err != nil {
		return nil, errors.New("error")
	}

	signatureVerificationError := signedStateNow.VerifyWithPublicKey(&verificationKey, nil)
	if signatureVerificationError != nil {
		return nil, fmt.Errorf("VerifyConsistency failed: signature verification failed: %w", err)
	}

	return &logStateNow, nil
}

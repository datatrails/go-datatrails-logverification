//go:build integration && azurite

package logverification

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/datatrails/go-datatrails-logverification/integrationsupport"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/stretchr/testify/require"

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
//
// 0   1 3   4 7   8 10  11 15  16  18 <- Leaf Nodes
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

	signedState, err := SignedLogState(
		context.Background(), testContext.Storer, hasher, codec,
		mmrtesting.DefaultGeneratorTenantIdentity, 0,
	)
	require.NoError(t, err)

	signatureVerificationErr := signedState.VerifyWithPublicKey(&publicVerificationKey, nil)
	require.NoError(t, signatureVerificationErr)

	logState, err := LogState(signedState, codec)
	require.NoError(t, err)

	verified, err := VerifyConsistencyFromMassifs(
		context.Background(), publicVerificationKey, hasher, testContext.Storer, &backupMassifContext,
		&newMassifContext, logState,
	)
	require.NoError(t, err)

	require.True(t, verified)
}

//go:build integration && azurite

package logverification

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"hash"
	"testing"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-common/cbor"
	"github.com/datatrails/go-datatrails-common/cose"
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
//     0   1 3   4 7   8 10   <- Leaf Nodes

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

type TestLogHelper struct {
	t          *testing.T
	tctx       mmrtesting.TestContext
	tgen       integrationsupport.TestGenerator
	signingKey ecdsa.PrivateKey
	hasher     hash.Hash
	codec      cbor.CBORCodec
}

// AppendToLog appends `newEventCount` test events to the log for `tenantID`, generates a seal
// and returns both the signed state and the reconstructed log state.
func (b *TestLogHelper) AppendToLog(tenantID string, newEventCount int, clearBlobs bool) (*cose.CoseSign1Message, *massifs.MMRState, []*assets.EventResponse) {
	events := integrationsupport.GenerateTenantLog(
		&b.tctx, b.tgen, newEventCount, tenantID, clearBlobs,
		integrationsupport.TestMassifHeight,
	)
	integrationsupport.GenerateMassifSeal(b.t, b.tctx, events[len(events)-1], b.signingKey)

	signedState, err := SignedLogState(context.Background(), b.tctx.Storer, b.hasher, b.codec, tenantID, 0)
	require.NoError(b.t, err)

	logState, err := LogState(signedState, b.codec)
	require.NoError(b.t, err)

	return signedState, logState, events
}

func (b *TestLogHelper) VerifyConsistencyBetween(fromState *massifs.MMRState, toState *massifs.MMRState, inTenant string) bool {
	result, err := VerifyConsistency(
		context.Background(), b.hasher, b.tctx.Storer, inTenant, fromState, toState,
	)

	require.NoError(b.t, err)
	return result
}

// TestConsistencyVerificationUnidirectionality checks that consistency proofs work as expected in
// the happy case. It also examines a couple of ordering edge cases.
func TestConsistencyVerificationUnidirectionality(t *testing.T) {
	var err error
	helper := TestLogHelper{
		t:          t,
		signingKey: massifs.TestGenerateECKey(t, elliptic.P256()),
		hasher:     sha256.New(),
	}

	helper.codec, err = massifs.NewRootSignerCodec()
	require.NoError(t, err)
	helper.tctx, helper.tgen, _ = integrationsupport.NewAzuriteTestContext(t, "TestVerifyConsistency")
	tenantID := mmrtesting.DefaultGeneratorTenantIdentity

	_, logStateA, _ := helper.AppendToLog(tenantID, 2, true)
	signedStateA2, logStateA2, _ := helper.AppendToLog(tenantID, 1, false)

	sigVerErr := signedStateA2.VerifyWithPublicKey(&helper.signingKey.PublicKey, nil)
	require.NoError(t, sigVerErr)

	// logStateA contains 2 events and logStateB extends that by 1 event.

	// A is a subset of A2, so we expect consistency here.
	result := helper.VerifyConsistencyBetween(logStateA, logStateA2, tenantID)
	require.True(t, result)

	// A2 is a superset of A, so consistency verification must fail if we reverse the states.
	result = helper.VerifyConsistencyBetween(logStateA2, logStateA, tenantID)
	require.False(t, result)

	// A2 is a (non-strict) subset of A2, so consistency verification should succeed
	result = helper.VerifyConsistencyBetween(logStateA2, logStateA2, tenantID)
	require.True(t, result)
}

// TestSignatureVerificationFailsIfTampered checks that our signature verification methods do
// actually fail when signature is tampered with, for real seal data.
func TestSignatureVerificationFailsIfTampered(t *testing.T) {
	var err error
	testLogBuilder := TestLogHelper{
		t:          t,
		signingKey: massifs.TestGenerateECKey(t, elliptic.P256()),
		hasher:     sha256.New(),
	}

	testLogBuilder.codec, err = massifs.NewRootSignerCodec()
	require.NoError(t, err)
	testLogBuilder.tctx, testLogBuilder.tgen, _ = integrationsupport.NewAzuriteTestContext(t, "TestVerifyConsistency")
	tenantID := mmrtesting.DefaultGeneratorTenantIdentity

	signedState, _, _ := testLogBuilder.AppendToLog(tenantID, 2, true)
	sigVerErr := signedState.VerifyWithPublicKey(&testLogBuilder.signingKey.PublicKey, nil)
	require.NoError(t, sigVerErr)

	signedState.Payload[0] = 'z'
	sigVerErr = signedState.VerifyWithPublicKey(&testLogBuilder.signingKey.PublicKey, nil)
	require.Error(t, sigVerErr)
}

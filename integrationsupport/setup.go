//go:build integration && azurite

package integrationsupport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/datatrails/go-datatrails-merklelog/mmrtesting"
	"github.com/stretchr/testify/require"
)

// SetupTest creates some test data used to demonstrate how we verify consistency between a previous
// and current log state. It returns (public verification key, previous massif context,
// current massif context.)
func SetupTest(t *testing.T, testContext mmrtesting.TestContext, testGenerator TestGenerator) (ecdsa.PublicKey, massifs.MassifContext, massifs.MassifContext) {
	// Things we'll need
	signingKey := massifs.TestGenerateECKey(t, elliptic.P256())
	verificationKey := signingKey.PublicKey
	massifReader := massifs.NewMassifReader(logger.Sugar, testContext.Storer)
	tenantID := mmrtesting.DefaultGeneratorTenantIdentity

	// Generate an initial batch of events. These are the last known backed-up events by the user.
	GenerateTenantLog(&testContext, testGenerator, 7, tenantID, true, TestMassifHeight)
	oldMassifContext, err := massifReader.GetMassif(context.TODO(), tenantID, 0)
	require.Nil(t, err)
	require.Equal(t, uint64(11), oldMassifContext.RangeCount())

	// Append 4 leaves to the existing Merkle log.
	appendedEvents := GenerateTenantLog(&testContext, testGenerator, 4, tenantID, false, TestMassifHeight)
	massifContext, err := massifReader.GetMassif(context.TODO(), tenantID, 0)
	require.Nil(t, err)

	// Check that our test generation code actually appended it. Confirm that the old massif context
	// hasn't been updated, as it represents the customer's cache of the data.
	require.Equal(t, uint64(19), massifContext.RangeCount())
	require.Equal(t, uint64(11), oldMassifContext.RangeCount())

	// New log is old log plus these appended events
	lastLogBEvent := appendedEvents[len(appendedEvents)-1]

	// Upload to emulated blob storage
	GenerateMassifSeal(t, testContext, lastLogBEvent, signingKey)
	return verificationKey, oldMassifContext, massifContext
}

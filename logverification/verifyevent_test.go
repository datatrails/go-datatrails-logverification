//go:build integration && azurite

package logverification

import (
	"testing"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-logverification/integrationsupport"
	"github.com/datatrails/go-datatrails-merklelog/mmrtesting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyEvent tests:
//
// An end to end run through of proof generation to proof verification
//
//	of an event stored on an emulated azure blob storage.
func TestVerifyEvent(t *testing.T) {
	tc, g, _ := integrationsupport.NewAzuriteTestContext(t, "TestVerify")

	// use the same tenant ID for all events
	tenantID := mmrtesting.DefaultGeneratorTenantIdentity

	events := integrationsupport.GenerateTenantLog(&tc, g, 10, tenantID, true, integrationsupport.TestMassifHeight)
	event := events[len(events)-1]

	// convert the last event into json
	marshaler := assets.NewFlatMarshalerForEvents()
	eventJSON, err := marshaler.Marshal(event)
	require.NoError(t, err)

	verifiableEvent, err := NewVerifiableAssetsV2Event(eventJSON)
	require.NoError(t, err)

	// NOTE: we would usually use azblob.NewReaderNoAuth()
	//       instead of tc.Storer. But the azurite emulator
	//       doesn't allow for public reads, unlike actual
	//       blob storage that does.
	verified, err := VerifyEvent(tc.Storer, *verifiableEvent, WithMassifHeight(integrationsupport.TestMassifHeight))
	require.NoError(t, err)
	assert.Equal(t, true, verified)
}

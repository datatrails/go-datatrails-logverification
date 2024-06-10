//go:build integration && azurite

package logverification

import (
	"fmt"
	"testing"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-logverification/integrationsupport"
	"github.com/datatrails/go-datatrails-merklelog/mmrtesting"
	"github.com/stretchr/testify/require"
	// TestVerifyListIntegration demonstrates how to verify the completeness of a list of events against a
	// DataTrails Merkle log.
)

func generateTestEvents(t *testing.T, count int, testContext mmrtesting.TestContext, testGenerator integrationsupport.TestGenerator, massifHeight uint8) []byte {
	tenantID := mmrtesting.DefaultGeneratorTenantIdentity
	generatedEvents := integrationsupport.GenerateTenantLog(&testContext, testGenerator, count, tenantID, true, massifHeight)
	marshaller := assets.NewFlatMarshalerForEvents()

	events := assets.ListEventsResponse{
		Events: generatedEvents,
	}

	eventsJson, err := marshaller.Marshal(&events)
	require.Nil(t, err)

	return eventsJson
}

func TestVerifyListIntegration(t *testing.T) {
	logger.New("TestVerifyList")
	defer logger.OnExit()

	// We're generating test events here, but you could also use data retrieved from the events API.
	testContext, testGenerator, _ := integrationsupport.NewAzuriteTestContext(t, "TestVerifyList")
	eventJsonList := generateTestEvents(t, 8, testContext, testGenerator, integrationsupport.TestMassifHeight)

	// massifHeight = 3, leaves = 8, so the first 4 leaves are in massif 0, and the others are in
	// massif 1

	// We now verify the completeness of our list of events. Given that our list of events is sorted
	// by MMR index, if we iterate over every leaf from the first leaf node to the last, we can do the
	// following:
	//   1. Detect any events in the log that were omitted from the list of events we have.
	//   2. Prove the inclusion of all events in our list against the merkle log.
	omittedIndices, err := VerifyList(testContext.Storer, eventJsonList)
	require.Nil(t, err)

	// If there were omittedIndices in our events, then the events are incomplete within that time
	// period. We report them here for inspection, but don't go as far as failing, as its context
	// dependent.
	fmt.Printf("There are '%d' omitted indices: %v\n", len(omittedIndices), omittedIndices)

	// In order to get the pre-image data (event json) for events on the log, but not
	//  in the given list of events, i.e. omitted events. We can call the datatrails
	//  events api to list events filtered by mmr index.
}

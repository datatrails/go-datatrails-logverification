//go:build integration && azurite

package logverification

import (
	"fmt"
	"testing"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-common-api-gen/attribute/v2/attribute"
	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-logverification/integrationsupport"
	"github.com/datatrails/go-datatrails-merklelog/mmrtesting"
	"github.com/stretchr/testify/require"
	// TestVerifyListIntegration demonstrates how to verify the completeness of a list of events against a
	// DataTrails Merkle log.
)

func serializeTestEvents(t *testing.T, events []*assets.EventResponse) []byte {
	wrappedEvents := assets.ListEventsResponse{
		Events: events,
	}

	marshaller := assets.NewFlatMarshalerForEvents()
	eventsJson, err := marshaller.Marshal(&wrappedEvents)
	require.Nil(t, err)

	return eventsJson
}

func TestVerifyListIntegration(t *testing.T) {
	logger.New("TestVerifyList")
	defer logger.OnExit()

	// We're generating test events here, but you could also use data retrieved from the events API.
	testContext, testGenerator, _ := integrationsupport.NewAzuriteTestContext(t, "TestVerifyList")
	tenantID := mmrtesting.DefaultGeneratorTenantIdentity
	generatedEvents := integrationsupport.GenerateTenantLog(
		&testContext, testGenerator, 8, tenantID, true, integrationsupport.TestMassifHeight,
	)
	eventJsonList := serializeTestEvents(t, generatedEvents)

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

// TestVerifyList_OmmittedEventReturned shows that, when verifying a list of API events against
// the merkle log, that the right event is returned.
func TestVerifyList_OmmittedEventReturned(t *testing.T) {
	logger.New("TestVerifyList")
	defer logger.OnExit()

	testContext, testGenerator, _ := integrationsupport.NewAzuriteTestContext(t, "TestVerifyList")
	tenantID := mmrtesting.DefaultGeneratorTenantIdentity
	generatedEvents := integrationsupport.GenerateTenantLog(
		&testContext, testGenerator, 8, tenantID, true, integrationsupport.TestMassifHeight,
	)
	trimmedGeneratedEvents := append(generatedEvents[:3], generatedEvents[4:]...)
	eventJsonList := serializeTestEvents(t, trimmedGeneratedEvents)
	omittedIndices, err := VerifyList(testContext.Storer, eventJsonList)

	require.Nil(t, err)
	require.Len(t, omittedIndices, 1)
	require.Equal(t, omittedIndices[0], uint64(4))
}

// TestVerifyList_MultipleOmittedEventsReturned shows that when multiple events are in the merkle
// log but not in the set of events, they are all returned.
// Note: The events are dropped from the middle, since "omitted" events are gaps in the middle of a
// range of events. The range it looks over for omitted events is based on the set of events its
// passed.
func TestVerifyList_MultipleOmittedEventsReturned(t *testing.T) {
	logger.New("TestVerifyList")
	defer logger.OnExit()

	testContext, testGenerator, _ := integrationsupport.NewAzuriteTestContext(t, "TestVerifyList")
	tenantID := mmrtesting.DefaultGeneratorTenantIdentity
	generatedEvents := integrationsupport.GenerateTenantLog(
		&testContext, testGenerator, 8, tenantID, true, integrationsupport.TestMassifHeight,
	)
	trimmedGeneratedEvents := append(generatedEvents[:3], generatedEvents[5:]...)
	eventJsonList := serializeTestEvents(t, trimmedGeneratedEvents)
	omittedIndices, err := VerifyList(testContext.Storer, eventJsonList)

	require.Nil(t, err)
	require.Len(t, omittedIndices, 2)
	require.Equal(t, omittedIndices[0], uint64(4))
	require.Equal(t, omittedIndices[1], uint64(7))
}

// TestVerifyList_TamperedEventContent_ShouldError shows that a modification to the content of
// a committed event causes a verification failure.
func TestVerifyList_TamperedEventContent_ShouldError(t *testing.T) {
	logger.New("TestVerifyList")
	defer logger.OnExit()

	testContext, testGenerator, _ := integrationsupport.NewAzuriteTestContext(t, "TestVerifyList")
	tenantID := mmrtesting.DefaultGeneratorTenantIdentity
	generatedEvents := integrationsupport.GenerateTenantLog(
		&testContext, testGenerator, 8, tenantID, true, integrationsupport.TestMassifHeight,
	)

	// Modify one of the logged events
	generatedEvents[5].EventAttributes["additional"] = attribute.NewStringAttribute("foobar")
	eventJsonList := serializeTestEvents(t, generatedEvents)
	_, err := VerifyList(testContext.Storer, eventJsonList)

	require.Error(t, err)
}

// TestVerifyList_ExtraEvent_ShouldError shows that an extra event at an intermediate node position
// should cause a verification failure.
func TestVerifyList_ExtraEvent_ShouldError(t *testing.T) {
	logger.New("TestVerifyList")
	defer logger.OnExit()

	testContext, testGenerator, _ := integrationsupport.NewAzuriteTestContext(t, "TestVerifyList")
	tenantID := mmrtesting.DefaultGeneratorTenantIdentity
	generatedEvents := integrationsupport.GenerateTenantLog(
		&testContext, testGenerator, 8, tenantID, true, integrationsupport.TestMassifHeight,
	)

	dodgyEvent := generatedEvents[0]
	dodgyEvent.MerklelogEntry.Commit.Index = 2 // Intermediate node

	// Modify one of the logged events
	eventsWithExtra := append(generatedEvents[:2], dodgyEvent)
	eventsWithExtra = append(eventsWithExtra, generatedEvents[2:]...)

	eventJsonList := serializeTestEvents(t, eventsWithExtra)
	_, err := VerifyList(testContext.Storer, eventJsonList)

	require.Error(t, err)
}

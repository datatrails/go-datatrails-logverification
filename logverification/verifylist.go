package logverification

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"hash"

	"github.com/datatrails/go-datatrails-common/azblob"
	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
)

/**
 * Verifies that a list of events is also on the immutable audit log.
 *
 * Terms:
 *
 * Complete:
 *   A complete subset of a list that does not skip any elements in the original list
 *   greater than the start of the subset, and less than the end of the subset.
 *
 *  In the below example, [2,3,4] is a complete subset of the list,
 *   whereas [2,4] is not, as it skips over 3.
 *
 *  [1, 2, 3, 4, 5, 6]
 *
 * Leaf Range:
 *  A complete subset of leaves in the merklelog from lowest mmrIndex to highest mmrIndex.
 *
 * The boundaries of the range of leaves are determined by the lowest and largest mmrIndex on the given list of events.
 *
 * In the below example the event with the lowest mmrIndex matches leaf2 of the mmr,
 *	 and the event with the largest mmrIndex matches leaf4 of the mmr:
 *
 *         ↓  leaf range  ↓
 * |-------------------------------|
 * | leaf1 leaf2 leaf3 leaf4 leaf5 |
 * |-------------------------------|
 *
 *
 * Included Event:
 *  An event in the given list, that is included on the immutable log.
 *
 * Example of Included events:
 *
 * |----------------------|
 * | event1 event2 event3 | event list (lowest mmrIndex to highest)
 * |----------------------|
 *     ↓      ↓      ↓
 * |----------------------|
 * | leaf1  leaf2  leaf3  | leaf range from merklelog
 * |----------------------|
 *
 * Excluded Event:
 *  An event in the given list, that is not included on the immutable log.
 *
 * Example of Excluded event2:
 *
 * |-----------------------------|
 * | event1 event2 event3 event4 | event list (lowest mmrIndex to highest)
 * |-----------------------------|
 *     ↓             ↓       ↓
 * |-----------------------------|
 * | leaf1          leaf2  leaf3 | leaf range from merklelog
 * |-----------------------------|
 *
 * Omitted Event:
 *  An event on the immutable log,
 *    within the range of the list of events given,
 *    that is not included in the list of events given.
 *
 * Example of Omitted Event at leaf2:
 *
 * |-----------------------------|
 * | event1        event3 event4 | event list (lowest mmrIndex to highest)
 * |-----------------------------|
 *     ↓             ↓       ↓
 * |-----------------------------|
 * | leaf1  leaf2  leaf3  leaf4  | leaf range from merklelog
 * |-----------------------------|
 */

type EventType int

const (

	// Unknown event is a given event that is unknown
	Unknown EventType = iota

	// Included event is a given event that is included on the immutable log
	Included

	// Excluded event is a given event that is NOT included on the immutable log
	Excluded

	// Omitted is an event on the immutable log, that has not been given within an expected list of events.
	Omitted
)

var (
	ErrIntermediateNode       = errors.New("event references an intermediate node on the merkle log")
	ErrDuplicateEventMMRIndex = errors.New("event mmrIndex is the same as the previous event")
	ErrEventNotOnLeaf         = errors.New("event does not correspond to the event found on the leaf node")
	ErrInclusionProofVerify   = errors.New("event failed to verify the inclusion proof on the merkle log")
	ErrNotEnoughEventsInList  = errors.New("the number of events in the list is less than the number of leafs on the log")
)

/** VerifyList verifies a given list of events against a range of leaves in the immutable merkle log.
 *
 * The list of events given is the json response from a datatrails list API call.
 *
 * The boundaries of the range of leaves are determined by the lowest and largest mmrIndex on the given list of events.
 * In the below example the event with the lowest mmrIndex matches leaf2 of the mmr,
 *	 and the event with the largest mmrIndex matches leaf4 of the mmr:
 *
 *         ↓  leaf range  ↓
 * |-------------------------------|
 * | leaf1 leaf2 leaf3 leaf4 leaf5 |
 * |-------------------------------|
 *
 * Once a range of leaves in the mmr has been established, we iterate over each leaf in the range
 *	 and each event in the list (sorted lowest to highest by mmrIndex).
 *
 * We check that each event is INCLUDED in the mmr at the leaf index it is in tandem with
 *	 in the iteration:
 *
 * |----------------------|
 * | event1 event2 event3 | event list (lowest mmrIndex to highest)
 * |----------------------|
 *     ↓      ↓      ↓
 * |----------------------|
 * | leaf1  leaf2  leaf3  | leaf range from merklelog
 * |----------------------|
 *
 * If every event within the list is included at its expected leaf index, we say the list is COMPLETE.
 *
 * If an event within the list of events is not present on the immutable merklelog
 *	 at the expected leaf index it is in tandem with, we call that an EXCLUDED event.
 *	 In the below example, event2 is an EXCLUDED event. (Note: proof of exclusion using the trie index is not shown in this demo)
 *
 * |-----------------------------|
 * | event1 event2 event3 event4 | event list (lowest mmrIndex to highest)
 * |-----------------------------|
 *     ↓             ↓       ↓
 * |-----------------------------|
 * | leaf1          leaf2  leaf3 | leaf range from merklelog
 * |-----------------------------|
 *
 * If there is a leaf within the range of leaves that does not have an event, within the list of events included,
 *  we call that an OMITTED event.
 *
 * In the below example the event included at leaf2 is an example of an ommitted event.
 *
 * |-----------------------------|
 * | event1        event3 event4 | event list (lowest mmrIndex to highest)
 * |-----------------------------|
 *     ↓             ↓      ↓
 * |-----------------------------|
 * | leaf1  leaf2  leaf3  leaf4  | leaf range from merklelog
 * |-----------------------------|
 *
 * Returns the omitted event mmrIndexes.
 *
 * The options argument can be the following:
 *
 *   WithTenantId - the tenantId of the merklelog, the event is expected
 *                  to be included on. E.g. the public tenant
 *                  for public events.
 */
func VerifyList(reader azblob.Reader, eventListJson []byte, options ...VerifyOption) ([]uint64, error) {

	verifyOptions := ParseOptions(options...)

	hasher := sha256.New()

	massifContext := massifs.MassifContext{}
	omittedMMRIndices := []uint64{}

	events, err := ParseEventList(eventListJson)
	if err != nil {
		return nil, err
	}

	lowestLeafIndex, highestLeafIndex := LeafRange(events)

	massifReader := massifs.NewMassifReader(logger.Sugar, reader)

	eventIndex := 0

	for leafIndex := lowestLeafIndex; leafIndex <= highestLeafIndex; leafIndex += 1 {

		if eventIndex >= len(events) {
			return nil, ErrNotEnoughEventsInList
		}

		event := events[eventIndex]

		// ensure we set the tenantId if
		//  if it passed in as an optional argument
		tenantId := verifyOptions.tenantId
		if tenantId == "" {

			// otherwise set it to the event tenantID
			tenantId = event.TenantID
		}

		eventType, err := VerifyEventInList(hasher, leafIndex, event, massifReader, &massifContext, tenantId)
		if err != nil {

			// NOTE: for now fail at the first sign of an EXCLUDED event.
			//       If the event is EXCLUDED, we could log that like omitted and carry
			//       on with the next event in the list at the same leaf index.
			return nil, err
		}

		// if the event is OMITTED add the leaf to the omitted list
		if eventType == Omitted {
			omittedMMRIndices = append(omittedMMRIndices, mmr.TreeIndex(leafIndex))

			// as the event is still the lowest mmrIndex we check this event
			//  against the next leaf
			continue
		}

		eventIndex += 1

	}

	return omittedMMRIndices, nil
}

// VerifyEventInList takes the next leaf in the list of leaves and the next event in the list of events
//
//	and verifies that the event is in that leaf position.
func VerifyEventInList(
	hasher hash.Hash,
	leafIndex uint64,
	event EventDetails,
	reader massifs.MassifReader,
	massifContext *massifs.MassifContext,
	tenantID string,
) (EventType, error) {

	hasher.Reset()

	leafMMRIndex := mmr.TreeIndex(leafIndex)
	eventMMRIndex := event.MerkleLog.Commit.Index

	// First we check if the event mmrIndex corresponds to a leaf node.
	//
	// ONLY leaf nodes correspond to events.
	//
	// Therefore if the event mmrIndex corresponds to an intermediate node,
	//   the event is not in the merkle log, it is EXCLUDED.
	indexHeight := mmr.IndexHeight(eventMMRIndex)

	// all leaf nodes are at height 0
	if indexHeight != 0 {
		return Excluded, ErrIntermediateNode
	}

	// When the next event in the list of events has an mmrindex LESS THAN the next leaf in the range of leaves.
	//
	// This means the mmr index of the event matches the previous leaf node.
	//
	// This can occur because one of the following:
	//   1. The event is a duplicate of the previous event in the list.
	//   2. The event is not included on the previous leaf, but says it is.
	//
	// In both cases we say the event is not on the merkle log, it is EXCLUDED.
	//
	// Example:
	//  Event mmrIndex: 10
	//  Leaf  mmrIndex: 11
	//
	//           14
	//          /  \
	//         /    \
	//        /      \
	//       /        \
	//      6          13
	//    /   \       /   \
	//   2     5     9     12     17
	//  / \   / \   / \   /  \   /  \
	// 0   1 3   4 7   8 10  11 15  16 <- Leaf Nodes
	//
	// NOTE: in the future we may mark a duplicated event as DUPLICATED instead of EXCLUDED.
	//
	// NOTE: we can make the above assumptions because:
	//       1. the event mmrIndex is the next in the list of events,
	//          so the previous event was included on the previous leaf node.
	//       2. we have already checked that the event mmrIndex is not an intermediate node.
	if eventMMRIndex < leafMMRIndex {
		return Excluded, ErrDuplicateEventMMRIndex
	}

	// When the next event in the list of events has an mmrindex GREATER THAN the next leaf in the range of leaves.
	//
	// This means the mmr index of the event matches a future leaf node.
	//
	// This can occur because there are events on the merklelog that are not included in the list of events.
	//   The event at the leaf mmr index is an OMITTED event.
	//
	//
	// Example:
	//  Event mmrIndex: 10
	//  Leaf  mmrIndex: 4
	//
	//           14
	//          /  \
	//         /    \
	//        /      \
	//       /        \
	//      6          13
	//    /   \       /   \
	//   2     5     9     12     17
	//  / \   / \   / \   /  \   /  \
	// 0   1 3   4 7   8 10  11 15  16 <- Leaf Nodes
	//
	// NOTE: we can make the above assumptions because:
	//       1. the event mmrIndex is the next in the list of events,
	//          so the previous event was included on the previous leaf node.
	//       2. we have already checked that the event mmrIndex is not an intermediate node.
	if eventMMRIndex > leafMMRIndex {
		return Omitted, nil
	}

	// If we reach this point, the next event in the list of events has an mmrindex EQUAL TO the next leaf in the range of leaves.
	//
	// We now do an inclusion proof on the event, to prove that the event is included at the leaf node.

	// Ensure we're using the correct massif for the current leaf
	err := UpdateMassifContext(reader, massifContext, leafMMRIndex, tenantID, DefaultMassifHeight)
	if err != nil {
		return Unknown, err
	}

	// Get the leaf node mmrEntry
	leafMMREntry, err := massifContext.Get(leafMMRIndex)
	if err != nil {
		return Unknown, err
	}

	// Check that the leaf node mmrEntry is the same as the event hash
	//
	// If its not, we know that the given event is not the same as the event on the leaf node.
	if !bytes.Equal(leafMMREntry, event.EventHash) {
		return Excluded, ErrEventNotOnLeaf
	}

	// Now we know that the event is the event stored on the leaf node,
	// we can do an inclusion proof of the leaf node on the merkle log.
	mmrSize := massifContext.RangeCount()
	root, err := mmr.GetRoot(mmrSize, massifContext, hasher)
	if err != nil {
		return Unknown, err
	}

	inclusionProof, err := mmr.IndexProof(mmrSize, massifContext, hasher, leafMMRIndex)
	if err != nil {
		return Unknown, err
	}

	verified := mmr.VerifyInclusion(mmrSize, hasher, event.EventHash, leafMMRIndex, inclusionProof, root)

	// if the inclusion proof verification failed, return EXCLUDED.
	//
	// This means the leaf node is not included on the merklelog.
	if !verified {
		return Excluded, ErrInclusionProofVerify
	}

	return Included, nil

}

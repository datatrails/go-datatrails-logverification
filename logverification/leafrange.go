package logverification

import "github.com/datatrails/go-datatrails-merklelog/mmr"

/**
 * Leaf Range holds utilities for finding the range of leaves in the merkle log to
 *  consider for a list of events.
 */

// LeafRange gets the range of leaf indexes for a given list of
//
//	events, that have been sorted from lowest mmr index to highest mmr index.
//
// Returns the lower and upper bound of the leaf indexes for the leaf range.
func LeafRange(sortedEvents []EventDetails) (uint64, uint64) {

	lowerBoundMMRIndex := sortedEvents[0].MerkleLog.Commit.Index
	lowerBoundLeafIndex := mmr.LeafCount(lowerBoundMMRIndex+1) - 1 // Note: LeafCount takes an mmrIndex here not a size

	upperBoundMMRIndex := sortedEvents[len(sortedEvents)-1].MerkleLog.Commit.Index
	upperBoundLeafIndex := mmr.LeafCount(upperBoundMMRIndex+1) - 1 // Note: LeafCount takes an mmrIndex here not a size

	return lowerBoundLeafIndex, upperBoundLeafIndex

}

package integrationsupport

import (
	"github.com/datatrails/go-datatrails-simplehash/simplehash"
)

// LeafType provides domain separation for the different kinds of tree leaves we require.
type LeafType uint8

const (
	// LeafTypePlain is used for committing to plain values.
	LeafTypePlain LeafType = iota
	// LeafTypePeriodSentinel is entered into the MMR once per period. By
	// forcing a heartbeat entry, we guarantee a liveness indicator - their will
	// be a definable lower bound on how often the MMR root changes
	LeafTypePeriodSentinel
	// LeafTypeEpochTombstone is always the last leave in an epoch MMR. This is
	// used to provide crash fault tolerance on the epoch as whole
	LeafTypeEpochTombStone
)

type LeafHasher struct {
	simplehash.HasherV3
}

func NewLeafHasher() LeafHasher {
	h := LeafHasher{
		HasherV3: simplehash.NewHasherV3(),
	}
	return h
}

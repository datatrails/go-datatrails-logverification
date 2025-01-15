package app

import (
	"crypto/sha256"
	"encoding/json"
	"sort"
	"strings"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-merklelog/mmr"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
)

/**
 * assetsv2 contains all log entry specific functions for the assetsv2 app (app domain 0).
 */

// AssetsV2AppEntry is the assetsv2 app provided data for a corresponding log entry.
type AssetsV2AppEntry struct {
	*AppEntry
}

// NewAssetsV2AppEntries takes a list of events JSON (e.g. from the assetsv2 events list API), converts them
// into AssetsV2AppEntries and then returns them sorted by ascending MMR index.
func NewAssetsV2AppEntries(eventsJson []byte) ([]VerifiableAppEntry, error) {
	// get the event list out of events
	eventListJson := struct {
		Events []json.RawMessage `json:"events"`
	}{}

	err := json.Unmarshal(eventsJson, &eventListJson)
	if err != nil {
		return nil, err
	}

	events := []VerifiableAppEntry{}
	for _, eventJson := range eventListJson.Events {
		verifiableEvent, err := NewAssetsV2AppEntry(eventJson)
		if err != nil {
			return nil, err
		}

		events = append(events, verifiableEvent)
	}

	// Sorting the events by MMR index guarantees that they're sorted in log append order.
	sort.Slice(events, func(i, j int) bool {
		return events[i].MMRIndex() < events[j].MMRIndex()
	})

	return events, nil
}

// NewAssetsV2AppEntry takes a single assetsv2 event JSON and returns an AssetsV2AppEntry,
// providing just enough information to verify the incluson of and identify the event.
func NewAssetsV2AppEntry(eventJson []byte) (*AssetsV2AppEntry, error) {

	// special care is needed here to deal with uint64 types. json marshal /
	// un marshal treats them as strings because they don't fit in a
	// javascript Number

	// Unmarshal into a generic type to get just the bits we need. Use
	// defered decoding to get the raw merklelog entry as it must be
	// unmarshaled using protojson and the specific generated target type.
	entry := struct {
		Identity       string `json:"identity,omitempty"`
		TenantIdentity string `json:"tenant_identity,omitempty"`
		// Note: the proof_details top level field can be ignored here because it is a 'oneof'
		MerklelogEntry json.RawMessage `json:"merklelog_entry,omitempty"`
	}{}
	err := json.Unmarshal(eventJson, &entry)
	if err != nil {
		return nil, err
	}

	merkleLog := &assets.MerkleLogEntry{}
	err = protojson.Unmarshal(entry.MerklelogEntry, merkleLog)
	if err != nil {
		return nil, err
	}

	// get the logID from the event log tenant
	logUuid := strings.TrimPrefix(entry.TenantIdentity, "tenant/")
	logId, err := uuid.Parse(logUuid)
	if err != nil {
		return nil, err
	}

	return &AssetsV2AppEntry{
		AppEntry: &AppEntry{
			appID: entry.Identity,
			logID: logId[:],
			mmrEntryFields: &MMREntryFields{
				domain:          byte(0),
				serializedBytes: eventJson, // we cheat a bit here, because the eventJson isn't really serialized
			},
			merkleLogCommit: merkleLog.Commit,
		},
	}, nil
}

// MMREntry derives the mmr entry of the corresponding log entry from the assetsv2 app data.
//
// for assetsv2 this is simplehashv3 hash and the 'serializedBytes' is the original
// event json.
//
// NOTE: the original event json isn't really serializedbytes, but the LogVersion0 hasher includes
// the serialization.
func (ae *AssetsV2AppEntry) MMREntry() ([]byte, error) {
	hasher := LogVersion0Hasher{}
	eventHash, err := hasher.HashEvent(ae.mmrEntryFields.serializedBytes)
	if err != nil {
		return nil, err
	}

	return eventHash, nil
}

// MMRSalt derives the MMR Salt of the corresponding log entry from the app data.
// MMRSalt is the datatrails provided fields included on the MMR Entry.
//
// For assetsv2 events this is empty.
func (ae *AssetsV2AppEntry) MMRSalt() ([]byte, error) {
	return []byte{}, nil // MMRSalt is always empty for assetsv2 events
}

// VerifyProof verifies the given inclusion proof of the corresponding log entry for the app data.
func (ae *AssetsV2AppEntry) VerifyProof(proof [][]byte, options ...MassifGetterOption) (bool, error) {

	massif, err := ae.Massif(options...)

	if err != nil {
		return false, err
	}

	// Get the size of the complete tenant MMR
	mmrSize := massif.RangeCount()

	hasher := sha256.New()

	mmrEntry, err := ae.MMREntry()
	if err != nil {
		return false, err
	}

	return mmr.VerifyInclusion(massif, hasher, mmrSize, mmrEntry,
		ae.MMRIndex(), proof)

}

// VerifyInclusion verifies the inclusion of the app entry
// against the corresponding log entry in immutable merkle log
//
// Returns true if the app entry is included on the log, otherwise false.
func (ae *AssetsV2AppEntry) VerifyInclusion(options ...MassifGetterOption) (bool, error) {

	massif, err := ae.Massif(options...)

	if err != nil {
		return false, err
	}

	proof, err := ae.Proof(WithMassifContext(massif))
	if err != nil {
		return false, err
	}

	return ae.VerifyProof(proof, WithMassifContext(massif))
}

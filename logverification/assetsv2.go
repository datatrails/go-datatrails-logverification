package logverification

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
)

/**
 * assetsv2 contains all log entry specific functions for the assetsv2 app (app domain 0).
 */

// VerifiableAssetsV2Event contains key information for verifying inclusion of merkle log events
type VerifiableAssetsV2Event struct {
	VerifiableLogEntry
}

// NewVerifiableAssetsV2Events takes a list of events JSON (e.g. from the events list API), converts them
// into VerifiableAssetsV2Events and then returns them sorted by ascending MMR index.
func NewVerifiableAssetsV2Events(eventsJson []byte) ([]VerifiableAssetsV2Event, error) {
	// get the event list out of events
	eventListJson := struct {
		Events []json.RawMessage `json:"events"`
	}{}

	err := json.Unmarshal(eventsJson, &eventListJson)
	if err != nil {
		return nil, err
	}

	events := []VerifiableAssetsV2Event{}
	for _, eventJson := range eventListJson.Events {
		verifiableEvent, err := NewVerifiableAssetsV2Event(eventJson)
		if err != nil {
			return nil, err
		}

		events = append(events, *verifiableEvent)
	}

	// Sorting the events by MMR index guarantees that they're sorted in log append order.
	sort.Slice(events, func(i, j int) bool {
		return events[i].MerkleLogCommit.Index < events[j].MerkleLogCommit.Index
	})

	return events, nil
}

// NewVerifiableAssetsV2Events takes a single assetsv2 event JSON and returns a VerifiableAssetsV2Event,
// providing just enough information to verify and identify the event.
func NewVerifiableAssetsV2Event(eventJson []byte) (*VerifiableAssetsV2Event, error) {

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

	return &VerifiableAssetsV2Event{
		VerifiableLogEntry: VerifiableLogEntry{
			AppId: entry.Identity,
			LogId: logId[:],
			MMREntryFields: &MMREntryFields{
				Domain:          byte(0),
				SerializedBytes: eventJson, // we cheat a bit here, because the eventJson isn't really serialized
			},
			MerkleLogCommit:  merkleLog.Commit,
			MerkleLogConfirm: merkleLog.Confirm,
		},
	}, nil
}

// MMREntry gets the MMR Entry from the VerifiableAssetsV2Event
// for assetsv2 this is simplehashv3 hash and the 'serializedBytes' is the original
// event json.
//
// NOTE: the original event json isn't really serializedbytes, but the LogVersion0 hasher includes
// the serialization.
func (ve *VerifiableAssetsV2Event) MMREntry() ([]byte, error) {
	hasher := LogVersion0Hasher{}
	eventHash, err := hasher.HashEvent(ve.MMREntryFields.SerializedBytes)
	if err != nil {
		return nil, err
	}

	return eventHash, nil
}

// MMRSalt gets the MMR Salt, which is the datatrails provided fields included on the MMR Entry.
//
// For assetsv2 events this is empty.
func (ve *VerifiableAssetsV2Event) MMRSalt() ([]byte, error) {
	return []byte{}, nil // MMRSalt is always empty for assetsv2 events
}

// LogTenant returns the Log tenant that committed this assetsv2 event to the log
//
// as a tenant identity.
func (ve *VerifiableAssetsV2Event) LogTenant() (string, error) {

	logTenantUuid, err := uuid.FromBytes(ve.LogId)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("tenant/%s", logTenantUuid.String()), nil

}

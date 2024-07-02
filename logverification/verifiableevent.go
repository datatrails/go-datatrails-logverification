package logverification

import (
	"encoding/json"
	"sort"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"google.golang.org/protobuf/encoding/protojson"
)

// VerifiableEvent contains key information for verifying inclusion of merkle log events
type VerifiableEvent struct {
	EventID   string
	TenantID  string
	LeafHash  []byte
	MerkleLog *assets.MerkleLogEntry
}

// NewVerifiableEvents takes a list of events JSON (e.g. from the events list API), converts them
// into VerifiableEvents and then returns them sorted by ascending MMR index.
func NewVerifiableEvents(eventsJson []byte) ([]VerifiableEvent, error) {
	// get the event list out of events
	eventListJson := struct {
		Events []json.RawMessage `json:"events"`
	}{}

	err := json.Unmarshal(eventsJson, &eventListJson)
	if err != nil {
		return nil, err
	}

	events := []VerifiableEvent{}
	for _, eventJson := range eventListJson.Events {
		verifiableEvent, err := NewVerifiableEvent(eventJson)
		if err != nil {
			return nil, err
		}

		events = append(events, *verifiableEvent)
	}

	// Sorting the events by MMR index guarantees that they're sorted in log append order.
	sort.Slice(events, func(i, j int) bool {
		return events[i].MerkleLog.Commit.Index < events[j].MerkleLog.Commit.Index
	})

	return events, nil
}

// NewVerifiableEvent takes a single event JSON and returns a VerifiableEvent,
// providing just enough information to verify and identify the event.
func NewVerifiableEvent(eventJson []byte) (*VerifiableEvent, error) {

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

	hasher := LogVersion0Hasher{}
	eventHash, err := hasher.HashEvent(eventJson)
	if err != nil {
		return nil, err
	}

	return &VerifiableEvent{
		EventID:   entry.Identity,
		TenantID:  entry.TenantIdentity,
		LeafHash:  eventHash,
		MerkleLog: merkleLog,
	}, nil
}

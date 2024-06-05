package logverification

import (
	"encoding/json"
	"sort"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"google.golang.org/protobuf/encoding/protojson"
)

// EventDetails contains key information for verifying inclusion of merkle log events
type EventDetails struct {
	EventID   string
	TenantID  string
	EventHash []byte
	MerkleLog *assets.MerkleLogEntry
}

// ParseEventList takes a json list of events returned by the datatrails events API
//
//	and returns an mmrIndex ascending, sorted list of golang list of event details whose members are easier to access.
func ParseEventList(eventsJson []byte) ([]EventDetails, error) {

	// get the event list out of events
	eventListJson := struct {
		Events []json.RawMessage `json:"events"`
	}{}
	err := json.Unmarshal(eventsJson, &eventListJson)
	if err != nil {
		return nil, err
	}

	events := []EventDetails{}
	for _, eventJson := range eventListJson.Events {

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

		eventDetails := EventDetails{
			EventID:   entry.Identity,
			TenantID:  entry.TenantIdentity,
			EventHash: eventHash,
			MerkleLog: merkleLog,
		}
		events = append(events, eventDetails)
	}

	// Sorting the events by MMR index guarantees that they're sorted in log append order.
	sort.Slice(events, func(i, j int) bool {
		return events[i].MerkleLog.Commit.Index < events[j].MerkleLog.Commit.Index
	})

	return events, nil

}

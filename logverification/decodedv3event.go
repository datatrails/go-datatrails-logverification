package logverification

import (
	"encoding/json"
	"sort"

	"github.com/datatrails/go-datatrails-simplehash/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-simplehash/simplehash"
	"google.golang.org/protobuf/encoding/protojson"
)

// DecodedEvent
type DecodedEvent struct {
	V3Event   simplehash.V3Event
	MerkleLog *assets.MerkleLogEntry
}

// NewDecodedEvents takes a list of events JSON (e.g. from the events list API), converts them
// into DecodedEvents and then returns them sorted by ascending MMR index.
func NewDecodedEvents(eventsJson []byte) ([]DecodedEvent, error) {
	// get the event list out of events
	eventListJson := struct {
		Events []json.RawMessage `json:"events"`
	}{}

	err := json.Unmarshal(eventsJson, &eventListJson)
	if err != nil {
		return nil, err
	}

	events := []DecodedEvent{}
	for _, eventJson := range eventListJson.Events {
		decodedEvent, err := NewDecodedEvent(eventJson)
		if err != nil {
			return nil, err
		}

		events = append(events, *decodedEvent)
	}

	// Sorting the events by MMR index guarantees that they're sorted in log append order.
	sort.Slice(events, func(i, j int) bool {
		return events[i].MerkleLog.Commit.Index < events[j].MerkleLog.Commit.Index
	})

	return events, nil
}

// NewDecodedEvent takes a single event JSON and returns a DecodedEvent
func NewDecodedEvent(eventJson []byte) (*DecodedEvent, error) {
	// special care is needed here to deal with uint64 types. json marshal /
	// un marshal treats them as strings because they don't fit in a
	// javascript Number

	// Unmarshal into a generic type to get just the bits we need. Use
	// defered decoding to get the raw merklelog entry as it must be
	// unmarshaled using protojson and the specific generated target type.
	entry := struct {
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

	v3Event, err := simplehash.V3FromEventJSON(eventJson)
	if err != nil {
		return nil, err
	}

	return &DecodedEvent{
		V3Event:   v3Event,
		MerkleLog: merkleLog,
	}, nil
}

package logverification

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/datatrails/go-datatrails-serialization/eventsv1"
)

/**
 * eventsv1 contains all log entry specific functions for the events1 app (app domain 1).
 */

const (

	// EventsV1AppDomain is the events v1 app domain
	EventsV1AppDomain = byte(1)
)

// VerifiableEventsV1Event contains key information for verifying inclusion of merkle log events
type VerifiableEventsV1Event struct {
	VerifiableLogEntry
}

// NewVerifiableEventsV1Events takes a list of events JSON (e.g. from the events list API), converts them
// into VerifiableEventsV1Event and then returns them sorted by ascending MMR index.
func NewVerifiableEventsV1Events(eventsJson []byte, logTenant string) ([]VerifiableEventsV1Event, error) {
	// get the event list out of events
	eventListJson := struct {
		Events []json.RawMessage `json:"events"`
	}{}

	err := json.Unmarshal(eventsJson, &eventListJson)
	if err != nil {
		return nil, err
	}

	events := []VerifiableEventsV1Event{}
	for _, eventJson := range eventListJson.Events {
		verifiableEvent, err := NewVerifiableEventsV1Event(eventJson, logTenant)
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

// NewVerifiableEventsV1Events takes a single eventsv1 event JSON and returns a VerifiableEventsV1Event,
// providing just enough information to verify and identify the event.
func NewVerifiableEventsV1Event(eventJson []byte, logTenant string, opts ...VerifiableLogEntryOption) (*VerifiableEventsV1Event, error) {

	// special care is needed here to deal with uint64 types. json marshal /
	// un marshal treats them as strings because they don't fit in a
	// javascript Number

	// Unmarshal into a generic type to get just the bits we need. Use
	// defered decoding to get the raw merklelog entry as it must be
	// unmarshaled using protojson and the specific generated target type.
	entry := struct {
		Identity     string `json:"identity,omitempty"`
		OriginTenant string `json:"origin_tenant,omitempty"`

		Attributes map[string]any `json:"attributes,omitempty"`
		Trails     []string       `json:"trails,omitempty"`

		// Note: the proof_details top level field can be ignored here because it is a 'oneof'
		MerkleLogCommit json.RawMessage `json:"merklelog_commit,omitempty"`
	}{}

	err := json.Unmarshal(eventJson, &entry)
	if err != nil {
		return nil, err
	}

	// get the merklelog commit info
	merkleLogCommit := &assets.MerkleLogCommit{}
	err = protojson.Unmarshal(entry.MerkleLogCommit, merkleLogCommit)
	if err != nil {
		return nil, err
	}

	// get the logID from the event log tenant
	logUuid := strings.TrimPrefix(logTenant, "tenant/")
	logId, err := uuid.Parse(logUuid)
	if err != nil {
		return nil, err
	}

	// get the extra bytes
	extraBytes, err := NewEventsV1ExtraBytes(entry.OriginTenant)
	if err != nil {
		return nil, err
	}

	// get the serialized bytes
	serializableEvent := eventsv1.SerializableEvent{
		Attributes: entry.Attributes,
		Trails:     entry.Trails,
	}
	serializedBytes, err := serializableEvent.Serialize()
	if err != nil {
		return nil, err
	}

	verifableLogEntryOptions := ParseVerifableLogEntryOptions()

	return &VerifiableEventsV1Event{
		VerifiableLogEntry: VerifiableLogEntry{
			AppId: entry.Identity,
			LogId: logId[:],
			MMREntryFields: &MMREntryFields{
				Domain:          byte(0),
				SerializedBytes: serializedBytes, // we cheat a bit here, because the eventJson isn't really serialized
			},
			ExtraBytes:       extraBytes,
			MerkleLogCommit:  merkleLogCommit,
			MerkleLogConfirm: verifableLogEntryOptions.merkleLogConfirm,
		},
	}, nil
}

// NewEventsV1ExtraBytes generates the extra bytes for an eventv1 event
// given the origin tenant of the event.
//
// NOTE: the extraBytes will always be padded to 24 bytes
func NewEventsV1ExtraBytes(originTenant string) ([]byte, error) {

	extraBytes := make([]byte, 24)

	extraBytes[0] = EventsV1AppDomain

	originTenantUuidStr := strings.TrimPrefix(originTenant, "tenant/")

	originTenantUuid, err := uuid.Parse(originTenantUuidStr)
	if err != nil {
		return nil, err
	}

	copy(extraBytes[1:len(originTenantUuid)+1], originTenantUuid[:])

	return extraBytes, nil
}

// LogTenant returns the Log tenant that committed this assetsv2 event to the log
//
// as a tenant identity.
func (ve *VerifiableEventsV1Event) LogTenant() (string, error) {

	logTenantUuid, err := uuid.FromBytes(ve.LogId)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("tenant/%s", logTenantUuid.String()), nil
}

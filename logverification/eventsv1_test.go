package logverification

import (
	"testing"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/stretchr/testify/assert"
)

// TestNewEventsV1ExtraBytes tests:
//
// 1. we get a valid extraBytes for an eventsv1 event
func TestNewEventsV1ExtraBytes(t *testing.T) {
	type args struct {
		originTenant string
	}
	tests := []struct {
		name        string
		args        args
		expected    []byte
		expectedLen int
		err         error
	}{
		{
			name: "positive",
			args: args{
				originTenant: "tenant/006e21d7-63d7-47bb-9a7e-0db55621317f",
			},
			expected: []byte{
				1,                                                                     // app domain
				0, 110, 33, 215, 99, 215, 71, 187, 154, 126, 13, 181, 86, 33, 49, 127, // 16 bytes for origin tenant uuid
				0, 0, 0, 0, 0, 0, 0, // 7 padded zeros
			},
			expectedLen: 24,
			err:         nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := NewEventsV1ExtraBytes(test.args.originTenant)

			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, actual)

			assert.Equal(t, test.expectedLen, len(actual))
		})
	}
}

// TestVerifiableEventsV1Event_LogTenant tests:
//
// 1. we get back a valid log tenant from the LogID
func TestVerifiableEventsV1Event_LogTenant(t *testing.T) {
	type fields struct {
		VerifiableLogEntry VerifiableLogEntry
	}
	tests := []struct {
		name     string
		fields   fields
		expected string
		err      error
	}{
		{
			name: "positive",
			fields: fields{
				VerifiableLogEntry: VerifiableLogEntry{
					LogId: []byte{0, 110, 33, 215, 99, 215, 71, 187, 154, 126, 13, 181, 86, 33, 49, 127}, // 006e21d7-63d7-47bb-9a7e-0db55621317f uuid
				},
			},
			expected: "tenant/006e21d7-63d7-47bb-9a7e-0db55621317f",
			err:      nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ve := &VerifiableEventsV1Event{
				VerifiableLogEntry: test.fields.VerifiableLogEntry,
			}
			actual, err := ve.LogTenant()

			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, actual)

		})
	}
}

// TestNewVerifiableEventsV1Event tests:
//
// 1. KAT test from test deployment for a committed eventsv1 event (inclusion verification previously tested to work)
func TestNewVerifiableEventsV1Event(t *testing.T) {

	eventJson := []byte(`
{
    "identity": "events/0193bb7f-e975-7007-95ad-4691e2b9c1f6",
    "attributes": {
        "5": "put in the over until golden brown",
        "1": "pour flour and milk into bowl",
        "2": "mix together until gloopy",
        "3": "slowly add in the sugar while still mixing",
        "4": "finally add in the eggs"
    },
    "trails": [
        "cake"
    ],
    "origin_tenant": "tenant/7e4a511f-d4ae-425c-b915-9c4ac09ca929",
    "created_by": "c152c19b-0bbe-4fdc-94bb-cd808d600a43",
    "created_at": 1734017542,
    "confirmation_status": "COMMITTED",
    "merklelog_commit": {
        "index": "16",
        "idtimestamp": "0193bb7feb86032500"
    }
}
	`)

	type args struct {
		eventJson []byte
		logTenant string
		opts      []VerifiableLogEntryOption
	}
	tests := []struct {
		name     string
		args     args
		expected *VerifiableEventsV1Event
		err      error
	}{
		{
			name: "positive",
			args: args{
				eventJson: eventJson,
				logTenant: "tenant/7e4a511f-d4ae-425c-b915-9c4ac09ca929",
			},
			expected: &VerifiableEventsV1Event{
				VerifiableLogEntry: VerifiableLogEntry{
					AppId: "events/0193bb7f-e975-7007-95ad-4691e2b9c1f6",
					LogId: []byte{126, 74, 81, 31, 212, 174, 66, 92, 185, 21, 156, 74, 192, 156, 169, 41}, // 7e4a511f-d4ae-425c-b915-9c4ac09ca929 uuid
					ExtraBytes: []byte{
						1,                                                                      // app domain
						126, 74, 81, 31, 212, 174, 66, 92, 185, 21, 156, 74, 192, 156, 169, 41, // 16 bytes for origin tenant uuid
						0, 0, 0, 0, 0, 0, 0, // 7 padded zeros
					},
					MMREntryFields: &MMREntryFields{
						Domain:          byte(0),
						SerializedBytes: []byte("222:{\"attributes\":{\"1\":\"pour flour and milk into bowl\",\"2\":\"mix together until gloopy\",\"3\":\"slowly add in the sugar while still mixing\",\"4\":\"finally add in the eggs\",\"5\":\"put in the over until golden brown\"},\"trails\":[\"cake\"]}"),
					},
					MerkleLogCommit: &assets.MerkleLogCommit{
						Index:       16,
						Idtimestamp: "0193bb7feb86032500",
					},
				},
			},
			err: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := NewVerifiableEventsV1Event(test.args.eventJson, test.args.logTenant, test.args.opts...)

			assert.Equal(t, test.err, err)

			// tests all the fields
			assert.Equal(t, test.expected.AppId, actual.AppId)
			assert.Equal(t, test.expected.LogId, actual.LogId)
			assert.Equal(t, test.expected.ExtraBytes, actual.ExtraBytes)
			assert.Equal(t, test.expected.MMREntryFields, actual.MMREntryFields)

			assert.Equal(t, test.expected.MerkleLogCommit.Idtimestamp, actual.MerkleLogCommit.Idtimestamp)
			assert.Equal(t, test.expected.MerkleLogCommit.Index, actual.MerkleLogCommit.Index)
		})
	}
}

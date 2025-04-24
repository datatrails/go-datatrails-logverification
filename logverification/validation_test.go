package logverification

import (
	"testing"

	"github.com/datatrails/go-datatrails-logverification/logverification/app"
	"github.com/datatrails/go-datatrails-simplehash/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-simplehash/simplehash"
	"github.com/stretchr/testify/assert"
)

func TestVerifiableEvent_Validate(t *testing.T) {
	type fields struct {
		appID           string
		logID           []byte
		mmrEntryFields  *app.MMREntryFields
		merkleLogCommit *assets.MerkleLogCommit
	}

	tests := []struct {
		name        string
		fields      fields
		expectedErr error
	}{
		{
			name: "valid input returns no error",
			fields: fields{
				appID:          "event/7189fa3d-9af1-40b1-975c-70f792142a82",
				logID:          []byte{0, 110, 33, 215, 99, 215, 71, 187, 154, 126, 13, 181, 86, 33, 49, 127}, // tenant/006e21d7-63d7-47bb-9a7e-0db55621317f
				mmrEntryFields: nil,
				merkleLogCommit: &assets.MerkleLogCommit{
					Index:       uint64(0),
					Idtimestamp: "018fa97ef269039b00",
				},
			},
			expectedErr: nil,
		},
		{
			name: "missing event identity returns specific error",
			fields: fields{
				appID:          "",
				logID:          []byte{0, 110, 33, 215, 99, 215, 71, 187, 154, 126, 13, 181, 86, 33, 49, 127}, // tenant/006e21d7-63d7-47bb-9a7e-0db55621317f
				mmrEntryFields: nil,
				merkleLogCommit: &assets.MerkleLogCommit{
					Index:       uint64(0),
					Idtimestamp: "018fa97ef269039b00",
				},
			},
			expectedErr: ErrNonEmptyAppIDRequired,
		},
		{
			name: "missing tenant identity returns specific error",
			fields: fields{
				appID:          "event/7189fa3d-9af1-40b1-975c-70f792142a82",
				logID:          []byte{},
				mmrEntryFields: nil,
				merkleLogCommit: &assets.MerkleLogCommit{
					Index:       uint64(0),
					Idtimestamp: "018fa97ef269039b00",
				},
			},
			expectedErr: ErrNonEmptyTenantIDRequired,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := app.NewAppEntry(
				tt.fields.appID,
				tt.fields.logID,
				tt.fields.mmrEntryFields,
				tt.fields.merkleLogCommit.Index)

			err := Validate(*e)
			assert.ErrorIs(t, err, tt.expectedErr)
		})
	}
}

func TestDecodedEvent_Validate(t *testing.T) {
	testPrincipal := map[string]any{
		"issuer":       "https://.soak.stage.datatrails.ai/appidpv1",
		"subject":      "e96dfa33-b645-4b83-a041-e87ac426c089",
		"display_name": "test",
		"email":        "test@test.datatrails.ai",
	}

	type fields struct {
		V3Event   simplehash.V3Event
		MerkleLog *assets.MerkleLogEntry
	}

	tests := []struct {
		name        string
		fields      fields
		expectedErr error
	}{
		{
			name: "valid input returns no error",
			fields: fields{
				V3Event: simplehash.V3Event{
					Identity:           "event/7189fa3d-9af1-40b1-975c-70f792142a82",
					TenantIdentity:     "tenant/7189fa3d-9af1-40b1-975c-70f792142a82",
					Operation:          "NewAsset",
					Behaviour:          "AssetCreator",
					TimestampDeclared:  "2024-03-14T23:24:50Z",
					TimestampAccepted:  "2024-03-14T23:24:50Z",
					TimestampCommitted: "2024-03-22T11:13:55.557Z",
					PrincipalDeclared:  testPrincipal,
					PrincipalAccepted:  testPrincipal,
				},
				MerkleLog: &assets.MerkleLogEntry{
					Commit: &assets.MerkleLogCommit{
						Index:       uint64(0),
						Idtimestamp: "018fa97ef269039b00",
					},
				},
			},
			expectedErr: nil,
		},
		{
			name: "missing event identity returns specific error",
			fields: fields{
				V3Event: simplehash.V3Event{
					Identity:           "",
					TenantIdentity:     "tenant/7189fa3d-9af1-40b1-975c-70f792142a82",
					Operation:          "NewAsset",
					Behaviour:          "AssetCreator",
					TimestampDeclared:  "2024-03-14T23:24:50Z",
					TimestampAccepted:  "2024-03-14T23:24:50Z",
					TimestampCommitted: "2024-03-22T11:13:55.557Z",
					PrincipalDeclared:  testPrincipal,
					PrincipalAccepted:  testPrincipal,
				},
				MerkleLog: &assets.MerkleLogEntry{
					Commit: &assets.MerkleLogCommit{
						Index:       uint64(0),
						Idtimestamp: "018fa97ef269039b00",
					},
				},
			},
			expectedErr: ErrNonEmptyEventIDRequired,
		},
		{
			name: "missing tenant identity returns specific error",
			fields: fields{
				V3Event: simplehash.V3Event{
					Identity:           "event/7189fa3d-9af1-40b1-975c-70f792142a82",
					TenantIdentity:     "",
					Operation:          "NewAsset",
					Behaviour:          "AssetCreator",
					TimestampDeclared:  "2024-03-14T23:24:50Z",
					TimestampAccepted:  "2024-03-14T23:24:50Z",
					TimestampCommitted: "2024-03-22T11:13:55.557Z",
					PrincipalDeclared:  testPrincipal,
					PrincipalAccepted:  testPrincipal,
				},
				MerkleLog: &assets.MerkleLogEntry{
					Commit: &assets.MerkleLogCommit{
						Index:       uint64(0),
						Idtimestamp: "018fa97ef269039b00",
					},
				},
			},
			expectedErr: ErrNonEmptyTenantIDRequired,
		},
		{
			name: "missing commit entry returns specific error",
			fields: fields{
				V3Event: simplehash.V3Event{
					Identity:           "event/7189fa3d-9af1-40b1-975c-70f792142a82",
					TenantIdentity:     "tenant/7189fa3d-9af1-40b1-975c-70f792142a82",
					Operation:          "NewAsset",
					Behaviour:          "AssetCreator",
					TimestampDeclared:  "2024-03-14T23:24:50Z",
					TimestampAccepted:  "2024-03-14T23:24:50Z",
					TimestampCommitted: "2024-03-22T11:13:55.557Z",
					PrincipalDeclared:  testPrincipal,
					PrincipalAccepted:  testPrincipal,
				},
				MerkleLog: &assets.MerkleLogEntry{},
			},
			expectedErr: ErrCommitEntryRequired,
		},
		{
			name: "missing idtimestamp returns specific error",
			fields: fields{
				V3Event: simplehash.V3Event{
					Identity:           "event/7189fa3d-9af1-40b1-975c-70f792142a82",
					TenantIdentity:     "tenant/7189fa3d-9af1-40b1-975c-70f792142a82",
					Operation:          "NewAsset",
					Behaviour:          "AssetCreator",
					TimestampDeclared:  "2024-03-14T23:24:50Z",
					TimestampAccepted:  "2024-03-14T23:24:50Z",
					TimestampCommitted: "2024-03-22T11:13:55.557Z",
					PrincipalDeclared:  testPrincipal,
					PrincipalAccepted:  testPrincipal,
				},
				MerkleLog: &assets.MerkleLogEntry{
					Commit: &assets.MerkleLogCommit{
						Index:       uint64(0),
						Idtimestamp: "",
					},
				},
			},
			expectedErr: ErrIdTimestampRequired,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &DecodedEvent{
				V3Event:   tt.fields.V3Event,
				MerkleLog: tt.fields.MerkleLog,
			}

			err := e.Validate()
			assert.ErrorIs(t, err, tt.expectedErr)
		})
	}
}

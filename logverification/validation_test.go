package logverification

import (
	"testing"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/datatrails/go-datatrails-simplehash/simplehash"
	"github.com/stretchr/testify/assert"
)

func TestVerifiableEvent_Validate(t *testing.T) {
	type fields struct {
		EventID   string
		TenantID  string
		LeafHash  []byte
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
				EventID:  "event/7189fa3d-9af1-40b1-975c-70f792142a82",
				TenantID: "tenant/7189fa3d-9af1-40b1-975c-70f792142a82",
				LeafHash: []byte("2091f2349925f93546c54d4140cdca5ab59213ef82daf665d81637260d022069"),
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
				EventID:  "",
				TenantID: "tenant/7189fa3d-9af1-40b1-975c-70f792142a82",
				LeafHash: []byte("2091f2349925f93546c54d4140cdca5ab59213ef82daf665d81637260d022069"),
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
				EventID:  "event/7189fa3d-9af1-40b1-975c-70f792142a82",
				TenantID: "",
				LeafHash: []byte("2091f2349925f93546c54d4140cdca5ab59213ef82daf665d81637260d022069"),
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
				EventID:   "event/7189fa3d-9af1-40b1-975c-70f792142a82",
				TenantID:  "tenant/7189fa3d-9af1-40b1-975c-70f792142a82",
				LeafHash:  []byte("2091f2349925f93546c54d4140cdca5ab59213ef82daf665d81637260d022069"),
				MerkleLog: &assets.MerkleLogEntry{},
			},
			expectedErr: ErrCommitEntryRequired,
		},
		{
			name: "missing idtimestamp returns specific error",
			fields: fields{
				EventID:  "event/7189fa3d-9af1-40b1-975c-70f792142a82",
				TenantID: "tenant/7189fa3d-9af1-40b1-975c-70f792142a82",
				LeafHash: []byte("2091f2349925f93546c54d4140cdca5ab59213ef82daf665d81637260d022069"),
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
			e := &VerifiableEvent{
				EventID:   tt.fields.EventID,
				TenantID:  tt.fields.TenantID,
				LeafHash:  tt.fields.LeafHash,
				MerkleLog: tt.fields.MerkleLog,
			}

			err := e.Validate()
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

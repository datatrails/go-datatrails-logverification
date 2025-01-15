package app

import (
	"testing"

	"github.com/datatrails/go-datatrails-common-api-gen/assets/v2/assets"
	"github.com/stretchr/testify/assert"
)

// TestNewAppEntry tests:
//
// 1. we can get all non derived fields for the app entry getter
func TestNewAppEntry(t *testing.T) {
	type args struct {
		appId           string
		logId           []byte
		extraBytes      []byte
		mmrEntryFields  *MMREntryFields
		merklelogCommit *assets.MerkleLogCommit
	}
	tests := []struct {
		name     string
		args     args
		expected *AppEntry
	}{
		{
			name: "positive",
			args: args{
				appId: "events/1234",
				logId: []byte("1234"),
				extraBytes: []byte{
					0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0,
				}, // 24 bytes long
				mmrEntryFields: &MMREntryFields{
					domain:          0,
					serializedBytes: []byte("its a me, an app entry"),
				},
				merklelogCommit: &assets.MerkleLogCommit{
					Index:       16,
					Idtimestamp: "0x1234",
				},
			},
			expected: &AppEntry{
				appID: "events/1234",
				logID: []byte("1234"),
				extraBytes: []byte{
					0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 0,
				}, // 24 bytes long
				mmrEntryFields: &MMREntryFields{
					domain:          0,
					serializedBytes: []byte("its a me, an app entry"),
				},
				merkleLogCommit: &assets.MerkleLogCommit{
					Index:       16,
					Idtimestamp: "0x1234",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := NewAppEntry(
				test.args.appId,
				test.args.logId,
				test.args.extraBytes,
				test.args.mmrEntryFields,
				test.args.merklelogCommit,
			)

			appEntryGetter := AppEntryGetter(actual)

			assert.Equal(t, test.expected.appID, appEntryGetter.AppID())
			assert.Equal(t, test.expected.logID, appEntryGetter.LogID())
			assert.Equal(t, test.expected.extraBytes, appEntryGetter.ExtraBytes())

			// mmr entry fields
			assert.Equal(t, test.expected.mmrEntryFields.domain, appEntryGetter.Domain())
			assert.Equal(t, test.expected.mmrEntryFields.serializedBytes, appEntryGetter.SerializedBytes())

			// merklelog commit
			assert.Equal(t, test.expected.merkleLogCommit.Index, appEntryGetter.MMRIndex())
			assert.Equal(t, test.expected.merkleLogCommit.Idtimestamp, appEntryGetter.IDTimestamp())

		})
	}
}

// TestAppEntry_MMREntry tests:
//
// 1. Known Answer Test (KAT) for mmr entry for log version 1
func TestAppEntry_MMREntry(t *testing.T) {
	type fields struct {
		extraBytes      []byte
		mmrEntryFields  *MMREntryFields
		merkleLogCommit *assets.MerkleLogCommit
	}
	tests := []struct {
		name     string
		fields   fields
		expected []byte
		err      error
	}{
		// TODO: Add test cases.
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			ae := &AppEntry{
				extraBytes:      test.fields.extraBytes,
				mmrEntryFields:  test.fields.mmrEntryFields,
				merkleLogCommit: test.fields.merkleLogCommit,
			}
			actual, err := ae.MMREntry()

			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

// TestAppEntry_MMRIndex tests:
//
// 1. an index > 0 returns that index.
// 2. an index == 0 returns 0.
// 3. a nil merklelog commit returns 0.
func TestAppEntry_MMRIndex(t *testing.T) {
	type fields struct {
		merkleLogCommit *assets.MerkleLogCommit
	}
	tests := []struct {
		name     string
		fields   fields
		expected uint64
	}{
		{
			name: "non 0 index",
			fields: fields{
				merkleLogCommit: &assets.MerkleLogCommit{
					Index: 176,
				},
			},
			expected: 176,
		},
		{
			name: "0 index",
			fields: fields{
				merkleLogCommit: &assets.MerkleLogCommit{
					Index: 0,
				},
			},
			expected: 0,
		},
		{
			name: "nil merklelog commit",
			fields: fields{
				merkleLogCommit: nil,
			},
			expected: 0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			ae := &AppEntry{
				merkleLogCommit: test.fields.merkleLogCommit,
			}

			actual := ae.MMRIndex()

			assert.Equal(t, test.expected, actual)
		})
	}
}

// TestAppEntry_IDTimestamp tests:
//
// 1. a non empty idtimestamp returns that idtimestamp.
// 2. an empty idtimestamp returns "".
// 3. a nil merklelog commit returns "".
func TestAppEntry_IDTimestamp(t *testing.T) {
	type fields struct {
		merkleLogCommit *assets.MerkleLogCommit
	}
	tests := []struct {
		name     string
		fields   fields
		expected string
	}{
		{
			name: "non empty idtimestamp",
			fields: fields{
				merkleLogCommit: &assets.MerkleLogCommit{
					Idtimestamp: "0x1234",
				},
			},
			expected: "0x1234",
		},
		{
			name: "empty idtimestamp",
			fields: fields{
				merkleLogCommit: &assets.MerkleLogCommit{
					Idtimestamp: "",
				},
			},
			expected: "",
		},
		{
			name: "nil merklelog commit",
			fields: fields{
				merkleLogCommit: nil,
			},
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			ae := &AppEntry{
				merkleLogCommit: test.fields.merkleLogCommit,
			}

			actual := ae.IDTimestamp()

			assert.Equal(t, test.expected, actual)
		})
	}
}

// TestAppEntry_MMRSalt tests:
//
// 1. Known Answer Test for MMRSalt for log version 0.
// 2. Boundary overflow test for mmr salt values higher than 24 bytes
// 3. Boundary underflow test for mmr salt values lower than 24 bytes
func TestAppEntry_MMRSalt(t *testing.T) {
	type fields struct {
		extraBytes      []byte
		merkleLogCommit *assets.MerkleLogCommit
	}
	tests := []struct {
		name     string
		fields   fields
		expected []byte
		err      error
	}{
		{
			name: "positive kat",
			fields: fields{
				extraBytes: []byte{
					1, // app domain
					1, 2, 3, 4, 5, 6, 7, 8,
					1, 2, 3, 4, 5, 6, 7, 8,
					1, 2, 3, 4, 5, 6, 7, // 23 remaining bytes
				},
				merkleLogCommit: &assets.MerkleLogCommit{
					Idtimestamp: "0x01931acb7b14043b00",
				},
			},
			expected: []byte{
				0x1, // app domain
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, // remaining bytes
				0x93, 0x1a, 0xcb, 0x7b, 0x14, 0x4, 0x3b, 0x0, // idtimestamp
			},
		},
		{
			name: "extrabyte overflow boundary",
			fields: fields{
				extraBytes: []byte{
					1, // app domain
					1, 2, 3, 4, 5, 6, 7, 8,
					1, 2, 3, 4, 5, 6, 7, 8,
					1, 2, 3, 4, 5, 6, 7, 8, // 24 remaining bytes (overflow by 1 byte)
				},
				merkleLogCommit: &assets.MerkleLogCommit{
					Idtimestamp: "0x01931acb7b14043b00",
				},
			},
			expected: []byte{
				0x1, // app domain
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, // remaining bytes
				0x93, 0x1a, 0xcb, 0x7b, 0x14, 0x4, 0x3b, 0x0, // idtimestamp
			},
		},
		{
			name: "extrabyte underflow boundary",
			fields: fields{
				extraBytes: []byte{
					1, // app domain
					1, 2, 3, 4, 5, 6, 7, 8,
					1, 2, 3, 4, 5, 6, 7, 8,
					1, 2, 3, 4, 5, 6, // 22 remaining bytes (undeflow by 1 byte)
				},
				merkleLogCommit: &assets.MerkleLogCommit{
					Idtimestamp: "0x01931acb7b14043b00",
				},
			},
			expected: []byte{
				0x1, // app domain
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x0, // remaining bytes (expect last byte to be padded)
				0x93, 0x1a, 0xcb, 0x7b, 0x14, 0x4, 0x3b, 0x0, // idtimestamp
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ae := &AppEntry{
				extraBytes:      test.fields.extraBytes,
				merkleLogCommit: test.fields.merkleLogCommit,
			}

			actual, err := ae.MMRSalt()

			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

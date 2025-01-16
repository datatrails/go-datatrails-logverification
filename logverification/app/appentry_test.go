package app

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testMassifContext generates a massif context with 2 entries
//
// the first entry is a known log version 0 entry
// the seconds entry is a known log version 1 entry
//
// TODO: Add actual KAT data
func testMassifContext(t *testing.T) *massifs.MassifContext {

	start := massifs.MassifStart{
		MassifHeight: 3,
	}

	testMassifContext := &massifs.MassifContext{
		Start: start,
		LogBlobContext: massifs.LogBlobContext{
			BlobPath: "test",
			Tags:     map[string]string{},
		},
	}

	data, err := start.MarshalBinary()
	require.NoError(t, err)

	testMassifContext.Data = append(data, testMassifContext.InitIndexData()...)

	testMassifContext.Tags["firstindex"] = fmt.Sprintf("%016x", testMassifContext.Start.FirstIndex)

	hasher := sha256.New()

	// KAT Data taken from an actual merklelog.

	// Log Version 0 (AssetsV2)
	_, err = testMassifContext.AddHashedLeaf(
		hasher,
		binary.BigEndian.Uint64([]byte{148, 111, 227, 95, 198, 1, 121, 0}),
		[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		[]byte("tenant/112758ce-a8cb-4924-8df8-fcba1e31f8b0"),
		[]byte("assets/899e00a2-29bc-4316-bf70-121ce2044472/events/450dce94-065e-4f6a-bf69-7b59f28716b6"),
		[]byte{97, 231, 1, 42, 127, 20, 181, 70, 122, 134, 84, 231, 174, 117, 200, 148, 171, 205, 57, 146, 174, 48, 34, 30, 152, 215, 77, 3, 204, 14, 202, 57},
	)
	require.NoError(t, err)

	// Log Version 1 (EventsV1)
	_, err = testMassifContext.AddHashedLeaf(
		hasher,
		binary.BigEndian.Uint64([]byte{148, 112, 0, 54, 17, 1, 121, 0}),
		[]byte{1, 17, 39, 88, 206, 168, 203, 73, 36, 141, 248, 252, 186, 30, 49, 248, 176, 0, 0, 0, 0, 0, 0, 0},
		[]byte("tenant/112758ce-a8cb-4924-8df8-fcba1e31f8b0"),
		[]byte("events/01947000-3456-780f-bfa9-29881e3bac88"),
		[]byte{215, 191, 107, 210, 134, 10, 40, 56, 226, 71, 136, 164, 9, 118, 166, 159, 86, 31, 175, 135, 202, 115, 37, 151, 174, 118, 115, 113, 25, 16, 144, 250},
	)
	require.NoError(t, err)

	// Intermediate Node Skipped

	return testMassifContext
}

// TODO: Test inclusion proofs using the AppEntry methods with the KAT data.

// TestNewAppEntry tests:
//
// 1. we can get all non derived fields for the app entry getter
func TestNewAppEntry(t *testing.T) {
	type args struct {
		appId          string
		logId          []byte
		mmrEntryFields *MMREntryFields
		mmrIndex       uint64
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
				mmrEntryFields: &MMREntryFields{
					domain:          0,
					serializedBytes: []byte("its a me, an app entry"),
				},
				mmrIndex: 16,
			},
			expected: &AppEntry{
				appID: "events/1234",
				logID: []byte("1234"),
				mmrEntryFields: &MMREntryFields{
					domain:          0,
					serializedBytes: []byte("its a me, an app entry"),
				},
				mmrIndex: 16,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := NewAppEntry(
				test.args.appId,
				test.args.logId,
				test.args.mmrEntryFields,
				test.args.mmrIndex,
			)

			assert.Equal(t, test.expected.appID, actual.AppID())
			assert.Equal(t, test.expected.logID, actual.LogID())

			// mmr entry fields
			assert.Equal(t, test.expected.mmrEntryFields.domain, actual.Domain())
			assert.Equal(t, test.expected.mmrEntryFields.serializedBytes, actual.SerializedBytes())

			// mmr index
			assert.Equal(t, test.expected.mmrIndex, actual.MMRIndex())

		})
	}
}

// TestAppEntry_MMRSalt tests:
//
// 1. Known Answer Test for MMRSalt for log version 1.
func TestAppEntry_MMRSalt(t *testing.T) {

	testMassifContext := testMassifContext(t)

	type fields struct {
		mmrIndex uint64
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
				mmrIndex: 0,
			},
			expected: []byte{
				0x1, // app domain
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, // remaining bytes
				0x93, 0x1a, 0xcb, 0x7b, 0x14, 0x4, 0x3b, 0x0, // idtimestamp
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ae := &AppEntry{
				mmrIndex: test.fields.mmrIndex,
			}

			actual, err := ae.MMRSalt(testMassifContext)

			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

package app

import (
	"crypto/sha256"
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

	idtimestampStr := "0x01931acb7b14043b00"

	// convert idtimestamp from bytes to uint64
	idTimestamp, _, err := massifs.SplitIDTimestampHex(idtimestampStr)
	require.NoError(t, err)

	extraBytes := []byte{1, // app domain
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7} // 23 remaining bytes

	mmrEntry := []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, // 32 byte hash
	}

	_, err = testMassifContext.AddHashedLeaf(hasher, idTimestamp, extraBytes, []byte("test"), []byte("events/1234"), mmrEntry)
	require.NoError(t, err)

	return testMassifContext
}

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

			appEntryGetter := AppEntryGetter(actual)

			assert.Equal(t, test.expected.appID, appEntryGetter.AppID())
			assert.Equal(t, test.expected.logID, appEntryGetter.LogID())

			// mmr entry fields
			assert.Equal(t, test.expected.mmrEntryFields.domain, appEntryGetter.Domain())
			assert.Equal(t, test.expected.mmrEntryFields.serializedBytes, appEntryGetter.SerializedBytes())

			// mmr index
			assert.Equal(t, test.expected.mmrIndex, appEntryGetter.MMRIndex())

		})
	}
}

// TestAppEntry_MMRSalt tests:
//
// 1. Known Answer Test for MMRSalt for log version 0.
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

			actual, err := ae.MMRSalt(WithMassifContext(testMassifContext))

			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

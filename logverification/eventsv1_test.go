package logverification

import (
	"testing"

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

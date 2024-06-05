package logverification

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogVersion0Hash tests:
//
// 1. known answer test (KAT) for generating the hash of a test event.
func TestLogVersion0Hash(t *testing.T) {
	type args struct {
		eventJson []byte
	}
	tests := []struct {
		name     string
		args     args
		expected []byte
		err      error
	}{
		{
			name: "positive (kat)",
			args: args{
				eventJson: []byte(testEventJson),
			},
			expected: []byte{117, 200, 223, 187, 85, 37, 16, 136, 187, 12, 16, 215, 5, 98, 144, 115, 43, 22, 136, 203, 199, 129, 140, 125, 143, 252, 92, 83, 186, 100, 230, 149},
			err:      nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hasher := LogVersion0Hasher{}
			actual, err := hasher.HashEvent(test.args.eventJson)

			hexString := hex.EncodeToString(actual)
			assert.NotNil(t, hexString)

			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}

package logverification

import (
	"errors"
	"testing"

	"github.com/datatrails/go-datatrails-merklelog/massifs"
	"github.com/stretchr/testify/assert"
)

// Test_handleMassifIndexErr tests:
//
// 1. don't suppress NotLeaf errors, error argument, return error.
// 2. don't suppress NotLeaf errors, NotLeaf error argument, return error.
// 3. don't suppress NotLeaf errors, no error argument, return no error.
// 4. suppress NotLeaf errors, error argument, return error.
// 5. suppress NotLeaf errors, NotLeaf error argument, return no error.
// 6. suppress NotLeaf errors, no error argument, return no error.
func Test_handleMassifIndexErr(t *testing.T) {

	mockErr := errors.New("mock error")

	type args struct {
		err         error
		nonLeafNode bool
	}
	tests := []struct {
		name string
		args args
		err  error
	}{
		{
			name: "allow NotLeaf errors, error argument",
			args: args{
				mockErr,
				false,
			},
			err: mockErr,
		},
		{
			name: "allow NotLeaf errors, NotLeaf error argument",
			args: args{
				massifs.ErrNotleaf,
				false,
			},
			err: massifs.ErrNotleaf,
		},
		{
			name: "allow NotLeaf errors, no error argument",
			args: args{
				nil,
				false,
			},
			err: nil,
		},
		{
			name: "suppress NotLeaf errors, error argument",
			args: args{
				mockErr,
				true,
			},
			err: mockErr,
		},
		{
			name: "suppress NotLeaf errors, NotLeaf error argument",
			args: args{
				massifs.ErrNotleaf,
				true,
			},
			err: nil,
		},
		{
			name: "suppress NotLeaf errors, no error argument",
			args: args{
				nil,
				true,
			},
			err: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := handleMassifIndexErr(test.args.err, test.args.nonLeafNode)

			assert.Equal(t, test.err, err)
		})
	}
}

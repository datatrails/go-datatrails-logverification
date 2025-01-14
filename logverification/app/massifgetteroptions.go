package app

import (
	"github.com/datatrails/go-datatrails-common/azblob"
	"github.com/datatrails/go-datatrails-merklelog/massifs"
)

/**
 * Massif Options for the App are how the App Entries retrieve the correct massif to get data from their corresponding log entry.
 */

// MassifGetterOptions how an app entry retrieves its massif
type MassifGetterOptions struct {
	*MassifOptions

	azblobReader azblob.Reader

	massifGetter MassifGetter

	massifContext *massifs.MassifContext
}

type MassifGetterOption func(*MassifGetterOptions)

// WithMassifContext is an option that ensures the app entry uses the given
//
//	massif context
func WithMassifContext(massifContext *massifs.MassifContext) MassifGetterOption {
	return func(mo *MassifGetterOptions) { mo.massifContext = massifContext }
}

// WithMassifReader is an option that ensures the given massif reader is used
// to obtain the massif for the app entry.
func WithMassifReader(massifReader MassifGetter, massifOpts ...MassifOption) MassifGetterOption {
	return func(mo *MassifGetterOptions) {
		mo.massifGetter = massifReader
		opts := ParseMassifOptions(massifOpts...)
		mo.MassifOptions = &opts
	}
}

// WithAzBlobReader is an option that ensures the given azblob reader is used
// to obtain the massif for the app entry.
func WithAzblobReader(azblobReader azblob.Reader, massifOpts ...MassifOption) MassifGetterOption {
	return func(mo *MassifGetterOptions) {
		mo.azblobReader = azblobReader
		opts := ParseMassifOptions(massifOpts...)
		mo.MassifOptions = &opts
	}
}

// ParseMassifGetterOptions parses the given options into a MassifGetterOptions struct
func ParseMassifGetterOptions(options ...MassifGetterOption) MassifGetterOptions {
	massifOptions := MassifGetterOptions{
		MassifOptions: &MassifOptions{
			NonLeafNode:  false,               // default to erroring on non leaf nodes
			MassifHeight: DefaultMassifHeight, // set the default massif height first
		},
	}

	for _, option := range options {
		option(&massifOptions)
	}

	return massifOptions
}

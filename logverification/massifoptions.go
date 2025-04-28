package logverification

type MassifOptions struct {

	// NonLeafNode is an optional suppression
	//
	//	of errors that occur due to attempting to get
	//  a massif based on a non leaf node mmrIndex.
	NonLeafNode bool

	// TenantId is an optional tenant ID to use instead
	//  of the TenantId found on the eventJson.
	TenantId string

	// MassifHeight is an optional massif height for the massif
	//  instead of the default.
	MassifHeight uint8
}

type MassifOption func(*MassifOptions)

// WithNonLeafNode is an optional suppression
//
//	of errors that occur due to attempting to get
//	a massif based on a non leaf node mmrIndex.
func WithNonLeafNode(nonLeafNode bool) MassifOption {
	return func(mo *MassifOptions) { mo.NonLeafNode = nonLeafNode }
}

// WithMassifTenantId is an optional tenant ID to use instead
//
//	of the tenantId found on the eventJson.
func WithMassifTenantId(tenantId string) MassifOption {
	return func(mo *MassifOptions) { mo.TenantId = tenantId }
}

// WithMassifHeight is an optional massif height for the massif
//
//	instead of the default.
func WithMassifHeight(massifHeight uint8) MassifOption {
	return func(mo *MassifOptions) { mo.MassifHeight = massifHeight }
}

// ParseMassifOptions parses the given options into a MassifOptions struct
func ParseMassifOptions(options ...MassifOption) MassifOptions {
	massifOptions := MassifOptions{
		NonLeafNode:  false,               // default to erroring on non leaf nodes
		MassifHeight: DefaultMassifHeight, // set the default massif height first
	}

	for _, option := range options {
		option(&massifOptions)
	}

	return massifOptions
}

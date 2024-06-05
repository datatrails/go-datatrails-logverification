package logverification

type VerifyOptions struct {

	// tenantId is an optional tenant ID to use instead
	//  of the tenantId found on the eventJson.
	tenantId string
}

type VerifyOption func(*VerifyOptions)

// WithTenantId is an optional tenant ID to use instead
//
//	of the tenantId found on the eventJson.
func WithTenantId(tenantId string) VerifyOption {
	return func(vo *VerifyOptions) { vo.tenantId = tenantId }
}

// ParseOptions parses the given options into a VerifyOptions struct
func ParseOptions(options ...VerifyOption) VerifyOptions {
	verifyOptions := VerifyOptions{}

	for _, option := range options {
		option(&verifyOptions)
	}

	return verifyOptions
}

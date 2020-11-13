package conditions

// Condition is a predicate condition on a credential attribute.
type Condition struct {
	Op              string          `json:"op"`
	CredentialValue CredentialValue `json:"credentialValue"`
	ComparisonValue ComparisonValue `json:"comparisonValue"`
	FailureMessage  string          `json:"failureMessage"`
}

// CredentialValue is an AST node that represents data on the credential.
type CredentialValue struct {
	Data     string `json:"data,omitempty"`
	Metadata string `json:"metadata,omitempty"`
}

// ComparisonValue is an AST node representing a value we're going to compare with:
// a constant, a variable, a moment in time or a calendar date.
type ComparisonValue struct {
	Constant interface{} `json:"constant,omitempty" `
	Variable string      `json:"variable,omitempty"`
}

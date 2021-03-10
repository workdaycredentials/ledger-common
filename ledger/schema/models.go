package schema

import (
	"fmt"

	"go.wday.io/credentials-open-source/ledger-common/ledger"
)

// wrapper around modified semantic version where only major and minor numbers are valid
type Version struct {
	Major int
	Minor int
}

type UpdateResult struct {
	Valid          bool
	MajorChange    bool
	MinorChange    bool
	DerivedVersion string
	Message        string
}

type UpdateInput struct {
	UpdatedSchema            *ledger.Schema
	UpdatedSchemaCategoryID  string
	PreviousSchema           *ledger.Schema
	PreviousSchemaCategoryID string
}

// IDFormatErr is a formatting error in the Schema ID, which should be in the form <author_did>;id=<uuid>;version=<major.minor>.
type IDFormatErr struct {
	schemaID string
}

func (e IDFormatErr) Error() string {
	return fmt.Sprintf("'%s' schema id is in an unrecognized format", e.schemaID)
}

// UnRecognisedVersionError is a formatting error in the Schema version, which should be in the form "major.minor".
type UnRecognisedVersionError struct {
	submittedVersion string
}

func (e UnRecognisedVersionError) Error() string {
	return fmt.Sprintf("'%s' is an unrecognized version format", e.submittedVersion)
}

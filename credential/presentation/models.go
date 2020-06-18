package presentation

import (
	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/proof"
)

// Presentation is a cryptographically signed set of Verifiable Credentials that are returned
// in response to a Proof Request.  Each claim in a Verifiable Credential is signed using a
// Claim Proof.  This allows for the user to selectively disclose individual claims without
// revealing the entire credential. The current structure does not allow for whole, signed
// credentials, like one would find in the W3C Verifiable Credentials Data Model.
type Presentation struct {
	UnsignedPresentation
	Proof []proof.Proof `json:"proof"`
}

// UnsignedPresentation is a set of Verifiable Credentials that will be returned in response to a
// Proof Request.  Each claim in a Verifiable Credential is signed using a Claim Proof; however,
// the overall set of credentials is unsigned.
type UnsignedPresentation struct {
	Context      []string                    `json:"@context"`
	ID           string                      `json:"id"`
	Type         []string                    `json:"type"`
	ModelVersion string                      `json:"modelVersion,omitempty"`
	Created      string                      `json:"created"`
	Credentials  []credential.VersionedCreds `json:"verifiableCredential"`
}

///////////// Platform use only /////////////

// Composite presentations

// Criterion is a data challenge for credentials of a particular schema type.  Only credentials
// that match the schema and predicate conditions can be included in the challenge response.
// Additionally, the criterion can optionally place restrictions on the credential Issuers and
// the minimum/maximum number of credentials that must/can be supplied.
type Criterion struct {
	Description string      `json:"description"`
	Reason      string      `json:"reason"`
	Issuers     Issuers     `json:"issuers"`
	MaxRequired int         `json:"max"`
	MinRequired int         `json:"min"`
	AllowExpired *bool      `json:"allowExpired,omitempty"`
	Schema      SchemaReq   `json:"schema"`
	Conditions  []Condition `json:"conditions,omitempty"`
}

type Issuers struct {
	DIDs            []string         `json:"dids,omitempty"`
}

// SchemaReq identifies a schema and defines the collection of attributes that are being requested
// in the Criterion. The Verifier is discouraged from requesting attributes that are unnecessary to
// the context of the interaction with the Holder.
type SchemaReq struct {
	//deprecated
	SchemaID           string         `json:"id"`
	AuthorDID          string         `json:"did,omitempty"`
	ResourceIdentifier string         `json:"resource,omitempty"`
	SchemaVersionRange string         `json:"version,omitempty"`
	Attributes         []AttributeReq `json:"attributes"`
}

// AttributeReq is a request for a particular attribute, which can either be required or optional.
// In order for a credential to match the criterion, all required attributes must be included in the
// credential.  The Holder may choose to include optional attributes at their discretion.
type AttributeReq struct {
	AttributeName string `json:"name"`
	Required      bool   `json:"required"`
}

// PostCompositeProofRequestRequest is an request payload for POST'ing a Composite Proof Request
// definition into the Workday Platform.
type PostCompositeProofRequestRequest struct {
	PlatformProofRequestMetadata
	CompositeProofRequest
}

type PlatformProofRequestMetadata struct {
	UserID string `json:"userId"`
	Name   string `json:"name"`
	// TODO add client id
	// ClientID	string `json:"clientId`
	CallbackURL string `json:"callbackURL"`
}

type ProofReqRespMetadata struct {
	Type         string `json:"type,omitempty"`
	ModelVersion string `json:"modelVersion,omitempty"`
	ID           string `json:"id,omitempty"`
}

// GetCompositeProofRequestRequestResponse is a response payload for GET'ing a
// Composite Proof Request that has been stored in the platform.
type GetCompositeProofRequestRequestResponse struct {
	Data CompositeProofRequestRecordDataHolder `json:"data"`
}

type CompositeProofRequestRecordDataHolder struct {
	CompositeProofRequest CompositeProofRequestRecord `json:"compositeProofRequest"`
}

type UnsignedCompositeProofRequestInstanceChallenge struct {
	ProofRequestInstanceID string                            `json:"proofRequestInstanceId"`
	ProofResponseURL       string                            `json:"proofURL"`
	ProofRequest           *CompositeProofRequest            `json:"proofRequest"`
	SupportingCredentials  []credential.VerifiableCredential `json:"supportingCredentials,omitempty"`
	Variables              map[string]interface{}            `json:"variables,omitempty"`
}

type CompositeProofRequestInstanceChallenge struct {
	UnsignedCompositeProofRequestInstanceChallenge
	Proof proof.Proof `json:"proof"`
}

type CompositeProofRequest struct {
	ProofReqRespMetadata
	Description string      `json:"description"`
	Verifier    string      `json:"verifier"`
	Criteria    []Criterion `json:"criteria"`
}

type CompositeProofRequestRecord struct {
	ID          string `json:"id"`
	CreatedDate string `json:"createdDate"`
	UpdatedDate string `json:"updatedDate"`
	PlatformProofRequestMetadata
	CompositeProofRequest
}

// Submission

type ProofResponseSubmission struct {
	ProofRequestInstanceId string         `json:"proofRequestInstanceId"`
	Presentations          []Presentation `json:"Presentations"`
}

type UnsignedCompositeProofResponseSubmission struct {
	ProofReqRespMetadata
	ProofRequestInstanceID string               `json:"proofRequestInstanceId"`
	FulfilledCriteria      []FulfilledCriterion `json:"FulfilledCriteria"`
}

type CompositeProofResponseSubmission struct {
	UnsignedCompositeProofResponseSubmission
	Proof []proof.Proof `json:"proof"`
}

// FulfilledCriterion holds a request Criterion and the list of all Proof Presentations that
// fulfilled that Criterion.
type FulfilledCriterion struct {
	Criterion     Criterion      `json:"Criterion"`
	Presentations []Presentation `json:"Presentations"`
}

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

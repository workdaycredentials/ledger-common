package presentation

import (
	"go.wday.io/credentials-open-source/ledger-common/credential"
	"go.wday.io/credentials-open-source/ledger-common/credential/presentation/conditions"
	"go.wday.io/credentials-open-source/ledger-common/did"
	"go.wday.io/credentials-open-source/ledger-common/proof"
)

// Presentation is a cryptographically signed set of Verifiable Credentials that are returned
// in response to a Proof Request.  Each claim in a Verifiable Credential is signed using a
// Claim Proof.  This allows for the user to selectively disclose individual claims without
// revealing the entire credential. The current structure does not allow for whole, signed
// credentials, like one would find in the W3C Verifiable Credentials Data Model.
type Presentation struct {
	Context      []string                   `json:"@context"`
	ID           string                     `json:"id"`
	Type         []string                   `json:"type"`
	ModelVersion string                     `json:"modelVersion,omitempty"`
	Created      string                     `json:"created"`
	Credentials  []credential.RawCredential `json:"verifiableCredential"`
	Proof        []*proof.Proof             `json:"proof,omitempty"`
}

// These methods assume a single proof.
func (p *Presentation) GetProof() *proof.Proof {
	if len(p.Proof) == 0 {
		return nil
	}
	return p.Proof[0]
}

func (p *Presentation) SetProof(pr *proof.Proof) {
	if pr == nil {
		p.Proof = nil
		return
	}
	if len(p.Proof) == 0 {
		p.Proof = make([]*proof.Proof, 1)
	}
	p.Proof[0] = pr
}

// /////////// Platform use only /////////////

// Composite presentations

// Criterion is a data challenge for credentials of a particular schema type.  Only credentials
// that match the schema and predicate conditions can be included in the challenge response.
// Additionally, the criterion can optionally place restrictions on the credential Issuers and
// the minimum/maximum number of credentials that must/can be supplied.
type Criterion struct {
	Description  string                 `json:"description"`
	Reason       string                 `json:"reason"`
	Issuers      Issuers                `json:"issuers"`
	MaxRequired  int                    `json:"max"`
	MinRequired  int                    `json:"min"`
	AllowExpired *bool                  `json:"allowExpired,omitempty"`
	Schema       SchemaReq              `json:"schema"`
	Conditions   []conditions.Condition `json:"conditions,omitempty"`
}

type Issuers struct {
	DIDs []did.DID `json:"dids,omitempty"`
}

// SchemaReq identifies a schema and defines the collection of attributes that are being requested
// in the Criterion. The Verifier is discouraged from requesting attributes that are unnecessary to
// the context of the interaction with the Holder.
type SchemaReq struct {
	// deprecated
	SchemaID           string         `json:"id"`
	AuthorDID          did.DID        `json:"did,omitempty"`
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
	CallbackURL did.URI `json:"callbackURL"`
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

type CompositeProofRequestInstanceChallenge struct {
	ProofRequestInstanceID string                 `json:"proofRequestInstanceId"`
	ProofResponseURL       string                 `json:"proofURL"`
	ProofRequest           *CompositeProofRequest `json:"proofRequest"`
	ConditionVariables     map[string]interface{} `json:"variables,omitempty"`
	Proof                  *proof.Proof           `json:"proof,omitempty"`
}

func (c *CompositeProofRequestInstanceChallenge) GetProof() *proof.Proof {
	return c.Proof
}

func (c *CompositeProofRequestInstanceChallenge) SetProof(p *proof.Proof) {
	c.Proof = p
}

type CompositeProofRequest struct {
	ProofReqRespMetadata
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Verifier    did.DID     `json:"verifier"`
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
	ProofRequestInstanceID string         `json:"proofRequestInstanceId"`
	Presentations          []Presentation `json:"Presentations"`
}

type CompositeProofResponseSubmission struct {
	ProofReqRespMetadata
	ProofRequestInstanceID string               `json:"proofRequestInstanceId"`
	FulfilledCriteria      []FulfilledCriterion `json:"FulfilledCriteria"`
	Proof                  []*proof.Proof       `json:"proof,omitempty"`
}

// These methods assume a single proof.
func (c *CompositeProofResponseSubmission) GetProof() *proof.Proof {
	if len(c.Proof) == 0 {
		return nil
	}
	return c.Proof[0]
}

func (c *CompositeProofResponseSubmission) SetProof(pr *proof.Proof) {
	if pr == nil {
		c.Proof = nil
		return
	}
	if len(c.Proof) == 0 {
		c.Proof = make([]*proof.Proof, 1)
	}
	c.Proof[0] = pr
}

// FulfilledCriterion holds a request Criterion and the list of all Proof Presentations that
// fulfilled that Criterion.
type FulfilledCriterion struct {
	Criterion     Criterion      `json:"Criterion"`
	Presentations []Presentation `json:"Presentations"`
}

// CriteriaHolder holds a Criterion, the index of that Criterion in the underlying
// CompositeProofRequest where the it was specified, and the set of variables used in any conditions.
type CriteriaHolder struct {
	Index     int
	Criterion Criterion
	Variables map[string]interface{}
}

// GetSchema returns the schema ID.
func (c *CriteriaHolder) GetSchema() string {
	return c.Criterion.Schema.SchemaID
}

// GetFields returns schema attributes.
func (c *CriteriaHolder) GetFields() []AttributeReq {
	return c.Criterion.Schema.Attributes
}

// GetDescription returns  the criterion description.
func (c *CriteriaHolder) GetDescription() string {
	return c.Criterion.Description
}

// GetMaxCreds returns the maximum number of credentials that can be submitted for this criterion.
func (c *CriteriaHolder) GetMaxCreds() int {
	maxReq := c.Criterion.MaxRequired
	return maxReq
}

// GetMinCreds returns the minimum number of credentials that must be submitted for this criterion.
func (c *CriteriaHolder) GetMinCreds() int {
	minReq := c.Criterion.MinRequired
	return minReq
}

// CanFulfill checks whether a cred can satisfy a request
func (c *CriteriaHolder) CanFulfill(cred credential.VerifiableCredential) bool {
	return CheckVCMatchesCriterion(c.Criterion, cred, c.Variables) == nil
}

// GetAuthorDID returns the schema author's decentralized identifier.
func (c *CriteriaHolder) GetAuthorDID() did.DID {
	return c.Criterion.Schema.AuthorDID
}

// GetResourceID returns the schema resource ID.
func (c *CriteriaHolder) GetResourceID() string {
	return c.Criterion.Schema.ResourceIdentifier
}

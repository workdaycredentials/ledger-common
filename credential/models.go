package credential

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/ledger"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

const (
	ModelVersionV1     = "1.0"
	W3Context          = "https://www.w3.org/2018/credentials/v1"
	Type               = "VerifiableCredential"
	SchemaType         = "JsonSchemaValidatorWorkday2019"
	RevocationType     = "WorkdayRevocation2020"
	SubjectIDAttribute = "id"
	credentialSubject  = "credentialSubject"
	claimProofs        = "claimProofs"
)

// VerifiableCredential is a digitally signed set of claims that adhere's to the W3C Verifiable
// Credentials data model. The set of claims, claim proofs, and associated metadata held
// within a Verifiable Credential. The "claimProofs" property is unique to Workday credentials and represents
// our implementation of attribute-level selective disclosure without Zero-Knowledge Proofs.
type VerifiableCredential struct {
	Metadata
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	ClaimProofs       map[string]proof.Proof `json:"claimProofs,omitempty"`
	*proof.Proof      `json:"proof,omitempty"`
}

func (v *VerifiableCredential) GetProof() *proof.Proof {
	return v.Proof
}

func (v *VerifiableCredential) SetProof(p *proof.Proof) {
	v.Proof = p
}

// IsEmpty returns true if the credential is nil or contains no data.
func (v *VerifiableCredential) IsEmpty() bool {
	if v == nil {
		return true
	}
	return reflect.DeepEqual(v, &VerifiableCredential{})
}

func (v *VerifiableCredential) ToJSON() (string, error) {
	bytes, err := json.Marshal(v)
	return string(bytes), err
}

// Metadata is the information about the set of claims in the Verifiable Credential.
type Metadata struct {

	// ModelVersion is a string that represents the data model version. As the system evolves,
	// different versions will have different capabilities, and the system must be able to
	// distinguish which model to use for de-serializing any JSON representations into concrete
	// objects. This version can change independently of the @context property, and should be
	// considered Workday specific.
	ModelVersion string `json:"modelVersion,omitempty"`

	// From the W3C Verfiable Credentials Data Model specification...
	// The value of the @context property MUST be an ordered set where the first item is a URI with
	// the value https://www.w3.org/2018/credentials/v1. For reference, a copy of the base context
	// is provided in Appendix § B. Base Context. Subsequent items in the array MUST express context
	// information and be composed of any combination of URIs or objects. It is RECOMMENDED that
	// each URI in the @context be one which, if de-referenced, results in a document containing
	// machine-readable information about the @context.
	Context []string `json:"@context"`

	// From the W3C Verifiable Credentials Data Model specification...
	// If the id property is present:
	// 1) The id property MUST express an identifier that others are expected to use when expressing
	// statements about a specific thing identified by that identifier.
	// 2) The id property MUST NOT have more than one value.
	// 3) The value of the id property MUST be a URI.
	ID string `json:"id,omitempty"`

	// From the W3C Verifiable Credentials Data Model specification...
	// The value of the type property MUST be, or map to (through interpretation of the @context
	// property), one or more URIs. If more than one URI is provided, the URIs MUST be interpreted
	// as an unordered set. Syntactic conveniences SHOULD be used to ease developer usage. Such
	// conveniences might include JSON-LD terms. It is RECOMMENDED that each URI in the type be one
	// which, if de-referenced, results in a document containing machine-readable information about
	// the type.
	Type []string `json:"type"`

	// From the W3C Verifiable Credentials Data Model specification...
	// The value of the issuer property MUST be either a URI or an object containing an id property.
	// It is RECOMMENDED that the URI in the issuer or its id be one which, if de-referenced,
	// results in a document containing machine-readable information about the issuer that can be
	// used to verify the information expressed in the credential.
	Issuer did.DID `json:"issuer,omitempty"`

	// From the W3C Verifiable Credentials Data Model specification...
	// A credential MUST have an issuanceDate property. The value of the issuanceDate property MUST
	// be a string value of an [RFC3339] combined date and time string representing the date and
	// time the credential becomes valid, which could be a date and time in the future. Note that
	// this value represents the earliest point in time at which the information associated with
	// the credentialSubject property becomes valid.
	IssuanceDate string `json:"issuanceDate,omitempty"`

	// From the W3C Verifiable Credentials Data Model specification...
	// The value of the credentialSchema property MUST be one or more data schemas that provide
	// verifiers with enough information to determine if the provided data conforms to the provided
	// schema. Each credentialSchema MUST specify its type (for example, JsonSchemaValidator2018),
	// and an id property that MUST be a URI identifying the schema file. The precise contents of
	// each data schema is determined by the specific type definition.
	Schema Schema `json:"credentialSchema,omitempty"`

	// From the W3C Verifiable Credentials Data Model specification...
	// If present, the value of the expirationDate property MUST be a string value of an [RFC3339]
	// combined date and time string representing the date and time the credential ceases to be valid.
	ExpirationDate string `json:"expirationDate,omitempty"`

	// From the W3C Verifiable Credentials Data Model specification...
	// This specification defines the following credentialStatus property for the discovery of information about the
	// current status of a verifiable credential, such as whether it is suspended or revoked.
	// The credentialStatus object consists of two properties:
	// id — which MUST be a URL
	// type - which expresses the credential status type (also referred to as the credential status method).
	// It is expected that the value will provide enough information to determine the current status of the credential.
	// For example, the object could contain a link to an external document noting whether or not the credential is
	// suspended or revoked.
	CredentialStatus *CredentialStatus `json:"credentialStatus,omitempty"`

	// TODO(gabe) add back when dynamic mobile model issue fixed
	// From the W3C Verifiable Credentials Data Model specification...
	// The nonTransferable property indicates that a verifiable credential must only be encapsulated into a verifiable
	// presentation whose proof was issued by the credentialSubject. A verifiable presentation that contains a
	// verifiable credential containing the nonTransferable property, whose proof creator is not the credentialSubject,
	// is invalid.
	// NonTransferable bool `json:"nonTransferable,omitempty"`
}

// IsEmpty returns true if the Metadata is nil or contains no data.
func (m *Metadata) IsEmpty() bool {
	if m == nil {
		return true
	}
	return reflect.DeepEqual(m, &Metadata{})
}

func newCredentialStatus(baseRevocationURL did.URI, issuer did.DID, id string) *CredentialStatus {
	if baseRevocationURL == "" {
		return nil
	}
	return &CredentialStatus{
		ID:   credentialbaseRevocationURL(baseRevocationURL, issuer, id),
		Type: RevocationType,
	}
}

// NewMetadataWithTimestamp returns Metadata for a credential with a specified IssuanceDate.
// Currently in Workday, the issuance date is determined by the offer date, although this is not
// a requirement in the W3C model, and in the future we may expose this to Issuers.
func NewMetadataWithTimestamp(id string, issuer did.DID, schema string, baseRevocationURL did.URI, issuanceDate time.Time) Metadata {
	return Metadata{
		ModelVersion: ModelVersionV1,
		Context:      []string{W3Context},
		ID:           id,
		Type:         []string{Type, util.CredentialTypeReference_v1_0},
		Issuer:       issuer,
		IssuanceDate: issuanceDate.Format(time.RFC3339),
		Schema: Schema{
			ID:   schema,
			Type: SchemaType,
		},
		CredentialStatus: newCredentialStatus(baseRevocationURL, issuer, id),
		// NonTransferable:  true,
	}
}

func NewMetadataWithTimestampAndExpiry(id string, issuer did.DID, schema string, baseRevocationURL did.URI, issuanceDate time.Time, expiry time.Time) Metadata {
	return Metadata{
		ModelVersion: ModelVersionV1,
		Context:      []string{W3Context},
		ID:           id,
		Type:         []string{Type, util.CredentialTypeReference_v1_0},
		Issuer:       issuer,
		IssuanceDate: issuanceDate.Format(time.RFC3339),
		Schema: Schema{
			ID:   schema,
			Type: SchemaType,
		},
		ExpirationDate:   expiry.Format(time.RFC3339),
		CredentialStatus: newCredentialStatus(baseRevocationURL, issuer, id),
		// NonTransferable:  true,
	}
}

// Deprecated: Callers should specify an issuance date when constructing Metadata.
func NewDefaultMetadata(id string, issuer did.DID, schema string, baseRevocationURL did.URI) Metadata {
	return Metadata{
		ModelVersion: ModelVersionV1,
		Context:      []string{W3Context},
		ID:           id,
		Type:         []string{Type, util.CredentialTypeReference_v1_0},
		Issuer:       issuer,
		IssuanceDate: time.Now().UTC().Format(time.RFC3339),
		Schema: Schema{
			ID:   schema,
			Type: SchemaType,
		},
		CredentialStatus: newCredentialStatus(baseRevocationURL, issuer, id),
		// NonTransferable:  true,
	}
}

// Schema is a URI that points to a JSON Schema, which can be used to validate the shape of the
// credential.  Workday currently only supports the "JsonSchemaValidator2018" type.
type Schema struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type CredentialStatus struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

func credentialbaseRevocationURL(baseRevocationURL did.URI, issuerDID did.DID, credID string) string {
	var url string
	if strings.LastIndex(baseRevocationURL, "/") == len(baseRevocationURL) {
		url = baseRevocationURL + ledger.GenerateRevocationKey(issuerDID, credID)
	} else {
		url = baseRevocationURL + "/" + ledger.GenerateRevocationKey(issuerDID, credID)
	}
	return url
}

// EncodeAttributeClaimDataForSigning creates a canonical byte array using the constituent parts of
// the credential that are required for generating a claim proof digital signature.
// See EncodeAttributeClaimDataForSigningOption.
func EncodeAttributeClaimDataForSigning(metadata Metadata, attribute string, value interface{}) ([]byte, error) {
	return EncodeAttributeClaimDataForSigningOption(metadata, attribute, value, true)
}

// EncodeAttributeClaimDataForSigningOption creates a byte array using the constituent parts of the
// credential that are required for generating a claim proof digital signature.  Claim Proofs
// include the credential metadata and claim/attribute name and value.  This can be thought of
// as a redacted version of the credential that contains a single claim.
func EncodeAttributeClaimDataForSigningOption(metadata Metadata, attribute string, value interface{}, canonicalMarshal bool) ([]byte, error) {
	credential := VerifiableCredential{
		Metadata:          metadata,
		CredentialSubject: map[string]interface{}{attribute: value},
	}

	if canonicalMarshal {
		credJSON, err := canonical.Marshal(credential)
		if err != nil {
			return nil, err
		}
		return []byte(base64.StdEncoding.EncodeToString(credJSON)), nil
	}

	logrus.Warn("Begrudgingly encoding attributes non-canonically. I urge you to canonicalize!!!")
	credJSON, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(credJSON)), nil
}

// JSONSchema for a credential schema.
type JSONSchema struct {
	Version  string `json:"version"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Author   string `json:"author"`
	Authored string `json:"authored"`
}

// Used to allow encoded claims to comply with the `Provable` interface
type Claim struct {
	EncodedClaim []byte `json:"encodedClaim"`
	*proof.Proof `json:"proof,omitempty"`
}

func (c *Claim) GetProof() *proof.Proof {
	return c.Proof
}

func (c *Claim) SetProof(p *proof.Proof) {
	c.Proof = p
}

// AsRawCredential creates a RawCredential that wraps a deep copy of the given credential.
func AsRawCredential(cred VerifiableCredential) (*RawCredential, error) {
	js, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	var raw RawCredential
	if err := json.Unmarshal(js, &raw); err != nil {
		return nil, err
	}
	raw.Raw = js
	return &raw, nil
}

// RawCredential is a wrapper around a byte array that holds a credential in raw JSON format.
// The byte array can be considered the data and the VerifiableCredential acts as a
// view into the data. Mutations to the data must go directly through this object in order to
// keep the raw form and the view in sync.  The purpose of this struct is to enable changes to the
// Credential model without disrupting the processing in the mobile code (exposed through gomobile).
type RawCredential struct {
	VerifiableCredential
	Raw []byte `json:"-"`
}

// Filter returns a copy of this RawCredential with only the claims (credentialSubject and
// claimProofs) specified in the attribute set.  This is intended to support selective disclosure of
// claims during a presentation exchange.
func (c *RawCredential) Filter(attrSet map[string]bool) (*RawCredential, error) {
	filteredJSON, err := filterRawJSON(c.Raw, attrSet)
	if err != nil {
		return nil, err
	}
	var filtered RawCredential
	err = json.Unmarshal(filteredJSON, &filtered)
	return &filtered, err
}

func filterRawJSON(credJSON []byte, attrSet map[string]bool) ([]byte, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(credJSON, &raw); err != nil {
		return nil, err
	}
	if err := filterCollection(credentialSubject, raw, attrSet); err != nil {
		return nil, err
	}
	if err := filterCollection(claimProofs, raw, attrSet); err != nil {
		return nil, err
	}
	return json.Marshal(raw)
}

func filterCollection(collection string, raw map[string]interface{}, attrSet map[string]bool) error {
	c, ok := raw[collection]
	if !ok {
		return fmt.Errorf("failed to find %s", c)
	}
	m := c.(map[string]interface{})
	for attr := range m {
		if !attrSet[attr] {
			delete(m, attr)
		}
	}
	return nil
}

func (c RawCredential) MarshalJSON() ([]byte, error) {
	js := make([]byte, len(c.Raw))
	copy(js, c.Raw)
	return js, nil
}

func (c *RawCredential) UnmarshalJSON(bits []byte) error {
	if err := json.Unmarshal(bits, &c.VerifiableCredential); err != nil {
		return err
	}
	c.Raw = make([]byte, len(bits))
	copy(c.Raw, bits)
	return nil
}

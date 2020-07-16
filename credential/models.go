package credential

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

const (
	ModelVersionV1     = "1.0"
	W3Context          = "https://www.w3.org/2018/credentials/v1"
	Type               = "VerifiableCredential"
	SchemaType         = "JsonSchemaValidatorWorkday2019"
	SubjectIDAttribute = "id"
)

// VerifiableCredential is a digitally signed set of claims that adhere's to the W3C Verifiable
// Credentials data model.
type VerifiableCredential struct {
	UnsignedVerifiableCredential
	*proof.Proof `json:"proof,omitempty"`
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

// UnsignedVerifiableCredential is the set of claims, claim proofs, and associated metadata held
// within a Verifiable Credential, but without the outer digital signature.  The "claimProofs"
// property is unique to Workday credentials and represents our implementation of attribute-level
// selective disclosure without Zero-Knowledge Proofs.
type UnsignedVerifiableCredential struct {
	Metadata
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	ClaimProofs       map[string]proof.Proof `json:"claimProofs,omitempty"`
}

// IsEmpty returns true if the credential isi nil or contains no data.
func (u *UnsignedVerifiableCredential) IsEmpty() bool {
	if u == nil {
		return true
	}
	return reflect.DeepEqual(u, &UnsignedVerifiableCredential{})
}

// Metadata is the information about the set of claims in the Verifiable Credential.
type Metadata struct {

	// ModelVersion is a string that represents the data model version. As the system evolves,
	// different versions will have different capabilities, and the system must be able to
	// distinguish which model to use for de-serializing any JSON representations into concrete
	// objects. This version can change independently of the @context property, and should be
	// considered Workday specific.
	ModelVersion string `json:"modelVersion"`

	// From the W3C Verfiable Credentials Data Model specification...
	// The value of the @context property MUST be an ordered set where the first item is a URI with
	// the value https://www.w3.org/2018/credentials/v1. For reference, a copy of the base context
	// is provided in Appendix § B. Base Context. Subsequent items in the array MUST express context
	// information and be composed of any combination of URIs or objects. It is RECOMMENDED that
	// each URI in the @context be one which, if de-referenced, results in a document containing
	// machine-readable information about the @context.
	Context []string `json:"@context"`

	// From the W3C Verfiable Credentials Data Model specification...
	// If the id property is present:
	// 1) The id property MUST express an identifier that others are expected to use when expressing
	// statements about a specific thing identified by that identifier.
	// 2) The id property MUST NOT have more than one value.
	// 3) The value of the id property MUST be a URI.
	ID string `json:"id"`

	// From the W3C Verfiable Credentials Data Model specification...
	// The value of the type property MUST be, or map to (through interpretation of the @context
	// property), one or more URIs. If more than one URI is provided, the URIs MUST be interpreted
	// as an unordered set. Syntactic conveniences SHOULD be used to ease developer usage. Such
	// conveniences might include JSON-LD terms. It is RECOMMENDED that each URI in the type be one
	// which, if de-referenced, results in a document containing machine-readable information about
	// the type.
	Type []string `json:"type"`

	// From the W3C Verfiable Credentials Data Model specification...
	// The value of the issuer property MUST be either a URI or an object containing an id property.
	// It is RECOMMENDED that the URI in the issuer or its id be one which, if de-referenced,
	// results in a document containing machine-readable information about the issuer that can be
	// used to verify the information expressed in the credential.
	Issuer string `json:"issuer"`

	// From the W3C Verfiable Credentials Data Model specification...
	// A credential MUST have an issuanceDate property. The value of the issuanceDate property MUST
	// be a string value of an [RFC3339] combined date and time string representing the date and
	// time the credential becomes valid, which could be a date and time in the future. Note that
	// this value represents the earliest point in time at which the information associated with
	// the credentialSubject property becomes valid.
	IssuanceDate string `json:"issuanceDate"`

	// From the W3C Verfiable Credentials Data Model specification...
	// The value of the credentialSchema property MUST be one or more data schemas that provide
	// verifiers with enough information to determine if the provided data conforms to the provided
	// schema. Each credentialSchema MUST specify its type (for example, JsonSchemaValidator2018),
	// and an id property that MUST be a URI identifying the schema file. The precise contents of
	// each data schema is determined by the specific type definition.
	Schema Schema `json:"credentialSchema"`

	// From the W3C Verfiable Credentials Data Model specification...
	// If present, the value of the expirationDate property MUST be a string value of an [RFC3339]
	// combined date and time string representing the date and time the credential ceases to be valid.
	ExpirationDate string `json:"expirationDate,omitempty"`
}

// IsEmpty returns true if the Metadata is nil or contains no data.
func (m *Metadata) IsEmpty() bool {
	if m == nil {
		return true
	}
	return reflect.DeepEqual(m, &Metadata{})
}

// NewMetadataWithTimestamp returns Metadata for a credential with a specified IssuanceDate.
// Currently in Workday, the issuance date is determined by the offer date, although this is not
// a requirement in the W3C model, and in the future we may expose this to Issuers.
func NewMetadataWithTimestamp(id, issuer, schema string, issuanceDate time.Time) Metadata {
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
	}
}

func NewMetadataWithTimestampAndExpiry(id, issuer, schema string, issuanceDate time.Time, expiry time.Time) Metadata {
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
		ExpirationDate: expiry.Format(time.RFC3339),
	}
}

// Deprecated: Callers should specify an issuance date when constructing Metadata.
func NewDefaultMetadata(id, issuer, schema string) Metadata {
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
	}
}

// Schema is a URI that points to a JSON Schema, which can be used to validate the shape of the
// credential.  Workday currently only supports the "JsonSchemaValidator2018" type.
type Schema struct {
	ID   string `json:"id"`
	Type string `json:"type"`
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
	credential := UnsignedVerifiableCredential{
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

// VersionedCreds is a wrapper around an UnsignedVerifiableCredential for the purpose of custom
// unmarshalling to guarantee that the "modelVersion" property is set to a supported value.
type VersionedCreds struct {
	UnsignedVerifiableCredential
}

func (c VersionedCreds) MarshalJSON() ([]byte, error) {
	return canonical.Marshal(c.UnsignedVerifiableCredential)
}

func (c *VersionedCreds) UnmarshalJSON(data []byte) error {
	version := struct {
		Version string `json:"modelVersion"`
	}{}
	if err := json.Unmarshal(data, &version); err != nil {
		return err
	}
	if version.Version == "" {
		return UnversionedCredError{}
	}
	if version.Version != util.Version_1_0 {
		return IncorrectCredError{
			SuppliedVersion: version.Version,
		}
	}
	c.UnsignedVerifiableCredential = UnsignedVerifiableCredential{}
	return json.Unmarshal(data, &c.UnsignedVerifiableCredential)
}

// IncorrectCredError is returned when attempting to unmarshal a verifiable credential into a model
// version that is not supported.
type IncorrectCredError struct {
	SuppliedVersion string
}

func (err IncorrectCredError) Error() string {
	return fmt.Sprintf(`unsupported version "%s"`, err.SuppliedVersion)
}

// UnversionedCredentialError is returned when attempting to unmarshal a verifiable credential that
// lacks a "modelVersion" field.  Without this field the json cannot be correctly mapped into a
// concrete object.
type UnversionedCredError struct {
}

func (err UnversionedCredError) Error() string {
	return fmt.Sprintf(`could not unmarshal unversioned credential`)
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

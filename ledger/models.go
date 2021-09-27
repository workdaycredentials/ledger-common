package ledger

import (
	"fmt"
	"reflect"
	"regexp"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

// Models for ledger objects and how they will be stored

// Type, Model ModelVersion, and ID should always be present
// Depending on the model object, the remainder of the fields may be optional.
// This should be enforced by the platform and smart contracts.
type Metadata struct {
	Type         string       `json:"type"`
	ModelVersion string       `json:"modelVersion"`
	ID           string       `json:"id"`
	Name         string       `json:"name,omitempty"`
	Author       did.DID      `json:"author,omitempty"`
	Authored     string       `json:"authored,omitempty"`
	Proof        *proof.Proof `json:"proof,omitempty"`
}

func (m *Metadata) IsEmpty() bool {
	if m == nil {
		return true
	}
	return reflect.DeepEqual(m, &Metadata{})
}

func (m *Metadata) GetProof() *proof.Proof {
	return m.Proof
}

func (m *Metadata) SetProof(p *proof.Proof) {
	m.Proof = p
}

// A unification of Provable and HasLedgerMetadata types as a utility to aid
// in the signing of objects that have ledger metadata
type HasLedgerMetadataProvable interface {
	proof.Provable
	HasLedgerMetadata
}

type HasLedgerMetadata interface {
	GetLedgerMetadata() *Metadata
}

func (m *Metadata) GetLedgerMetadata() *Metadata {
	return m
}

type DIDDoc struct {
	*Metadata
	*did.DIDDoc `json:"didDoc"`
}

func (d *DIDDoc) GetProof() *proof.Proof {
	return d.Metadata.Proof
}

func (d *DIDDoc) SetProof(p *proof.Proof) {
	d.Metadata.Proof = p
}

func (d *DIDDoc) IsEmpty() bool {
	if d == nil {
		return true
	}
	return reflect.DeepEqual(d, &DIDDoc{})
}

type Schema struct {
	*Metadata
	*JSONSchema
}

func (s *Schema) IsEmpty() bool {
	if s == nil {
		return true
	}
	return reflect.DeepEqual(s, &Schema{})
}

type Revocation struct {
	*Metadata
	*UnsignedRevocation `json:"revocation"`
}

func (r *Revocation) IsEmpty() bool {
	if r == nil {
		return true
	}
	return reflect.DeepEqual(r, &Revocation{})
}

// Revocation //

type UnsignedRevocation struct {
	ID           string  `json:"id"`
	CredentialID string  `json:"credentialId,omitempty"`
	IssuerDID    did.DID `json:"issuerId,omitempty"`
	ReasonCode   int     `json:"reason,omitempty"`
	Revoked      string  `json:"revoked,omitempty"`
}

func (u *UnsignedRevocation) IsEmpty() bool {
	if u == nil {
		return true
	}
	return reflect.DeepEqual(u, &UnsignedRevocation{})
}

// Schema //

// go representation of json schema document
type JSONSchemaMap map[string]interface{}

type Properties map[string]interface{}

// Assumes the json schema has a properties field
func (j JSONSchemaMap) Properties() Properties {
	if properties, ok := j["properties"]; ok {
		return properties.(map[string]interface{})
	}
	return map[string]interface{}{}
}

// Assumes the json schema has a description field
func (j JSONSchemaMap) Description() string {
	if description, ok := j["description"]; ok {
		return description.(string)
	}
	return ""
}

func (j JSONSchemaMap) AllowsAdditionalProperties() bool {
	if v, exists := j["additionalProperties"]; exists {
		if additionalProps, ok := v.(bool); ok {
			return additionalProps
		}
	}
	return false
}

func (j JSONSchemaMap) RequiredFields() []string {
	if v, exists := j["required"]; exists {
		if requiredFields, ok := v.([]interface{}); ok {
			required := make([]string, 0, len(requiredFields))
			for _, f := range requiredFields {
				required = append(required, f.(string))
			}
			return required
		}
	}
	return []string{}
}

func Type(field interface{}) string {
	if asMap, isMap := field.(map[string]interface{}); isMap {
		if v, exists := asMap["type"]; exists {
			if typeString, ok := v.(string); ok {
				return typeString
			}
		}
	}
	return ""
}

func Format(field interface{}) string {
	if asMap, isMap := field.(map[string]interface{}); isMap {
		if v, exists := asMap["format"]; exists {
			if formatString, ok := v.(string); ok {
				return formatString
			}
		}
	}
	return ""
}

func Contains(field string, required []string) bool {
	for _, f := range required {
		if f == field {
			return true
		}
	}
	return false
}

func (j JSONSchemaMap) ToJSON() string {
	bytes, err := canonical.Marshal(j)
	if err != nil {
		logrus.WithError(err).Error("Unable to jsonify schema")
		panic(err)
	}
	return string(bytes)
}

func GenerateSchemaID(author did.DID, version string) string {
	return fmt.Sprintf("%s;id=%s;version=%s", author.ToShortFormDid(), uuid.New().String(), version)
}

// Object for a credential that has not been signed
type JSONSchema struct {
	Schema JSONSchemaMap `json:"schema"`
}

// Validates a schema for a correctly composed Credential Schema
// Currently only validates the ID property. Add additional validation if required

// ID validation is based on our public schema specification:
// This identifier is a method-specific DID parameter name based upon the author of the
// schema. For example, if the author had a did like did:work:abcdefghi a possible schema
// ID the author created would have an identifier such as:
// did:work:abcdefghi;schema=17de181feb67447da4e78259d92d0240;version=1.0
func (s Schema) ValidateID() error {
	regx := "^did:work:\\S+\\;id=\\S+;version=\\d+\\.\\d+$"
	r, err := regexp.Compile(regx)
	if err != nil {
		return fmt.Errorf("failed to compile regular expression: %s", regx)
	}

	result := r.Match([]byte(s.ID))
	if !result {
		return fmt.Errorf("ledger schema 'id': %s is not valid against pattern: %s", s.ID, regx)
	}

	return nil
}

// Version assumes the version property is the only version in the identifier separated by periods
func (s Schema) Version() (string, error) {
	regx := "\\d+\\.\\d+$"
	r, err := regexp.Compile(regx)
	if err != nil {
		return "", fmt.Errorf("failed to compile regular expression: %s", regx)
	}

	result := r.Find([]byte(s.ID))
	if result == nil {
		return "", fmt.Errorf("error returning version property with regular expression: %s", regx)
	}

	return string(result), nil
}

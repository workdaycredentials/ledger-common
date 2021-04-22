package did

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/mr-tron/base58"

	"github.com/workdaycredentials/ledger-common/proof"
)

// DID is a Decentralized Identifier conforming to https://www.w3.org/TR/did-core/#did-syntax
type DID string

// String returns the DID as a string (conforming to `fmt.Stringer`)
func (did DID) String() string {
	return string(did)
}

// HashCode returns the DID as a string suitable for hashing
func (did DID) HashCode() string {
	return string(did)
}

// URI is a string conforming to https://tools.ietf.org/html/rfc3986
type URI = string

// DIDDoc a W3C compliant signed DID Document
type DIDDoc struct {
	// Deprecated: left here for backward compatibility. All new DID Docs should exclude this property.
	SchemaContext        StringOrArray `json:"@context,omitempty"`
	ID                   DID           `json:"id"`
	PublicKey            []KeyDef      `json:"publicKey"`                    // Deprecated: use `VerificationMethod`
	Authentication       []KeyRef      `json:"authentication"`               // TODO: optional
	Service              []ServiceDef  `json:"service"`                      // TODO: optional
	VerificationMethod   []KeyDef      `json:"verificationMethod,omitempty"` // TODO: required
	AssertionMethod      []KeyRef      `json:"assertionMethod,omitempty"`
	CapabilityInvocation []KeyRef      `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation []KeyRef      `json:"capabilityDelegation,omitempty"`
	KeyAgreement         []KeyRef      `json:"keyAgreement,omitempty"`
	AlsoKnownAs          []URI         `json:"alsoKnownAs,omitempty"`
	Controller           StringOrArray `json:"controller,omitempty"`
	Proof                *proof.Proof  `json:"proof,omitempty"`
}

func (d *DIDDoc) GetVerificationMethod() []KeyDef {
	// Return the old PublicKey array if the (new) VerificationMethod array is empty
	if len(d.VerificationMethod) == 0 {
		return d.PublicKey
	}
	return d.VerificationMethod
}

func (d *DIDDoc) GetPublicKey(keyID string) *KeyDef {
	for _, pubKey := range d.GetVerificationMethod() {
		if pubKey.ID == keyID {
			return &pubKey
		}
	}
	return nil
}

func (d *DIDDoc) IsEmpty() bool {
	if d == nil {
		return true
	}
	return reflect.DeepEqual(d, &DIDDoc{})
}

func (d *DIDDoc) GetProof() *proof.Proof {
	return d.Proof
}

func (d *DIDDoc) SetProof(p *proof.Proof) {
	d.Proof = p
}

type JWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
}

// KeyDef represents a DID public key (also known as Verification Method)
type KeyDef struct {
	ID              URI           `json:"id"`
	Type            proof.KeyType `json:"type"`
	Controller      DID           `json:"controller"`
	PublicKeyBase58 string        `json:"publicKeyBase58,omitempty"`
	PublicKeyJwk    *JWK          `json:"publicKeyJwk,omitempty"`
	// TODO: verification method MAY include additional properties. NEXT-11525
}

func (k *KeyDef) IsEmpty() bool {
	if k == nil {
		return true
	}
	return reflect.DeepEqual(k, &KeyDef{})
}

func (k *KeyDef) GetDecodedPublicKey() ([]byte, error) {
	if k.PublicKeyJwk != nil {
		return decodedJWK(*k.PublicKeyJwk)
	}
	return base58.Decode(k.PublicKeyBase58)
}

func (k *KeyDef) GetKeyFragment() (string, error) {
	split := strings.Split(k.ID, "#")
	if len(split) != 2 {
		return "", fmt.Errorf("could not extract key reference from key ID: %s", k.ID)
	}
	return split[1], nil
}

type ServiceDef struct {
	ID              URI         `json:"id"`
	Type            string      `json:"type"`
	ServiceEndpoint interface{} `json:"serviceEndpoint"` // string, array, or map
	// TODO: service endpoint MAY include additional properties. NEXT-11525
}

// CredentialDefinition JSON Schema
// Represents an identity that binds an issuer to a schema that allows specific issuance
type CredentialDefinition struct {
	CredDefDID DID    `json:"did"`
	IssuerDID  DID    `json:"issuerDid"`
	SchemaID   string `json:"schemaId"`
}

// Struct to contain identifier for an Admin DID
type AdminDID struct {
	ID DID `json:"id"`
}

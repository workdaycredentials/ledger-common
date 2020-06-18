package did

import (
	"reflect"

	"github.com/mr-tron/base58"

	"github.com/workdaycredentials/ledger-common/proof"
)

// UnsignedDIDDoc is a W3C compliant DID Document without an embedded Proof.
type UnsignedDIDDoc struct {
	// Deprecated: left here for backward compatibility. All new DID Docs should exclude this property.
	SchemaContext  string       `json:"@context,omitempty"`
	ID             string       `json:"id"`
	PublicKey      []KeyDef     `json:"publicKey"`
	Authentication []string     `json:"authentication"`
	Service        []ServiceDef `json:"service"`
}

func (u *UnsignedDIDDoc) IsEmpty() bool {
	if u == nil {
		return true
	}
	return reflect.DeepEqual(u, &UnsignedDIDDoc{})
}

func (u *UnsignedDIDDoc) GetPublicKey(keyID string) *KeyDef {
	for _, pubKey := range u.PublicKey {
		if pubKey.ID == keyID {
			return &pubKey
		}
	}
	return nil
}

// DIDDoc a W3C compliant signed DID Document
type DIDDoc struct {
	UnsignedDIDDoc
	*proof.Proof `json:"proof,omitempty"`
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

// KeyDef represents a DID public key
type KeyDef struct {
	ID              string        `json:"id"`
	Type            proof.KeyType `json:"type"`
	Controller      string        `json:"controller,omitempty"`
	PublicKeyBase58 string        `json:"publicKeyBase58"`
}

func (k *KeyDef) IsEmpty() bool {
	if k == nil {
		return true
	}
	return reflect.DeepEqual(k, &KeyDef{})
}

func (k *KeyDef) GetDecodedPublicKey() ([]byte, error) {
	return base58.Decode(k.PublicKeyBase58)
}

type ServiceDef struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// CredentialDefinition JSON Schema
// Represents an identity that binds an issuer to a schema that allows specific issuance
type CredentialDefinition struct {
	CredDefDID string `json:"did"`
	IssuerDID  string `json:"issuerDid"`
	SchemaID   string `json:"schemaId"`
}

// Struct to contain identifier for an Admin DID
type AdminDID struct {
	ID string `json:"id"`
}

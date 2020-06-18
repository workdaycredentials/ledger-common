package proof

import (
	"crypto"
	"crypto/rand"
	"reflect"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"
)

var (
	EmptyProof = Proof{}
)

type (
	// KeyType is the type of cryptographic key that is listed in a DID Document.
	KeyType string

	// SignatureType is the signature suite that was used to generate a digital signature,
	// and therefore the algorithm that must be used to verify a signature.
	SignatureType string

	ModelVersion int
)

const (
	JCSEdKeyType       KeyType       = "JcsEd25519Key2020"
	JCSEdSignatureType SignatureType = "JcsEd25519Signature2020"

	EcdsaSecp256k1KeyType       KeyType       = "EcdsaSecp256k1VerificationKey2019"
	EcdsaSecp256k1SignatureType SignatureType = "EcdsaSecp256k1Signature2019"

	// Deprecated: Do not create more keys of this type. The system can still use these keys
	// for support of existing DID Documents.
	WorkEdKeyType KeyType = "WorkEd25519VerificationKey2020"

	// Deprecated: Do not create more signatures of this type. The system can still verify these
	// signatures in existing signed documents.
	WorkEdSignatureType SignatureType = "WorkEd25519Signature2020"

	// Note: this is not a typo, both types below are represented by the same string.

	// Deprecated: Do not create more keys of this type. The system can still use these keys
	// for support of existing DID Documents.
	Ed25519KeyType KeyType = "Ed25519VerificationKey2018"

	// Deprecated: Do not create more signatures of this type. The system can still verify these
	// signatures in existing signed documents.
	Ed25519SignatureType SignatureType = "Ed25519VerificationKey2018"

	V1 ModelVersion = 1
	V2 ModelVersion = 2
)

func GetCorrespondingKeyType(t SignatureType) KeyType {
	switch t {
	case JCSEdSignatureType:
		return JCSEdKeyType
	case EcdsaSecp256k1SignatureType:
		return EcdsaSecp256k1KeyType
	case WorkEdSignatureType:
		return WorkEdKeyType
	case Ed25519SignatureType:
		return Ed25519KeyType
	default:
		logrus.Errorf("unknown type: %s", t)
		return ""
	}
}

func GetCorrespondingSignatureType(t KeyType) SignatureType {
	switch t {
	case JCSEdKeyType:
		return JCSEdSignatureType
	case EcdsaSecp256k1KeyType:
		return EcdsaSecp256k1SignatureType
	case WorkEdKeyType:
		return WorkEdSignatureType
	case Ed25519KeyType:
		return Ed25519SignatureType
	default:
		logrus.Errorf("unknown type: %s", t)
		return ""
	}
}

// Proof represents a verifiable digital signature.
type Proof struct {
	// Created is the datetime (RFC3339) when the signature was generated.
	Created string `json:"created,omitempty"`
	// Deprecated: Creator is a reference to the public key used to verify this signature.
	Creator string `json:"creator,omitempty"`
	// VerificationMethod is a reference to the public key used to verify this signature.
	VerificationMethod string `json:"verificationMethod,omitempty"`
	// Nonce is a random value (e.g. uuid) used to prevent replay attacks.
	Nonce string `json:"nonce,omitempty"`
	// SignatureValue is the digital signature.
	SignatureValue string `json:"signatureValue,omitempty"`
	// Type is the algorithm used to generate and verify the signature.
	Type SignatureType `json:"type,omitempty"`
}

// IsEmpty returns true if the proof is nil or contains no data.
func (p *Proof) IsEmpty() bool {
	if p == nil {
		return true
	}
	return reflect.DeepEqual(p, &Proof{})
}

func (p *Proof) ModelVersion() ModelVersion {
	if p.Creator != "" {
		return V1
	}
	return V2
}

// Utility for backwards compatibility of the "creator" property, which has been replaced by
// "verificationMethod" in later drafts of the Verifiable Credentials specification.
func (p *Proof) GetVerificationMethod() string {
	if p.VerificationMethod == "" {
		return p.Creator
	}
	return p.VerificationMethod
}

// Provable is an interface that allows in-place retrieval and modification of proof objects.
type Provable interface {
	GetProof() *Proof
	SetProof(p *Proof)
}

// Signer can generate digital signatures using a particular signing algorithm.
// This is basically a wrapper around a private key.
//
// Note: some signature suites require more sophisticated introspection (into json/structs), which
// can be used in conjunction with what this interface provides.
type Signer interface {
	ID() string
	Sign(toSign []byte) ([]byte, error)
	// TODO remove this method. The signature type is determined by the signature suite, not the proof algorithm.
	Type() SignatureType
	KeyType() KeyType
}

// Verifier can verify a digital signature of a particular signing algorithm.
// This is basically a wrapper around a public key.
type Verifier interface {
	Verify(data, signature []byte) (bool, error)
	KeyType() KeyType
}

// A generic holder for an object with an embedded proof. The JSON cannot be assumed to be canonical
// and it is recommended that it is run through the appropriate canonicalizer before signing.
type GenericProvable struct {
	JSONData string
	*Proof
}

func (t *GenericProvable) GetProof() *Proof {
	return t.Proof
}

func (t *GenericProvable) SetProof(p *Proof) {
	t.Proof = p
}

type Ed25519Signer struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
}

func (s *Ed25519Signer) ID() string {
	return s.KeyID
}

func (s *Ed25519Signer) Sign(toSign []byte) ([]byte, error) {
	return s.PrivateKey.Sign(rand.Reader, toSign, crypto.Hash(0))
}

func (s *Ed25519Signer) Type() SignatureType {
	return Ed25519SignatureType
}

func (s *Ed25519Signer) KeyType() KeyType {
	return Ed25519KeyType
}

type Ed25519Verifier struct {
	PubKey ed25519.PublicKey
}

func (v *Ed25519Verifier) Verify(data, signature []byte) (bool, error) {
	return ed25519.Verify(v.PubKey, data, signature), nil
}

func (v *Ed25519Verifier) KeyType() KeyType {
	return Ed25519KeyType
}

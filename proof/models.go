package proof

import (
	"crypto"
	"crypto/rand"
	"errors"
	"reflect"

	"golang.org/x/crypto/ed25519"
)

var (
	EmptyProof = Proof{}
)

type (
	// Type is the type of cryptographic key that is listed in a DID Document.
	KeyType string

	// SignatureType is the signature suite that was used to generate a digital signature,
	// and therefore the algorithm that must be used to verify a signature.
	SignatureType string

	ModelVersion int

	ProofPurpose string
)

const (
	// The only key type that should be used for Ed25519 keys
	Ed25519KeyType KeyType = "Ed25519VerificationKey2018"

	JCSEdSignatureType   SignatureType = "JcsEd25519Signature2020"
	Ed25519SignatureType SignatureType = "Ed25519Signature2018"

	EcdsaSecp256k1KeyType       KeyType       = "EcdsaSecp256k1VerificationKey2019"
	EcdsaSecp256k1SignatureType SignatureType = "EcdsaSecp256k1Signature2019"

	// Deprecated: do not use this signature type
	Ed25519KeySignatureType SignatureType = "Ed25519VerificationKey2018"

	// Deprecated: Do not create more keys of this type. The system can still use these keys
	// for support of existing DID Documents.
	WorkEdKeyType KeyType = "WorkEd25519VerificationKey2020"

	// Deprecated: Do not create more signatures of this type. The system can still verify these
	// signatures in existing signed documents.
	WorkEdSignatureType SignatureType = "WorkEd25519Signature2020"

	V1 ModelVersion = 1
	V2 ModelVersion = 2

	AuthenticationPurpose  ProofPurpose = "authentication"
	AssertionMethodPurpose ProofPurpose = "assertionMethod"
)

// Proof represents a verifiable digital signature conforming to https://www.w3.org/TR/vc-data-model/#proofs-signatures
type Proof struct {
	// Created is the datetime (RFC3339) when the signature was generated.
	Created string `json:"created,omitempty"` // required

	// ProofPurpose is the specific intent for the proof, the reason why an entity created it.
	// Acts as a safeguard to prevent the proof from being misused for a purpose other than the one it was intended for.
	ProofPurpose ProofPurpose `json:"proofPurpose,omitempty"` // required

	// Deprecated: Creator is a reference to the public key used to verify this signature.
	Creator string `json:"creator,omitempty"`

	// VerificationMethod is a reference to the public key used to verify this signature.
	VerificationMethod string `json:"verificationMethod,omitempty"` // required

	// Deprecated (use challenge): Nonce is a random value (e.g. uuid) used to prevent replay attacks.
	Nonce string `json:"nonce,omitempty"`

	// SignatureValue is the digital signature.
	SignatureValue string `json:"signatureValue,omitempty"`

	// Type is the algorithm used to generate and verify the signature.
	Type SignatureType `json:"type"`

	// JWS represents an optional field for an encoded JSON Web Signature
	JWS string `json:"jws,omitempty"`

	// Domain is a string value specifying the restricted domain of the proof.
	Domain string `json:"domain,omitempty"`

	// Challenge is a random or pseudo-random value used by some authentication protocols to mitigate replay attacks.
	Challenge string `json:"challenge,omitempty"`
}

func (p *Proof) GetProof() *Proof {
	return p
}

func (p *Proof) SetProof(pr *Proof) {
	p = pr
}

type ProofOptions struct {
	ProofPurpose ProofPurpose
	Domain       string
	Challenge    string
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
	Type() KeyType
}

// NewEd25519Signer is used to build a signer with validations
func NewEd25519Signer(key ed25519.PrivateKey, keyID string) (Signer, error) {
	if key == nil {
		return nil, errors.New("must have valid private key")
	}
	if keyID == "" {
		return nil, errors.New("must have valid key ID")
	}
	return &Ed25519Signer{KeyID: keyID, PrivateKey: key}, nil
}

// Verifier can verify a digital signature of a particular signing algorithm.
// This is basically a wrapper around a public key.
type Verifier interface {
	Verify(data, signature []byte) (bool, error)
	Type() KeyType
}

// A generic holder for an object with an embedded proof. The JSON cannot be assumed to be canonical
// and it is recommended that it is run through the appropriate canonicalizer before signing.
type GenericProvable struct {
	JSONData string
	*Proof   `json:"proof"`
}

func (g *GenericProvable) GetProof() *Proof {
	return g.Proof
}

func (g *GenericProvable) SetProof(p *Proof) {
	g.Proof = p
}

// Unification type for all ed25519 based signers
// Intended to be constructed via the `NewEd25519Signer` method
type Ed25519Signer struct {
	// The fully qualified key id (e.g. did:work:abcd#key-1)
	KeyID      string
	PrivateKey ed25519.PrivateKey
}

func (s *Ed25519Signer) ID() string {
	return s.KeyID
}

func (s *Ed25519Signer) Sign(toSign []byte) ([]byte, error) {
	return s.PrivateKey.Sign(rand.Reader, toSign, crypto.Hash(0))
}

func (s *Ed25519Signer) Type() KeyType {
	return Ed25519KeyType
}

type Ed25519Verifier struct {
	PubKey ed25519.PublicKey
}

func (v *Ed25519Verifier) Verify(data, signature []byte) (bool, error) {
	return ed25519.Verify(v.PubKey, data, signature), nil
}

func (v *Ed25519Verifier) Type() KeyType {
	return Ed25519KeyType
}

// Provides which signature types use a nonce in their proofs
func (s SignatureType) UsesNonce() bool {
	switch s {
	case Ed25519SignatureType:
		return false
	default:
		return true
	}
}

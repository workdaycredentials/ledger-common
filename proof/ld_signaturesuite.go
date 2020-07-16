package proof

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	jcs "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/uuid"
	"github.com/mr-tron/base58"

	"github.com/workdaycredentials/ledger-common/util"
)

// LDSignatureSuite is a SignatureSuite based on the Linked-Data Signatures specification.
// See https://w3c-ccg.github.io/ld-proofs/#linked-data-signatures.
type LDSignatureSuite struct {
	SignatureType   SignatureType
	KeyType         KeyType
	ProofFactory    ProofFactory
	Marshaler       Marshaler
	Canonicalizer   Canonicalizer
	MessageDigest   MessageDigest
	OptionsAppender OptionsAppender
}

// Type returns the SignatureType that this suite is capable of generating and verifying.
func (s LDSignatureSuite) Type() SignatureType {
	return s.SignatureType
}

// Sign adds a digital signature to the provable object in the form of a Proof.
// The type of Proof is determined by the ProofFactory used to construct this suite.
// Returns an error if the provable object already contains a Proof or if any error is
// encountered when generating the digital signature.
func (s LDSignatureSuite) Sign(provable Provable, signer Signer) error {
	if provable.GetProof() != nil {
		return fmt.Errorf("attempt to overwrite existing proof")
	}
	if signer.Type() != s.KeyType {
		return fmt.Errorf("incorrect key type")
	}

	p := s.ProofFactory.Create(signer, s.SignatureType)
	provable.SetProof(p)

	jsonBytes, err := s.encode(provable)
	if err != nil {
		provable.SetProof(nil)
		return err
	}

	signature, err := signer.Sign(jsonBytes)
	if err != nil {
		provable.SetProof(nil)
		return err
	}

	p.SignatureValue = base58.Encode(signature)
	return nil
}

// encode transforms the provable object into a canonical byte array that can be signed over.
func (s *LDSignatureSuite) encode(provable Provable) ([]byte, error) {
	jsonBytes, err := s.Marshaler.Marshal(provable)
	if err != nil {
		return nil, err
	}
	if s.Canonicalizer != nil {
		jsonBytes, err = s.Canonicalizer.Canonicalize(jsonBytes)
		if err != nil {
			return nil, err
		}
	}
	if s.MessageDigest != nil {
		jsonBytes, err = s.MessageDigest.Digest(jsonBytes)
		if err != nil {
			return nil, err
		}
	}
	if s.OptionsAppender != nil {
		jsonBytes = s.OptionsAppender.Append(jsonBytes, provable.GetProof())
	}
	return jsonBytes, nil
}

// Verify checks that the provable's Proof is valid.
// Returns an error if the Proof is missing or invalid.
func (s LDSignatureSuite) Verify(provable Provable, verifier Verifier) error {
	p := provable.GetProof()
	if p.IsEmpty() {
		return fmt.Errorf("missing proof")
	}
	signatureB58 := p.SignatureValue
	signature, err := base58.Decode(signatureB58)
	if err != nil {
		return err
	}
	jsonBytes, err := s.encode(provable)
	if success, err := verifier.Verify(jsonBytes, signature); err != nil {
		return err
	} else if !success {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// ProofFactory creates proofs given a signer and signature type
type ProofFactory interface {
	Create(signer Signer, signatureType SignatureType) *Proof
}

// proofFactoryV1 is a factory for creating proofs using the "creator" field.
type proofFactoryV1 struct {
	SignatureType SignatureType
}

func (f *proofFactoryV1) Create(signer Signer, signatureType SignatureType) *Proof {
	return &Proof{
		Created: time.Now().UTC().Format(time.RFC3339),
		Nonce:   uuid.New().String(),
		Creator: signer.ID(),
		Type:    signatureType,
	}
}

// proofFactoryV2 is a factory for creating proofs using the "verificationMethod" field.
type proofFactoryV2 struct {
	SignatureType SignatureType
}

func (f *proofFactoryV2) Create(signer Signer, signatureType SignatureType) *Proof {
	return &Proof{
		Created:            time.Now().UTC().Format(time.RFC3339),
		Nonce:              uuid.New().String(),
		VerificationMethod: signer.ID(),
		Type:               signatureType,
	}
}

// Marshaler turns a Provable object into a JSON byte array. The JSON is not expected to be in
// canonical form; we have a separate Canonicalizer for that. Instead, this method gives the
// flexibility to add custom marshaling over the standard json.Marshal(). For example,
// some suites expect an embedded Proof object, while others do not. This type of manipulation
// should be handled here (or in OptionAppender if after canonicalization).
type Marshaler interface {
	Marshal(provable Provable) ([]byte, error)
}

// EmbeddedProofMarshaler transforms the Provable into JSON, and leaves an embedded Proof sans the
// signature value. This will effectively pass the Proof Options (metadata) into the signing
// algorithm as part of the canonicalized JSON payload.
type EmbeddedProofMarshaler struct{}

func (m *EmbeddedProofMarshaler) Marshal(provable Provable) ([]byte, error) {
	p := provable.GetProof()
	signatureB58 := p.SignatureValue
	p.SignatureValue = ""
	defer func() { p.SignatureValue = signatureB58 }()
	return json.Marshal(provable)
}

// WithoutProofMarshaler transforms the Provable into JSON, and strips the proof.
type WithoutProofMarshaler struct{}

func (m *WithoutProofMarshaler) Marshal(provable Provable) ([]byte, error) {
	p := provable.GetProof()
	provable.SetProof(nil)
	defer func() { provable.SetProof(p) }()
	b, err := json.Marshal(provable)
	if err != nil {
		return nil, err
	}
	// make sure the proof is really gone
	var object map[string]interface{}
	if err := json.Unmarshal(b, &object); err != nil {
		return nil, err
	}
	delete(object, "proof")
	return json.Marshal(object)
}

// Canonicalizer transforms a JSON byte array into its canonical form.
type Canonicalizer interface {
	Canonicalize(jsonBytes []byte) ([]byte, error)
}

// JCSCanonicalizer transforms a JSON byte array using the JSON Canonicalization Scheme algorithm.
type JCSCanonicalizer struct{}

func (c *JCSCanonicalizer) Canonicalize(jsonBytes []byte) ([]byte, error) {
	return jcs.Transform(jsonBytes)
}

// MessageDigest transforms a byte array into a more compact byte array using a hashing digest
// algorithm, such as sha256.  This creates a smaller payload for the digital signature.
//
// It should be noted that some ProofAlgorithms natively use a digest, such as the Ed25519 Ecdsa,
// which uses SHA512 under the hood. Therefore, we don't need to use a separate MessageDigest
// when signing with Ed25519 keys.
type MessageDigest interface {
	Digest(data []byte) ([]byte, error)
}

// Base64Encoder base64 encodes the payload. This is only included to be compatible with the
// existing proof signatures on verifiable credentials. There's no benefit to base64 encoding a
// byte array that represents utf-8 characters, since little- and big-endianness does not apply.
type Base64Encoder struct{}

func (e *Base64Encoder) Digest(data []byte) ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(data)
	return []byte(encoded), nil
}

// OptionsAppender appends the proof options (metadata) to the payload before signing or verifying.
type OptionsAppender interface {
	Append(data []byte, proof *Proof) []byte
}

// NonceAppender appends ".<nonce>" to the payload before signing or verifying.
// The nonce adds randomness in order to prevent a replay attack. Workday's earlier signature
// algorithms only included this field and did not sign over the other proof metadata fields.
type NonceAppender struct{}

func (n *NonceAppender) Append(data []byte, proof *Proof) []byte {
	return util.AddNonceToDoc(data, proof.Nonce)
}

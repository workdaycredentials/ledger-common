package proof

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	jcs "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/mr-tron/base58"
	"github.com/piprate/json-gold/ld"

	"github.com/workdaycredentials/ledger-common/util"
)

const (
	jwsSeparator = "."
	jwsSignature = 2

	w3SecurityContext = "https://w3id.org/security/v2"
)

var (
	ed25519JWTHeader = map[string]interface{}{
		"alg":  "EdDSA",
		"b64":  false,
		"crit": []string{"b64"},
	}
)

// LDSignatureSuite is a SignatureSuite based on the Linked-Data Signatures specification.
// See https://w3c-ccg.github.io/ld-proofs/#linked-data-signatures.
type LDSignatureSuite struct {
	SignatureType SignatureType
	KeyType       KeyType
	ProofFactory  ProofFactory
	Encoder       Encoder
}

// Type returns the SignatureType that this suite is capable of generating and verifying.
func (s LDSignatureSuite) Type() SignatureType {
	return s.SignatureType
}

// Sign adds a digital signature to the provable object in the form of a Proof.
// The type of Proof is determined by the ProofFactory used to construct this suite.
// Returns an error if the provable object already contains a Proof or if any error is
// encountered when generating the digital signature.
func (s LDSignatureSuite) Sign(provable Provable, signer Signer, opts *ProofOptions) error {
	if provable.GetProof() != nil {
		return errors.New("attempt to overwrite existing proof")
	}
	if signer.Type() != s.KeyType {
		return errors.New("incorrect key type")
	}
	p := s.ProofFactory.Create(signer, s.SignatureType, opts)
	provable.SetProof(p)
	toBeSigned, err := s.Encoder.Encode(provable)
	if err != nil {
		provable.SetProof(nil)
		return err
	}
	signature, err := signer.Sign(toBeSigned)
	if err != nil {
		provable.SetProof(nil)
		return err
	}
	if err := s.Encoder.SetSignatureValue(provable, signature); err != nil {
		return err
	}
	return nil
}

type EncodeOptions struct {
	JWSHeader string
}

// Verify checks that the provable's Proof is valid.
// Returns an error if the Proof is missing or invalid.
func (s LDSignatureSuite) Verify(provable Provable, verifier Verifier) error {
	p := provable.GetProof()
	if p.IsEmpty() {
		return fmt.Errorf("missing proof")
	}
	signature, err := s.Encoder.DecodeSignature(provable)
	if err != nil {
		return err
	}
	data, err := s.Encoder.Encode(provable)
	if err != nil {
		return err
	}
	if success, err := verifier.Verify(data, signature); err != nil {
		return err
	} else if !success {
		return errors.New("signature verification failed")
	}
	return nil
}

// ProofFactory creates proofs given a signer and signature type
type ProofFactory interface {
	Create(signer Signer, signatureType SignatureType, opts *ProofOptions) *Proof
}

// proofFactoryV1 is a factory for creating proofs using the "creator" field.
type proofFactoryV1 struct {
	SignatureType SignatureType
}

func (f *proofFactoryV1) Create(signer Signer, signatureType SignatureType, opts *ProofOptions) *Proof {
	proof := &Proof{
		Created: time.Now().UTC().Format(time.RFC3339),
		Creator: signer.ID(),
		Type:    signatureType,
	}
	if opts != nil {
		proof.ProofPurpose = opts.ProofPurpose
		proof.Domain = opts.Domain
		proof.Challenge = opts.Challenge
	}
	return proof
}

// proofFactoryV2 is a factory for creating proofs using the "verificationMethod" field.
type proofFactoryV2 struct {
	SignatureType SignatureType
	UsesNonce     bool
}

func (f *proofFactoryV2) Create(signer Signer, signatureType SignatureType, opts *ProofOptions) *Proof {
	var nonce string
	if f.UsesNonce {
		nonce = util.GetNonce()
	}
	proof := &Proof{
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: signer.ID(),
		Type:               signatureType,
	}
	if opts != nil {
		proof.ProofPurpose = opts.ProofPurpose
		proof.Domain = opts.Domain
		proof.Challenge = opts.Challenge
		proof.Nonce = nonce
		proof.VerificationMethod = signer.ID()
	}
	return proof
}

type Encoder interface {
	Encode(provable Provable) ([]byte, error)
	SetSignatureValue(provable Provable, signature []byte) error
	DecodeSignature(provable Provable) ([]byte, error)
}

type JWSEncoder struct {
	header          string
	marshaler       Marshaler
	canonicalizer   Canonicalizer
	digester        MessageDigest
	optionsAppender OptionsAppender
}

// Prepare a provable for JWSification
// https://w3c-ccg.github.io/ld-proofs/#create-verify-hash-algorithm
func (e *JWSEncoder) Encode(provable Provable) ([]byte, error) {
	var ldProof Proof
	if err := util.DeepCopy(provable.GetProof(), &ldProof); err != nil {
		return nil, err
	}

	// canonicalize proof
	proofBytes, err := e.marshaler.Marshal(&ldProof)
	if err != nil {
		return nil, err
	}
	var proofMap map[string]interface{}
	if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
		return nil, err
	}
	proofMap["@context"] = w3SecurityContext
	proofMapBytes, err := json.Marshal(proofMap)
	if err != nil {
		return nil, err
	}
	if e.canonicalizer == nil {
		return nil, errors.New("canonicalizer must be initialized")
	}
	canonicalProofBytes, err := e.canonicalizer.Canonicalize(proofMapBytes)
	if err != nil {
		return nil, err
	}

	// get digest of proof
	if e.digester == nil {
		return nil, errors.New("digester must be initialized")
	}
	proofDigest, err := e.digester.Digest(canonicalProofBytes)
	if err != nil {
		return nil, err
	}

	// canonicalize doc
	defer provable.SetProof(&ldProof)
	provable.SetProof(nil)
	docBytes, err := json.Marshal(provable)
	if err != nil {
		return nil, err
	}

	canonicalDocBytes, err := e.canonicalizer.Canonicalize(docBytes)
	if err != nil {
		return nil, err
	}

	// get digest of doc
	docDigest, err := e.digester.Digest(canonicalDocBytes)
	if err != nil {
		return nil, err
	}

	// append header before finishing encoding
	data := append(proofDigest, docDigest...)
	return e.optionsAppender.Append(data, &AppendOptions{Header: e.header}), nil
}

func (e *JWSEncoder) SetSignatureValue(provable Provable, signature []byte) error {
	p := provable.GetProof()
	if p == nil {
		p = &Proof{}
	}
	if p.JWS != "" {
		return errors.New("jws value already set")
	}
	if p.SignatureValue != "" {
		return errors.New("signature value set on jws proof type")
	}
	p.JWS = e.header + ".." + base64.RawURLEncoding.EncodeToString(signature)
	provable.SetProof(p)
	return nil
}

func (e *JWSEncoder) DecodeSignature(provable Provable) ([]byte, error) {
	splitJWS := strings.Split(provable.GetProof().JWS, jwsSeparator)
	if len(splitJWS) != 3 {
		return nil, errors.New("signature verification failed")
	}
	return base64.RawURLEncoding.DecodeString(splitJWS[jwsSignature])
}

// As per https://w3c-ccg.github.io/lds-rsa2018/#modifications-to-signature-algorithm
func getEd25519SignatureJWSHeader() string {
	headerBytes, err := json.Marshal(ed25519JWTHeader)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(headerBytes)
}

type LDSignatureEncoder struct {
	marshaler       Marshaler
	canonicalizer   Canonicalizer
	digester        MessageDigest
	optionsAppender OptionsAppender
}

func (e *LDSignatureEncoder) Encode(provable Provable) ([]byte, error) {
	if e.marshaler == nil {
		return nil, errors.New("marshaler cannot be nil")
	}
	jsonBytes, err := e.marshaler.Marshal(provable)
	if err != nil {
		return nil, err
	}
	if e.canonicalizer != nil {
		jsonBytes, err = e.canonicalizer.Canonicalize(jsonBytes)
		if err != nil {
			return nil, err
		}
	}
	if e.digester != nil {
		jsonBytes, err = e.digester.Digest(jsonBytes)
		if err != nil {
			return nil, err
		}
	}
	if e.optionsAppender != nil {
		jsonBytes = e.optionsAppender.Append(jsonBytes, &AppendOptions{Nonce: provable.GetProof().Nonce})
	}
	return jsonBytes, nil
}

func (e *LDSignatureEncoder) SetSignatureValue(provable Provable, signature []byte) error {
	p := provable.GetProof()
	if p.SignatureValue != "" {
		return errors.New("signature value already set")
	}
	if p.JWS != "" {
		return errors.New("jws value set on signature proof type")
	}
	p.SignatureValue = base58.Encode(signature)
	p.SetProof(p)
	return nil
}

func (e *LDSignatureEncoder) DecodeSignature(provable Provable) ([]byte, error) {
	signatureB58 := provable.GetProof().SignatureValue
	return base58.Decode(signatureB58)
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
	jws := p.JWS
	if p.SignatureValue != "" {
		p.SignatureValue = ""
		defer func() { p.SignatureValue = signatureB58 }()
	}
	if p.JWS != "" {
		p.JWS = ""
		defer func() { p.JWS = jws }()
	}
	return json.Marshal(provable)
}

// WithoutProofMarshaler transforms the Provable into JSON, and strips the proof.
type WithoutProofMarshaler struct{}

func (m *WithoutProofMarshaler) Marshal(provable Provable) ([]byte, error) {
	p := provable.GetProof()
	provable.SetProof(nil)
	defer func() { provable.SetProof(p) }()
	return json.Marshal(provable)
}

type JWSProofMarshaler struct{}

// Canonicalizer transforms a JSON byte array into its canonical form.
type Canonicalizer interface {
	Canonicalize(jsonBytes []byte) ([]byte, error)
}

// JCSCanonicalizer transforms a JSON byte array using the JSON Canonicalization Scheme algorithm.
type JCSCanonicalizer struct{}

func (c *JCSCanonicalizer) Canonicalize(jsonBytes []byte) ([]byte, error) {
	return jcs.Transform(jsonBytes)
}

const (
	// Used in RDF Dataset Canonicalization
	format    = "application/n-quads"
	algorithm = "URDNA2015"
)

type RDFCanonicalizer struct{}

func (c *RDFCanonicalizer) Canonicalize(jsonBytes []byte) ([]byte, error) {
	processor := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Algorithm = algorithm
	options.Format = format
	options.ProcessingMode = ld.JsonLd_1_1
	options.ProduceGeneralizedRdf = true

	// convert jsonBytes to map[string]interface{} which the library expects
	var out map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &out); err != nil {
		return nil, err
	}

	normalized, err := processor.Normalize(out, options)
	if err != nil {
		return nil, err
	}
	s := normalized.(string)
	return []byte(s), nil
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

// TODO(gabe) consider moving the Base64 encoding into the Canonicalizer instead of as a Digest.
// Base64Encoder base64 encodes the payload. This is only included to be compatible with the
// existing proof signatures on verifiable credentials. There's no benefit to base64 encoding a
// byte array that represents utf-8 characters, since little- and big-endianness does not apply.
type Base64Encoder struct{}

func (e *Base64Encoder) Digest(data []byte) ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(data)
	return []byte(encoded), nil
}

// SHA256Encoder creates a SHA-256 hash of the payload.
type SHA256Encoder struct{}

func (e *SHA256Encoder) Digest(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return hash[:], nil
}

type AppendOptions struct {
	Nonce  string
	Header string
}

// OptionsAppender appends the proof options (metadata) to the payload before signing or verifying.
type OptionsAppender interface {
	Append(data []byte, options *AppendOptions) []byte
}

// NonceAppender appends ".<nonce>" to the payload before signing or verifying.
// The nonce adds randomness in order to prevent a replay attack. Workday's earlier signature
// algorithms only included this field and did not sign over the other proof metadata fields.
type NonceAppender struct{}

func (n *NonceAppender) Append(data []byte, options *AppendOptions) []byte {
	return util.AddNonceToDoc(data, options.Nonce)
}

// HeaderPrepender prepends a header to the data for a JWS
type HeaderPrepender struct{}

func (h *HeaderPrepender) Append(data []byte, options *AppendOptions) []byte {
	return append([]byte(options.Header+"."), data...)
}

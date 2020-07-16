package proof

import (
	"fmt"
)

// SignatureSuite is a set of algorithms that specify how to sign and verify provable objects.
// This model is based on the W3C Linked-Data Proofs, see https://w3c-ccg.github.io/ld-proofs.
type SignatureSuite interface {
	Type() SignatureType
	Sign(provable Provable, signer Signer) error
	Verify(provable Provable, verifier Verifier) error
}

// withAndWithoutCanonicalizer returns a composite signature suite where the primary signature
// verification uses a canonicalizer and the backup does not. This is intended to cover Workday's
// initial lack of canonicalization.  We initially signed marshaled object using json.Marshal,
// which is based on the struct field declaration order. We later introduced a canonicalizer with
// recursive lexicographical ordering; however, we didn't update the signature type.
func withAndWithoutCanonicalizer(suite *LDSignatureSuite) *compositeSignatureSuite {
	backup := *suite
	backup.Canonicalizer = nil
	return &compositeSignatureSuite{main: suite, backup: backup}
}

// withV2Proofs returns a copy of the given LDSignatureSuite with the a ProofFactory that produces
// version 2 Proofs (uses the newer verificationMethod field).
func withV2Proofs(suite *LDSignatureSuite) *LDSignatureSuite {
	updated := *suite
	updated.ProofFactory = &proofFactoryV2{}
	return &updated
}

// withB64Digest returns a copy of the given LDSignatureSuite with a base64 message digest.
func withB64Digest(suite *LDSignatureSuite) *LDSignatureSuite {
	updated := *suite
	updated.MessageDigest = &Base64Encoder{}
	return &updated
}

// compositeSignatureSuite wraps two suites in order to support (unintended) variable
// canonicalization of some signature schemes. We designate a main suite and a backup.
// The signature generation always uses the primary suite. On verification, if the main suite fails,
// then we will fallback to the backup suite.
type compositeSignatureSuite struct {
	main   SignatureSuite
	backup SignatureSuite
}

func (s *compositeSignatureSuite) Type() SignatureType {
	return s.main.Type()
}

func (s *compositeSignatureSuite) Sign(provable Provable, signer Signer) error {
	return s.main.Sign(provable, signer)
}

func (s *compositeSignatureSuite) Verify(provable Provable, verifier Verifier) error {
	if err := s.main.Verify(provable, verifier); err != nil {
		return s.backup.Verify(provable, verifier)
	}
	return nil
}

type SignatureSuiteFactory interface {
	// GetSuiteForProof returns the corresponding signature suite the proof was created using
	GetSuiteForProof(proof *Proof) (SignatureSuite, error)

	// GetSuiteForCredentialsProof returns the corresponding signature suite the credential proof was created using
	GetSuiteForCredentialsProof(proof *Proof) (SignatureSuite, error)

	// GetSuite returns the signature suite corresponding to the provided type and version of the suite
	GetSuite(signatureType SignatureType, version ModelVersion) (SignatureSuite, error)

	// GetSuiteForCredentials returns the signature suite corresponding to the provided
	// type and version of the suite for credential signing
	GetSuiteForCredentials(signatureType SignatureType, version ModelVersion) (SignatureSuite, error)
}

type signatureSuites struct {
	// JCS Signature suite
	jcsEd25519 SignatureSuite
	// WorkEd25519 Signature suite with v1 Proofs
	workEd25519 SignatureSuite
	// WorkEd25519 Signature suite with v2 Proofs
	workEd25519v2 SignatureSuite
	// Ed25519 Signature suite with v1 Proofs
	ed25519 SignatureSuite
	// Ed25519 Signature suite with v2 Proofs
	ed25519v2 SignatureSuite
	// EcdsaSecp256k1 Signature suite with v1 Proofs
	secp256k1 SignatureSuite
}

// GetSuiteForProof returns the correct type of SignatureSuite to use to verify the given Proof.
func (s *signatureSuites) GetSuiteForProof(proof *Proof) (suite SignatureSuite, err error) {
	return s.GetSuite(proof.Type, proof.ModelVersion())
}

// GetSuite returns the correct SignatureSuite to use for signing or verifying a Proof of a
// particular Type and Proof model version.
func (s *signatureSuites) GetSuite(signatureType SignatureType, modelVersion ModelVersion) (suite SignatureSuite, err error) {
	switch modelVersion {
	case V1:
		suite = s.getSuiteV1(signatureType)
	case V2:
		suite = s.getSuiteV2(signatureType)
	}
	if suite == nil {
		err = fmt.Errorf("unsupported signature type: %s:%d", signatureType, modelVersion)
	}
	return
}

func (s *signatureSuites) getSuiteV1(signatureType SignatureType) SignatureSuite {
	switch signatureType {
	case EcdsaSecp256k1SignatureType:
		return s.secp256k1
	case WorkEdSignatureType:
		return s.workEd25519
	case Ed25519SignatureType:
		return s.ed25519
	}
	return nil
}

func (s *signatureSuites) getSuiteV2(signatureType SignatureType) SignatureSuite {
	switch signatureType {
	case JCSEdSignatureType:
		return s.jcsEd25519
	case WorkEdSignatureType:
		return s.workEd25519v2
	case Ed25519SignatureType:
		return s.ed25519v2
	}
	return nil
}

// GetSuiteForCredentials returns a signature suite for credential signing based on a key type
// and model version of the signature requested
func (s *signatureSuites) GetSuiteForCredentials(signatureType SignatureType, version ModelVersion) (suite SignatureSuite, err error) {
	switch version {
	case V1:
		suite = s.getSuiteV1Cred(signatureType)
	case V2:
		suite = s.getSuiteV2Cred(signatureType)
	}
	if suite == nil {
		err = fmt.Errorf("unsupported signature type")
	}
	return
}

// GetSuiteForCredentialsProof returns the correct type of SignatureSuite to use to sign and verify
// proofs on Verifiable Credentials. These proofs have diverged from the standard proofs by using
// base64 encoding as a message digest.
func (s *signatureSuites) GetSuiteForCredentialsProof(proof *Proof) (suite SignatureSuite, err error) {
	switch proof.ModelVersion() {
	case V1:
		suite = s.getSuiteV1Cred(proof.Type)
	case V2:
		suite = s.getSuiteV2Cred(proof.Type)
	}
	if suite == nil {
		err = fmt.Errorf("unsupported signature type")
	}
	return
}

func (s *signatureSuites) getSuiteV1Cred(signatureType SignatureType) SignatureSuite {
	switch signatureType {
	case Ed25519SignatureType:
		return ed25519SignatureSuiteV1B64
	case WorkEdSignatureType:
		return workSignatureSuiteV1B64
	default:
		return nil
	}
}

func (s *signatureSuites) getSuiteV2Cred(signatureType SignatureType) SignatureSuite {
	switch signatureType {
	case Ed25519SignatureType:
		return ed25519SignatureSuiteV2B64
	case WorkEdSignatureType:
		return workSignatureSuiteV2B64
	case JCSEdSignatureType:
		return jcsEd25519SignatureSuite
	default:
		return nil
	}
}

func SignatureSuites() SignatureSuiteFactory {
	return &signatureSuites{
		jcsEd25519:    jcsEd25519SignatureSuite,
		workEd25519:   workSignatureSuiteV1,
		workEd25519v2: workSignatureSuiteV2,
		ed25519:       ed25519SignatureSuiteV1,
		ed25519v2:     ed25519SignatureSuiteV2,
		secp256k1:     secp256K1SignatureSuite,
	}
}

var (
	// General JCS signatures.
	jcsEd25519SignatureSuite = &LDSignatureSuite{
		SignatureType: JCSEdSignatureType,
		KeyType:       Ed25519KeyType,
		ProofFactory:  &proofFactoryV2{},
		Canonicalizer: &JCSCanonicalizer{},
		Marshaler:     &EmbeddedProofMarshaler{},
	}

	// General WorkEd25519 signatures with "creator" field.
	workSignatureSuiteV1 = withAndWithoutCanonicalizer(
		&LDSignatureSuite{
			SignatureType:   WorkEdSignatureType,
			KeyType:         Ed25519KeyType,
			ProofFactory:    &proofFactoryV1{},
			Marshaler:       &WithoutProofMarshaler{},
			Canonicalizer:   &JCSCanonicalizer{},
			OptionsAppender: &NonceAppender{},
		})

	// General WorkEd25519 signatures with "verificationMethod" field.
	workSignatureSuiteV2 = withAndWithoutCanonicalizer(
		withV2Proofs(workSignatureSuiteV1.main.(*LDSignatureSuite)))

	// WorkEd25519 signatures with "creator" field on credential proofs.
	workSignatureSuiteV1B64 = withAndWithoutCanonicalizer(
		withB64Digest(workSignatureSuiteV1.main.(*LDSignatureSuite)))

	// WorkEd25519 signatures with "verificationMethod" field on credential proofs.
	workSignatureSuiteV2B64 = withAndWithoutCanonicalizer(
		withV2Proofs(withB64Digest(workSignatureSuiteV1.main.(*LDSignatureSuite))))

	// Ed25519 signatures with "creator" field.
	ed25519SignatureSuiteV1 = withAndWithoutCanonicalizer(
		&LDSignatureSuite{
			SignatureType:   Ed25519SignatureType,
			KeyType:         Ed25519KeyType,
			ProofFactory:    &proofFactoryV1{},
			Marshaler:       &WithoutProofMarshaler{},
			Canonicalizer:   &JCSCanonicalizer{},
			OptionsAppender: &NonceAppender{},
		})

	// Ed25519 signatures with "verificationMethod" field.
	ed25519SignatureSuiteV2 = withAndWithoutCanonicalizer(
		withV2Proofs(ed25519SignatureSuiteV1.main.(*LDSignatureSuite)))

	// Ed25519 signatures with "creator" field on credential proofs.
	ed25519SignatureSuiteV1B64 = withAndWithoutCanonicalizer(
		withB64Digest(ed25519SignatureSuiteV1.main.(*LDSignatureSuite)))

	// Ed25519 signatures with "verificationMethod" field on credential proofs.
	ed25519SignatureSuiteV2B64 = withAndWithoutCanonicalizer(
		withV2Proofs(withB64Digest(ed25519SignatureSuiteV1.main.(*LDSignatureSuite))))

	// EcdsaSecp256k1 signatures with "creator" field used for administrative actions.
	secp256K1SignatureSuite = &LDSignatureSuite{
		SignatureType:   EcdsaSecp256k1SignatureType,
		KeyType:         EcdsaSecp256k1KeyType,
		ProofFactory:    &proofFactoryV1{},
		Marshaler:       &WithoutProofMarshaler{},
		Canonicalizer:   &JCSCanonicalizer{},
		OptionsAppender: &NonceAppender{},
	}
)

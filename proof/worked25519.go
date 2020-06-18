package proof

import (
	"crypto"
	cryptorand "crypto/rand"
	"fmt"
	"time"

	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/util"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

type WorkEd25519Signer struct {
	KeyID   string
	PrivKey ed25519.PrivateKey
}

func (e WorkEd25519Signer) Type() SignatureType {
	return WorkEdSignatureType
}

func (e WorkEd25519Signer) KeyType() KeyType {
	return WorkEdKeyType
}

func (e WorkEd25519Signer) ID() string {
	return e.KeyID
}

func (e WorkEd25519Signer) Sign(toSign []byte) ([]byte, error) {
	return e.PrivKey.Sign(cryptorand.Reader, toSign, crypto.Hash(0))
}

// Deprecated: this proof signing and verification models DO NOT sign over the proof object minus the signature
// value. Additionally, the nonce is appended to the signed over bytes before signing/verification.
// To create proofs in a supported manner please implement the `Provable` interface and use the CreateJCSEd25519Proof method.
func CreateWorkEd25519Proof(unsignedDoc []byte, keyRef string, privKey ed25519.PrivateKey, nonce string) (*Proof, error) {
	signer := &WorkEd25519Signer{
		KeyID:   keyRef,
		PrivKey: privKey,
	}
	return CreateWorkEd25519ProofGeneric(signer, unsignedDoc, keyRef, nonce, true)
}

// Deprecated: this proof signing and verification models DO NOT sign over the proof object minus the signature
// value. Additionally, the nonce is appended to the signed over bytes before signing/verification.
// To create proofs in a supported manner please implement the `Provable` interface and use the CreateJCSEd25519Proof method.
func CreateWorkEd25519ProofGeneric(s Signer, unsignedDoc []byte, keyRef, nonce string, creator bool) (*Proof, error) {
	toSign := util.AddNonceToDoc(unsignedDoc, nonce)
	signature, err := s.Sign(toSign)
	if err != nil {
		return nil, errors.New("failed to Sign JSON DOC")
	}

	b58sig := base58.Encode(signature)
	genTime := time.Now().UTC()

	if creator {
		return &Proof{
			Type:           s.Type(),
			Created:        genTime.Format(time.RFC3339),
			Creator:        keyRef,
			SignatureValue: b58sig,
			Nonce:          nonce,
		}, nil
	}
	return &Proof{
		Type:               s.Type(),
		Created:            genTime.Format(time.RFC3339),
		VerificationMethod: keyRef,
		SignatureValue:     b58sig,
		Nonce:              nonce,
	}, nil
}

// Deprecated: this deprecated proof signing and verification models DO NOT sign over the proof object minus the signature
// value. Additionally, the nonce is appended to the signed over bytes before signing/verification.
// To verify proofs in a supported manner please implement the `Provable` interface and use the VerifyJCSEd25519Proof method.
func VerifyWorkEd25519Proof(pubKey ed25519.PublicKey, proofUnderTest Proof, bytesToProve []byte) error {
	if isSignatureTypeSupported(proofUnderTest.Type) {
		return errors.Errorf("cannot verify proof with type %s as Ed25519 signature", proofUnderTest.Type)
	}
	toSign := util.AddNonceToDoc(bytesToProve, proofUnderTest.Nonce)
	sigBytes, err := base58.Decode(proofUnderTest.SignatureValue)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubKey, toSign, sigBytes) {
		return fmt.Errorf("failure while verifying signature (b58) %s for pub key (b58) %s", proofUnderTest.SignatureValue, base58.Encode(pubKey))
	}
	return nil
}

// Deprecated: this deprecated proof signing and verification models DO NOT sign over the proof object minus the signature
// value. Additionally, the nonce is appended to the signed over bytes before signing/verification.
// To verify proofs in a supported manner please implement the `Provable` interface and use the VerifyJCSEd25519Proof method.
func VerifyWorkEd25519ProofGeneric(pubKey ed25519.PublicKey, proofUnderTest Proof, toProve interface{}) error {
	if isSignatureTypeSupported(proofUnderTest.Type) {
		return errors.Errorf("cannot verify proof with type %s as Ed25519 signature", proofUnderTest.Type)
	}

	nonce := proofUnderTest.Nonce

	bytesToProve, err := canonical.Marshal(toProve)
	if err != nil {
		return err
	}

	toSign := util.AddNonceToDoc(bytesToProve, nonce)
	sigBytes, err := base58.Decode(proofUnderTest.SignatureValue)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubKey, toSign, sigBytes) {
		return fmt.Errorf("failure while verifying signature (b58) %s for pub key (b58) %s", proofUnderTest.SignatureValue, base58.Encode(pubKey))
	}
	return nil
}

func isSignatureTypeSupported(signatureType SignatureType) bool {
	return !(signatureType == WorkEdSignatureType || signatureType == Ed25519SignatureType)
}

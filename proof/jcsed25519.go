package proof

import (
	"crypto"
	cryptorand "crypto/rand"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/util"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

var (
	// Verifier is a signer without a key (just used for resolving the type)
	JCSEd25519Verifier = JCSEd25519Signer{}
)

type JCSEd25519Signer struct {
	KeyID   string
	PrivKey ed25519.PrivateKey
}

func (j JCSEd25519Signer) Type() SignatureType {
	return JCSEdSignatureType
}

func (j JCSEd25519Signer) KeyType() KeyType {
	return JCSEdKeyType
}

func (j JCSEd25519Signer) ID() string {
	return j.KeyID
}

func (j JCSEd25519Signer) Sign(toSign []byte) ([]byte, error) {
	return j.PrivKey.Sign(cryptorand.Reader, toSign, crypto.Hash(0))
}

func CreateJCSEd25519Proof(p Provable, s Signer, fullyQualifiedKeyRef string) (*Proof, error) {
	if s.Type() != JCSEdSignatureType {
		return nil, fmt.Errorf("cannot verify: expected<%s>, got <%s>", JCSEdSignatureType, s.Type())
	}

	currProof := p.GetProof()
	if !currProof.IsEmpty() && currProof.SignatureValue != "" {
		return nil, errors.New("proof value not set and/or signature value on proof already set")
	}

	// create and set unsigned proof value
	proof := Proof{
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: fullyQualifiedKeyRef,
		Nonce:              uuid.New().String(),
		Type:               JCSEdSignatureType,
	}
	p.SetProof(&proof)

	// Return proof to empty state after proof generation
	defer func() { p.SetProof(nil) }()

	toSign, err := canonical.Marshal(p)
	if err != nil {
		return nil, err
	}
	signature, err := s.Sign(toSign)
	if err != nil {
		return nil, errors.New("failed to sign doc")
	}

	proof.SignatureValue = base58.Encode(signature)
	return &proof, nil
}

// This method is not thread-safe; it modifies the `Provable` object during verification.
func VerifyJCSEd25519Proof(p Provable, s Signer, pubKey ed25519.PublicKey) error {
	if s.Type() != JCSEdSignatureType {
		return fmt.Errorf("cannot verify: expected<%s>, got <%s>", JCSEdSignatureType, s.Type())
	}

	// Make a copy of the provable object so this method is thread safe
	proof := p.GetProof()
	if proof.IsEmpty() {
		return errors.New("proof is empty or nil")
	}
	if proof.Type != JCSEdSignatureType {
		return errors.Errorf("cannot verify proof with type %s as Ed25519 signature", proof.Type)
	}

	var proofCopy Proof
	if err := util.DeepCopy(p.GetProof(), &proofCopy); err != nil {
		return err
	}
	sigBytes, err := base58.Decode(proofCopy.SignatureValue)
	if err != nil {
		return err
	}

	// Remove signature value from proof to validate
	p.SetProof(&Proof{
		Created:            proof.Created,
		VerificationMethod: proof.VerificationMethod,
		Nonce:              proof.Nonce,
		Type:               proof.Type,
	})

	// Put the proof back
	defer func() { p.SetProof(&proofCopy) }()

	toSign, err := canonical.Marshal(p)
	if err != nil {
		return err
	}

	if valid := ed25519.Verify(pubKey, toSign, sigBytes); !valid {
		return fmt.Errorf("failure while verifying signature (b58) %s for pub key (b58) %s", proof.SignatureValue, base58.Encode(pubKey))
	}
	return nil
}

package proof

import (
	"crypto"
	cryptorand "crypto/rand"
	"testing"
	"time"

	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/util"
)

var (
	nonce             = "0948bb75-60c2-4a92-ad50-01ccee169ae0"
	creatorKey        = "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1"
	expectedSignature = "2NQNA7SXVrTJRPYGAtpdxXAaKZDdzzQ3XYEghVVhRKH8AGrNS9kHa4USgbUYxbgG3wHpF8Qzou34P5jqYC9x4UYE"

	testJSON      = `{"some":"one","test":"two","structure":"three"}`
	differentJSON = `{"some":"one","test":"two","structure":"banana"}`
	keySeed       = []byte("12345678901234567890123456789012")
	issuerPrivKey = ed25519.NewKeyFromSeed(keySeed) // this matches the public key in didDocJson
	issuerPubKey  = issuerPrivKey.Public().(ed25519.PublicKey)
)

func TestProofGeneration(t *testing.T) {
	proofUnderTest, err := CreateWorkEd25519Proof([]byte(testJSON), creatorKey, issuerPrivKey, nonce)
	assert.NoError(t, err)
	assert.Equal(t, proofUnderTest.Nonce, nonce)
	assert.Equal(t, proofUnderTest.GetVerificationMethod(), creatorKey)
	assert.Equal(t, expectedSignature, proofUnderTest.SignatureValue)
	assert.NoError(t, VerifyWorkEd25519Proof(issuerPubKey, *proofUnderTest, []byte(testJSON)))
}

func TestVerificationOfProof(t *testing.T) {
	proofUnderTest, _ := CreateWorkEd25519Proof([]byte(testJSON), creatorKey, issuerPrivKey, nonce)
	err := VerifyWorkEd25519Proof(issuerPubKey, *proofUnderTest, []byte(testJSON))
	assert.NoError(t, err)

	err = VerifyWorkEd25519Proof(issuerPubKey, *proofUnderTest, []byte(differentJSON))
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "failure while verifying signature (b58) 2NQNA7SXVrTJRPYGAtpdxXAaKZDdzzQ3XYEghVVhRKH8AGrNS9kHa4USgbUYxbgG3wHpF8Qzou34P5jqYC9x4UYE for pub key (b58) 4CcKDtU1JNGi8U4D8Rv9CHzfmF7xzaxEAPFA54eQjRHF")
}

func TestBadProofType(t *testing.T) {
	toSign := util.AddNonceToDoc([]byte(testJSON), nonce)
	signature, err := issuerPrivKey.Sign(cryptorand.Reader, toSign, crypto.Hash(0))
	assert.NoError(t, err)

	b58sig := base58.Encode(signature)
	genTime := time.Now().UTC()
	proof := &Proof{
		Type:           "BAD_TYPE",
		Created:        genTime.Format(time.RFC3339),
		Creator:        creatorKey,
		SignatureValue: b58sig,
		Nonce:          nonce,
	}

	err = VerifyWorkEd25519Proof(issuerPubKey, *proof, []byte(testJSON))
	assert.Error(t, err)
}

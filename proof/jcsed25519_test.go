package proof

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

var (
	seed    = []byte("12345678901234567890123456789012")
	privKey = ed25519.NewKeyFromSeed(seed)
	pubKey  = privKey.Public().(ed25519.PublicKey)
)

func TestCreateAndVerifyJCSEd25519Proof(t *testing.T) {
	testSigner := JCSEd25519Signer{KeyID: "key-ref", PrivKey: privKey}

	t.Run("Happy path sign and verify", func(t *testing.T) {
		testData := GenericProvable{JSONData: "testData"}

		// Create and set proof
		proof, err := CreateJCSEd25519Proof(&testData, testSigner, "key-ref")
		assert.NoError(t, err)
		testData.Proof = proof

		err = VerifyJCSEd25519Proof(&testData, testSigner, pubKey)
		assert.NoError(t, err)
	})

	t.Run("Bad pub key - can't verify", func(t *testing.T) {
		testData := GenericProvable{JSONData: "testData"}

		// Create and set proof
		proof, err := CreateJCSEd25519Proof(&testData, testSigner, "key-ref")
		assert.NoError(t, err)
		testData.Proof = proof

		badPubKey := make([]byte, ed25519.PublicKeySize)
		err = VerifyJCSEd25519Proof(&testData, testSigner, badPubKey)
		assert.Error(t, err)
	})

	t.Run("Non JCS Signer", func(t *testing.T) {
		testData := GenericProvable{JSONData: "testData"}

		badSigner := WorkEd25519Signer{KeyID: "key-ref", PrivKey: privKey}
		_, err := CreateJCSEd25519Proof(&testData, badSigner, "key-ref")
		assert.Error(t, err)
	})

	t.Run("Non JCS Verifier", func(t *testing.T) {
		testData := GenericProvable{JSONData: "testData"}

		// Create and set proof
		proof, err := CreateJCSEd25519Proof(&testData, testSigner, "key-ref")
		assert.NoError(t, err)
		testData.Proof = proof

		badVerifier := WorkEd25519Signer{KeyID: "key-ref", PrivKey: privKey}
		err = VerifyJCSEd25519Proof(&testData, badVerifier, pubKey)
		assert.Error(t, err)
	})
}

package examples

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
)

func TestDIDDoc_create(t *testing.T) {
	// First, choose a key type. We pick the standard Ed25519KeyType type.
	// Next, pass it to our generate method which will return the complete, signed document, along
	// with the associated private key that should be stored safely.
	didDoc, privKey := did.GenerateWorkDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)

	assert.NotEmpty(t, didDoc)
	assert.NotEmpty(t, privKey)

	// uncomment me to print out the DID Doc
	// fmt.Printf("%+v", didDoc)
}

func TestDIDDoc_sign_verify(t *testing.T) {
	// First, choose a key type. We pick the standard Ed25519KeyType type.
	// Next, pass it to our generate method which will return the complete, signed document, along
	// with the associated private key that should be stored safely.
	didDoc, privKey := did.GenerateWorkDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)

	// We can use the private key to sign a sample piece of data
	testData := &proof.GenericProvable{
		JSONData: "{\"test\":\"data\"}",
	}

	// Create a JCSEd25519 signer for our private key set to use the key reference for our private key
	keyRef, err := didDoc.PublicKey[0].GetKeyFragment()
	assert.NoError(t, err)

	signer, err := proof.NewEd25519Signer(privKey, keyRef)
	assert.NoError(t, err)

	// Get the signature suite associated with our DID Document
	suite, err := proof.SignatureSuites().GetSuite(proof.JCSEdSignatureType, proof.V2)
	assert.NoError(t, err)

	err = suite.Sign(testData, signer, nil)
	assert.NoError(t, err)

	// Create a verifier using the public key in our DID Document
	pubKey, err := didDoc.PublicKey[0].GetDecodedPublicKey()
	assert.NoError(t, err)
	verifier := &proof.Ed25519Verifier{PubKey: pubKey}

	err = suite.Verify(testData, verifier)
	assert.NoError(t, err)
}

func TestDIDDoc_deactivate(t *testing.T) {
	// First, choose a signing type. We pick the standard Ed25519KeyType type.
	// Next, pass it to our generate method which will return the complete, signed document, along
	// with the associated private key that should be stored safely.
	didDoc, privKey := did.GenerateWorkDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)

	// Make sure there are keys visible in the document
	assert.NotEmpty(t, didDoc.PublicKey)

	// Now deactivate the document
	deactivated, err := did.DeactivateDIDDoc(*didDoc, privKey)
	assert.NoError(t, err)

	// Make sure there are no keys visible in the document
	assert.Empty(t, deactivated.PublicKey)

	// Validate signature with original pub key
	verifier := &proof.Ed25519Verifier{PubKey: privKey.Public().(ed25519.PublicKey)}
	suite, err := proof.SignatureSuites().GetSuiteForProof(deactivated.GetProof())
	assert.NoError(t, err)

	err = suite.Verify(deactivated, verifier)
	assert.NoError(t, err)
}

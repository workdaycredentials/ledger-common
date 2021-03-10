package didcomm

import (
	"crypto/ed25519"
	"testing"

	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"

	"go.wday.io/credentials-open-source/ledger-common/did"
	"go.wday.io/credentials-open-source/ledger-common/proof"
)

func TestCreateAndVerifyJWS(t *testing.T) {
	doc, _, privKey2 := generateDIDDocMultipleKeys(proof.JCSEdSignatureType)
	data, err := CreateAttachmentData(doc.PublicKey[1].ID, *doc, privKey2)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	err = VerifyAttachmentData(*data, doc.PublicKey[1].ID)
	assert.NoError(t, err)
}

func generateDIDDocMultipleKeys(signatureType proof.SignatureType) (*did.DIDDoc, ed25519.PrivateKey, ed25519.PrivateKey) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	publicKey2, privateKey2, _ := ed25519.GenerateKey(nil)

	id := did.GenerateDID(publicKey)
	signingKeyRef := did.GenerateKeyID(id, did.InitialKey)

	var didPubKeys = []did.KeyDef{
		{
			ID:              signingKeyRef,
			Type:            proof.Ed25519KeyType,
			Controller:      id,
			PublicKeyBase58: base58.Encode(publicKey),
		},
		{
			ID:              "did:lcn:123456abcdefg#key-" + uuid.New().String(),
			Type:            proof.Ed25519KeyType,
			Controller:      id,
			PublicKeyBase58: base58.Encode(publicKey2),
		},
	}

	doc := did.DIDDoc{
		ID:        id,
		PublicKey: didPubKeys,
	}

	signer, _ := proof.NewEd25519Signer(privateKey, signingKeyRef)
	suite, _ := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	_ = suite.Sign(&doc, signer, nil)
	return &doc, privateKey, privateKey2
}

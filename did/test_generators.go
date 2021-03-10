package did

import (
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ed25519"

	"go.wday.io/credentials-open-source/ledger-common/proof"
)

func GenerateDIDDocWithContext(keyType proof.KeyType, signatureType proof.SignatureType) (*DIDDoc, ed25519.PrivateKey) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	id := GenerateDID(publicKey)
	signingKeyRef := GenerateKeyID(id, InitialKey)

	var didPubKeys = []KeyDef{{
		ID:              signingKeyRef,
		Type:            keyType,
		Controller:      id,
		PublicKeyBase58: base58.Encode(publicKey),
	}}

	doc := DIDDoc{
		SchemaContext: []string{SchemaContext},
		ID:            id,
		PublicKey:     didPubKeys,
	}

	signer, _ := proof.NewEd25519Signer(privateKey, signingKeyRef)
	suite, _ := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	_ = suite.Sign(&doc, signer, nil)
	return &doc, privateKey
}

func GenerateDIDDoc(keyType proof.KeyType, signatureType proof.SignatureType) (*DIDDoc, ed25519.PrivateKey) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)

	id := GenerateDID(publicKey)
	signingKeyRef := GenerateKeyID(id, InitialKey)

	var didPubKeys = []KeyDef{{
		ID:              signingKeyRef,
		Type:            keyType,
		Controller:      id,
		PublicKeyBase58: base58.Encode(publicKey),
	}}

	doc := DIDDoc{
		ID:        id,
		PublicKey: didPubKeys,
	}

	signer, _ := proof.NewEd25519Signer(privateKey, signingKeyRef)
	suite, _ := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	_ = suite.Sign(&doc, signer, nil)
	return &doc, privateKey
}

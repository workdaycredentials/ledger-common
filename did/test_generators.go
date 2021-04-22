package did

import (
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/proof"
)

func GenerateWorkDIDDocWithContext(keyType proof.KeyType, signatureType proof.SignatureType, context []string) (*DIDDoc, ed25519.PrivateKey) {
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
		SchemaContext: context,
		ID:            id,
		PublicKey:     didPubKeys,
	}

	// TODO: new DIDDocs should no longer have proofs
	signer, _ := proof.NewEd25519Signer(privateKey, signingKeyRef)
	suite, _ := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	_ = suite.Sign(&doc, signer, nil)
	return &doc, privateKey
}

func GenerateWorkDIDDoc(keyType proof.KeyType, signatureType proof.SignatureType) (*DIDDoc, ed25519.PrivateKey) {
	return GenerateWorkDIDDocWithContext(keyType, signatureType, nil)
}

package did

import (
	"github.com/mr-tron/base58"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/proof"
)

func GenerateDIDDocWithContext(signerType proof.SignatureType) (*DIDDoc, ed25519.PrivateKey) {
	pk, sk, _ := ed25519.GenerateKey(nil)

	var signer proof.Signer
	switch signerType {
	case proof.JCSEdSignatureType:
		signer = proof.JCSEd25519Signer{PrivKey: sk}

	case proof.Ed25519SignatureType:
		fallthrough

	case proof.WorkEdSignatureType:
		signer = proof.WorkEd25519Signer{PrivKey: sk}
	default:
		logrus.Errorf("unsupported signer: %s", signerType)
		return nil, nil
	}

	id := GenerateDID(pk)
	signingKeyRef := id + "#" + InitialKey

	var didPubKeys = []KeyDef{{
		ID:              signingKeyRef,
		Type:            proof.GetCorrespondingKeyType(signer.Type()),
		Controller:      id,
		PublicKeyBase58: base58.Encode(pk),
	}}

	doc := UnsignedDIDDoc{
		SchemaContext: SchemaContext,
		ID:            id,
		PublicKey:     didPubKeys,
	}

	signedDoc, _ := SignDIDDocGeneric(signer, doc, signingKeyRef)
	return signedDoc, sk
}

func GenerateDIDDoc(signerType proof.SignatureType) (*DIDDoc, ed25519.PrivateKey) {
	pk, sk, _ := ed25519.GenerateKey(nil)

	var signer proof.Signer
	switch signerType {
	case proof.JCSEdSignatureType:
		signer = proof.JCSEd25519Signer{PrivKey: sk}

	case proof.Ed25519SignatureType:
		fallthrough

	case proof.WorkEdSignatureType:
		signer = proof.WorkEd25519Signer{PrivKey: sk}
	default:
		logrus.Errorf("unsupported signer: %s", signerType)
		return nil, nil
	}

	id := GenerateDID(pk)
	signingKeyRef := id + "#" + InitialKey

	var didPubKeys = []KeyDef{{
		ID:              signingKeyRef,
		Type:            proof.GetCorrespondingKeyType(signer.Type()),
		Controller:      id,
		PublicKeyBase58: base58.Encode(pk),
	}}

	doc := UnsignedDIDDoc{
		ID:        id,
		PublicKey: didPubKeys,
	}
	signedDoc, _ := SignDIDDocGeneric(signer, doc, signingKeyRef)
	return signedDoc, sk
}

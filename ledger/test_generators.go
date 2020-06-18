package ledger

import (
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

func GenerateLedgerDIDDoc(signatureType proof.SignatureType) (*DIDDoc, ed25519.PrivateKey) {
	pk, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	id := did.GenerateDID(pk)
	signingKeyRef := id + "#" + did.InitialKey
	pubKeys := make(map[string]ed25519.PublicKey)
	pubKeys[did.InitialKey] = pk

	var signer proof.Signer
	switch signatureType {
	case proof.JCSEdSignatureType:
		signer = proof.JCSEd25519Signer{PrivKey: sk}

	case proof.Ed25519SignatureType:
		fallthrough

	case proof.WorkEdSignatureType:
		signer = proof.WorkEd25519Signer{PrivKey: sk}
	default:
		logrus.Errorf("unsupported signature type: %s", signatureType)
		return nil, nil
	}

	ledgerDIDDoc, err := GenerateDIDDocInput{
		DID:                  id,
		FullyQualifiedKeyRef: signingKeyRef,
		Signer:               signer,
		PublicKeys:           pubKeys,
		Issuer:               id,
	}.GenerateLedgerDIDDoc()
	if err != nil {
		panic(err)
	}
	return ledgerDIDDoc, sk
}

func GenerateLedgerRevocation(credentialID string, issuer string, signer proof.Signer, keyRef string) (*Revocation, error) {
	timeStamp := time.Now().UTC().Format(time.RFC3339)
	r := &UnsignedRevocation{
		ID:           GenerateRevocationKey(issuer, credentialID),
		CredentialID: credentialID,
		IssuerDID:    issuer,
		ReasonCode:   0,
		Revoked:      timeStamp,
	}
	metadata := &Metadata{
		Type:         util.RevocationTypeReference_v1_0,
		ModelVersion: util.Version_1_0,
		ID:           r.ID,
		Author:       issuer,
		Authored:     timeStamp,
	}
	ledgerRevocation := Revocation{
		UnsignedRevocation: r,
		Metadata:           metadata,
	}
	if err := SignLedgerDocGeneric(signer, ledgerRevocation, keyRef); err != nil {
		return nil, err
	}
	return &ledgerRevocation, nil
}

func GenerateLedgerSchema(name, author, signingKeyRef string, signer proof.Signer, schema map[string]interface{}) (*Schema, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	s := Schema{
		Metadata: &Metadata{
			Type:         util.SchemaTypeReference_v1_0,
			ModelVersion: util.Version_1_0,
			ID:           GenerateSchemaID(author, util.Version_1_0),
			Name:         name,
			Author:       author,
			Authored:     now,
		},
		JSONSchema: &JSONSchema{Schema: schema},
	}
	if err := SignLedgerDocGeneric(signer, s, signingKeyRef); err != nil {
		return nil, err
	}
	return &s, nil
}

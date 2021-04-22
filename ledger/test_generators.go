package ledger

import (
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

func GenerateLedgerDIDDoc(keyType proof.KeyType, signatureType proof.SignatureType) (*DIDDoc, ed25519.PrivateKey) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	id := did.GenerateDID(publicKey)
	keyID := did.GenerateKeyID(id, did.InitialKey)
	signingKeyRef := keyID
	pubKeys := make(map[string]ed25519.PublicKey)
	pubKeys[did.InitialKey] = publicKey

	if keyType == proof.EcdsaSecp256k1KeyType {
		logrus.Errorf("Unsupported type: %s", proof.EcdsaSecp256k1KeyType)
		return nil, nil
	}
	signer, err := proof.NewEd25519Signer(privateKey, keyID)

	ledgerDIDDoc, err := GenerateDIDDocInput{
		DID:                  id,
		FullyQualifiedKeyRef: signingKeyRef,
		Signer:               signer,
		SignatureType:        signatureType,
		PublicKeys:           pubKeys,
		Issuer:               id,
	}.GenerateLedgerDIDDoc()
	if err != nil {
		panic(err)
	}
	return ledgerDIDDoc, privateKey
}

func GenerateLedgerRevocation(credentialID string, issuer did.DID, signer proof.Signer, signatureType proof.SignatureType) (*Revocation, error) {
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
	suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	if err != nil {
		return nil, err
	}
	opts := &proof.ProofOptions{ProofPurpose: proof.AssertionMethodPurpose}
	err = suite.Sign(ledgerRevocation, signer, opts)
	return &ledgerRevocation, err
}

func GenerateLedgerSchema(name string, author did.DID, signer proof.Signer, signatureType proof.SignatureType, schema map[string]interface{}) (*Schema, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	ledgerSchema := Schema{
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
	suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	if err != nil {
		return nil, err
	}
	opts := &proof.ProofOptions{ProofPurpose: proof.AssertionMethodPurpose}
	err = suite.Sign(ledgerSchema, signer, opts)
	return &ledgerSchema, err
}

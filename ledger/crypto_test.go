package ledger

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

func TestDIDDocProof(t *testing.T) {
	ed25519KeyType := proof.Ed25519KeyType
	signatureType := proof.WorkEdSignatureType
	doc, privateKey := did.GenerateDIDDoc(ed25519KeyType, signatureType)
	pubKey := privateKey.Public().(ed25519.PublicKey)
	ledgerDoc := DIDDoc{
		Metadata: &Metadata{
			Type:         util.DIDDocTypeReference_v1_0,
			ModelVersion: util.Version_1_0,
			ID:           doc.ID,
			Author:       doc.PublicKey[0].Controller,
			Authored:     time.Now().UTC().Format(time.RFC3339),
		},
		DIDDoc: doc,
	}

	suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	assert.NoError(t, err)

	signer, err := proof.NewEd25519Signer(privateKey, didDoc.PublicKey[0].ID)
	assert.NoError(t, err)

	assert.NoError(t, suite.Sign(&ledgerDoc, signer))

	verifier := &proof.Ed25519Verifier{PubKey: pubKey}
	assert.NoError(t, suite.Verify(&ledgerDoc, verifier))

	// Validate using methods on did doc
	assert.NoError(t, didDoc.ValidateProof())

	provider := TestDIDDocProvider{Records: map[string]*DIDDoc{didDoc.ID: didDoc}}
	assert.NoError(t, didDoc.Validate(context.Background(), provider.GetDIDDoc))
}

func TestVerifySchemaProof(t *testing.T) {
	testSchema := `{
	  "$schema": "http://json-schema.org/draft-07/schema#",
	  "description": "Name Credential Object",
	  "type": "object",
	  "properties": {
		"title": {
		  "type": "string",
		  "format": "fake"
		},
		"firstName": {
		  "type": "string",
		  "format": "fake"
		},
		"lastName": {
		  "type": "string",
		  "format": "fake"
		},
		"middleName": {
		  "type": "string",
		  "format": "fake"
		},
		"suffix": {
		  "type": "string",
		  "format": "fake"
		}
	  },
	  "required": ["firstName", "lastName"],
	  "additionalProperties": false
	 }
	`

	var s JSONSchemaMap
	assert.NoError(t, json.Unmarshal([]byte(testSchema), &s))

	signatureType := proof.WorkEdSignatureType
	ed25519KeyType := proof.Ed25519KeyType
	didDoc, privKey := GenerateLedgerDIDDoc(ed25519KeyType, signatureType)
	now := time.Now().UTC().Format(time.RFC3339)
	pubKey, err := base58.Decode(didDoc.PublicKey[0].PublicKeyBase58)
	assert.NoError(t, err)

	schema := Schema{
		Metadata: &Metadata{
			Type:         util.SchemaTypeReference_v1_0,
			ModelVersion: util.Version_1_0,
			ID:           GenerateSchemaID(didDoc.ID, "1.0"),
			Name:         "Name",
			Author:       didDoc.ID,
			Authored:     now,
		},
		JSONSchema: &JSONSchema{Schema: s},
	}

	suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	assert.NoError(t, err)

	signer, err := proof.NewEd25519Signer(privKey, didDoc.PublicKey[0].ID)
	assert.NoError(t, err)

	assert.NoError(t, suite.Sign(schema, signer))

	verifier := &proof.Ed25519Verifier{PubKey: pubKey}
	assert.NoError(t, suite.Verify(schema, verifier))

	// Validate using method on schema
	provider := TestDIDDocProvider{Records: map[string]*DIDDoc{didDoc.ID: didDoc}}
	assert.NoError(t, schema.ValidateProof(context.Background(), provider.GetDIDDoc))
	assert.NoError(t, schema.ValidateStatic())
}

// Revocation //

func TestHashing(t *testing.T) {
	var signingDID = "did:work:UpguDp5Sq4py71M9mqKHJA"

	key := GenerateRevocationKey(signingDID, CredentialID)
	assert.Equal(t, "GjqBiRAsdSbZgUKB2AtMWYyhrs7WtNH3eoAvQ6qY7q2v", key)
}

func TestVerifyRevocationProof(t *testing.T) {
	signatureType := proof.WorkEdSignatureType
	ed25519KeyType := proof.Ed25519KeyType
	didDoc, privKey := GenerateLedgerDIDDoc(ed25519KeyType, signatureType)
	keyRef := didDoc.PublicKey[0].ID

	signer, err := proof.NewEd25519Signer(privKey, keyRef)
	assert.NoError(t, err)

	revocation, err := GenerateLedgerRevocation(CredentialID, didDoc.ID, signer, signatureType)
	assert.NoError(t, err)

	// Validate using methods on revocation
	provider := TestDIDDocProvider{Records: map[string]*DIDDoc{didDoc.ID: didDoc}}
	assert.NoError(t, revocation.ValidateProof(context.Background(), provider.GetDIDDoc))
	assert.NoError(t, revocation.ValidateStatic())
}

func TestGenericVerify(t *testing.T) {
	// Create DID Doc and mock provider
	ed25519KeyType := proof.Ed25519KeyType
	signatureType := proof.WorkEdSignatureType
	didDoc, privKey := GenerateLedgerDIDDoc(ed25519KeyType, signatureType)
	keyRef := didDoc.PublicKey[0].ID

	provider := TestDIDDocProvider{Records: map[string]*DIDDoc{didDoc.ID: didDoc}}

	signer, err := proof.NewEd25519Signer(privKey, keyRef)
	assert.NoError(t, err)

	suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	assert.NoError(t, err)

	testData := proof.GenericProvable{
		JSONData: "{\"test\":\"data\"}",
	}

	err = suite.Sign(&testData, signer)
	assert.NoError(t, err)

	// now verify
	err = Verify(ctx, &testData, provider.GetDIDDoc)
	assert.NoError(t, err)
}

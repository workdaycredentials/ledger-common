package examples

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"go.wday.io/credentials-open-source/ledger-common/credential"
	"go.wday.io/credentials-open-source/ledger-common/ledger"
	"go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas/name"
	"go.wday.io/credentials-open-source/ledger-common/proof"
)

func TestRevocation(t *testing.T) {
	// First, create a schema
	// create an issuer and target holder for the credential
	issuerDoc, issuerPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	holderDoc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)

	// select a schema
	nameSchema := name.Name
	nameSchemaMap := ledger.JSONSchemaMap{}
	err := json.Unmarshal([]byte(nameSchema), &nameSchemaMap)
	assert.NoError(t, err)

	// create a signer with the issuer's private key to author the schema and later the credential
	signer, err := proof.NewEd25519Signer(issuerPrivKey, issuerDoc.PublicKey[0].ID)
	assert.NoError(t, err)

	// turn it into a ledger schema to give it an identifier
	// here we are using the issuer as the author of the schema
	ledgerSchema, err := ledger.GenerateLedgerSchema("Name Schema", issuerDoc.DIDDoc.ID, signer, proof.JCSEdSignatureType, nameSchemaMap)
	assert.NoError(t, err)

	// choose a cred id
	credID := uuid.New().String()

	// create the credential metadata (this one doesn't expire)
	baseRevocationURL := "https://testrevocationservice.com/"
	metadata := credential.NewMetadataWithTimestamp(credID, issuerDoc.DIDDoc.ID, ledgerSchema.ID, baseRevocationURL, time.Now())

	// build the credential
	cred, err := credential.Builder{
		SubjectDID: holderDoc.DIDDoc.ID,
		// according to the schema, only the first and last name fields are required
		Data: map[string]interface{}{
			"firstName": "Genghis",
			"lastName":  "Khan",
		},
		Metadata:      &metadata,
		Signer:        signer,
		SignatureType: proof.JCSEdSignatureType,
	}.Build()

	assert.NoError(t, err)
	assert.NotEmpty(t, cred)

	// Next, create a revocation for the schema using the same DID used to issue the credential
	revocation, err := ledger.GenerateLedgerRevocation(cred.ID, issuerDoc.DIDDoc.ID, signer, proof.JCSEdSignatureType)
	assert.NoError(t, err)
	assert.NotEmpty(t, revocation)
	assert.Equal(t, revocation.CredentialID, cred.ID)
	assert.Equal(t, revocation.IssuerDID, cred.Issuer)

	// uncomment me to print out the Revocation
	// b, _ := json.Marshal(revocation)
	// println(string(b))
}

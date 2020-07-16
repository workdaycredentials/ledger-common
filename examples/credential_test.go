package examples

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/credential/schema"
	"github.com/workdaycredentials/ledger-common/ledger"
	schemaValidation "github.com/workdaycredentials/ledger-common/ledger/schema"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/name"
	"github.com/workdaycredentials/ledger-common/proof"
)

func TestCredential(t *testing.T) {
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
	ledgerSchema, err := ledger.GenerateLedgerSchema("Name Schema", issuerDoc.ID, signer, proof.JCSEdSignatureType, nameSchemaMap)
	assert.NoError(t, err)

	// choose a cred id
	credID := uuid.New().String()

	// create the credential metadata (this one doesn't expire)
	metadata := credential.NewMetadataWithTimestamp(credID, issuerDoc.ID, ledgerSchema.ID, time.Now())

	// build the credential
	cred, err := credential.Builder{
		SubjectDID: holderDoc.ID,
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

	// Turn the cred into JSON
	credJSON, err := cred.ToJSON()
	assert.NoError(t, err)

	// For sanity, we can validate the credential against the schema that defines the shape of all credentials
	credSchema, err := schema.GetSchema(schema.VerifiableCredentialSchema)
	assert.NoError(t, err)

	assert.NoError(t, schemaValidation.Validate(credSchema, credJSON))

	// We can also validate the credential's data against the credential's name schema
	assert.NoError(t, schemaValidation.ValidateCredential(nameSchema, credJSON))

	// uncomment me to print out the Verifiable Credential
	// fmt.Printf("%s", credJSON)
}

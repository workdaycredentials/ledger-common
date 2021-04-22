package examples

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/workdaycredentials/ledger-common/ledger"
	. "github.com/workdaycredentials/ledger-common/ledger/schema"
	"github.com/workdaycredentials/ledger-common/proof"
)

func TestSchema_create(t *testing.T) {
	// First create a JSON Schema
	description := "Contact Information"
	attrs := []Attribute{
		{
			Name:     "firstName",
			Type:     String,
			Required: true,
		},
		{
			Name:     "middleName",
			Type:     String,
			Required: false,
		},
		{
			Name:     "lastName",
			Type:     String,
			Required: true,
		},
		{
			Name:       "email",
			Type:       String,
			StringType: &StringType{Format: Email},
			Required:   true,
		},
	}
	schema, err := Builder{
		Name:                 "Contact",
		Description:          description,
		AdditionalProperties: false,
		Attributes:           attrs,
	}.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, schema)

	// Verify data
	properties := schema.Properties()
	assert.Contains(t, properties, "firstName")
	assert.Contains(t, properties, "middleName")
	assert.Contains(t, properties, "lastName")
	assert.Contains(t, properties, "email")

	assert.Equal(t, description, schema.Description())
	assert.Equal(t, false, schema.AllowsAdditionalProperties())
	assert.Equal(t, []string{"firstName", "lastName", "email"}, schema.RequiredFields())

	// Check if it's a valid json schema
	assert.NoError(t, ValidateJSONSchema(schema))

	// Next take the schema and turn it into a "ledger schema" to add authorship, versioning, and identifier info

	// Create a DID Doc to author the schema
	authorDID, privateKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)

	// Create a signer that wraps the author's private key
	signer, err := proof.NewEd25519Signer(privateKey, authorDID.PublicKey[0].ID)
	assert.NoError(t, err)

	// Build a ledger schema with a name, author DID, signer, signature type, and json schema
	ledgerSchema, err := ledger.GenerateLedgerSchema("Contact Info Schema", authorDID.DIDDoc.ID, signer, proof.JCSEdSignatureType, schema)
	assert.NoError(t, err)
	assert.NotEmpty(t, ledgerSchema)

	// The ledger schema can now be used as a backing for a verifiable credentials
	// uncomment me to print out the Ledger Schema
	// fmt.Printf("%+v", ledgerSchema)
}

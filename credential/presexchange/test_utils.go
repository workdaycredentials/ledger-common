package presexchange

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/decentralized-identity/presentation-exchange-implementations/pkg/definition"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/ledger"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/email"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/name"
	"github.com/workdaycredentials/ledger-common/proof"
)

const (
	signatureType = proof.JCSEdSignatureType
)

type credGenInput struct {
	issuerPrivKey ed25519.PrivateKey
	issuerDoc     ledger.DIDDoc
	holderDoc     ledger.DIDDoc
}

func makeMeANameCred(t *testing.T, input credGenInput) *credential.VerifiableCredential {
	// select a schema
	nameSchema := name.Name
	nameSchemaMap := ledger.JSONSchemaMap{}
	err := json.Unmarshal([]byte(nameSchema), &nameSchemaMap)
	assert.NoError(t, err)

	// create a signer with the issuer's private key to author the schema and later the credential
	signer, err := proof.NewEd25519Signer(input.issuerPrivKey, input.issuerDoc.PublicKey[0].ID)
	assert.NoError(t, err)

	// turn it into a ledger schema to give it an identifier
	// here we are using the issuer as the author of the schema
	ledgerSchema, err := ledger.GenerateLedgerSchema("Name Schema", input.issuerDoc.DIDDoc.ID, signer, proof.JCSEdSignatureType, nameSchemaMap)
	assert.NoError(t, err)

	// choose a cred id
	credID := uuid.New().String()

	// create the credential metadata (this one doesn't expire)
	baseRevocationURL := "https://testrevocationservice.com/"
	metadata := credential.NewMetadataWithTimestamp(credID, input.issuerDoc.DIDDoc.ID, ledgerSchema.ID, baseRevocationURL, time.Now())

	// build the credential
	cred, err := credential.Builder{
		SubjectDID: input.holderDoc.DIDDoc.ID,
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
	return cred
}

func makeMeAnEmailCred(t *testing.T, input credGenInput) *credential.VerifiableCredential {
	// select a schema
	emailSchema := email.Email
	emailSchemaMap := ledger.JSONSchemaMap{}
	err := json.Unmarshal([]byte(emailSchema), &emailSchemaMap)
	assert.NoError(t, err)

	// create a signer with the issuer's private key to author the schema and later the credential
	signer, err := proof.NewEd25519Signer(input.issuerPrivKey, input.issuerDoc.PublicKey[0].ID)
	assert.NoError(t, err)

	// turn it into a ledger schema to give it an identifier
	// here we are using the issuer as the author of the schema
	ledgerSchema, err := ledger.GenerateLedgerSchema("Email Schema", input.issuerDoc.DIDDoc.ID, signer, proof.JCSEdSignatureType, emailSchemaMap)
	assert.NoError(t, err)

	// choose a cred id
	credID := uuid.New().String()

	// create the credential metadata (this one doesn't expire)
	baseRevocationURL := "https://testrevocationservice.com/"
	metadata := credential.NewMetadataWithTimestamp(credID, input.issuerDoc.DIDDoc.ID, ledgerSchema.ID, baseRevocationURL, time.Now())

	// build the credential
	cred, err := credential.Builder{
		SubjectDID: input.holderDoc.DIDDoc.ID,
		// according to the schema, only the first and last name fields are required
		Data: map[string]interface{}{
			"emailAddress": "genghis.khan@conquering.you",
		},
		Metadata:      &metadata,
		Signer:        signer,
		SignatureType: proof.JCSEdSignatureType,
	}.Build()

	assert.NoError(t, err)
	assert.NotEmpty(t, cred)
	return cred
}

func makeMeAPresentationDefinition(t *testing.T, nameSchemaID, emailSchemaID string) definition.PresentationDefinition {
	builder := definition.NewPresentationDefinitionBuilder()
	builder.SetLocale(enUSLocale)

	nameInput := definition.NewInputDescriptor("name_input", "Name Schema", "To get an individual's first name", "")
	err := nameInput.AddSchema(definition.Schema{
		URI: nameSchemaID,
	})
	assert.NoError(t, err)

	// make sure the first name is there
	firstNameField := definition.NewConstraintsField([]string{"$.credentialSubject.firstName"})
	firstNameField.SetPurpose("We need your first name")
	err = firstNameField.SetFilter(definition.Filter{
		Type:      "string",
		MinLength: 2,
	})
	assert.NoError(t, err)

	// add all constraints
	err = nameInput.SetConstraints(*firstNameField)
	assert.NoError(t, err)

	// add the name input descriptor
	err = builder.AddInputDescriptor(*nameInput)
	assert.NoError(t, err)

	// add the email input descriptor
	emailInput := definition.NewInputDescriptor("email_input", "Email Schema", "To get an individual's email", "")
	err = emailInput.AddSchema(definition.Schema{
		URI: emailSchemaID,
	})
	assert.NoError(t, err)

	// make sure the email is there
	emailField := definition.NewConstraintsField([]string{"$.credentialSubject.emailAddress"})
	emailField.SetPurpose("We need your email")
	err = emailField.SetFilter(definition.Filter{
		Type:      "string",
		Format:    "email",
		MinLength: 3,
	})
	assert.NoError(t, err)

	// add all constraints
	err = emailInput.SetConstraints(*emailField)
	assert.NoError(t, err)

	// add the name input descriptor
	err = builder.AddInputDescriptor(*emailInput)
	assert.NoError(t, err)

	// Build the presentation definition
	presDefHolder, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, presDefHolder)

	return presDefHolder.PresentationDefinition
}

type vpInput struct {
	definition          definition.PresentationDefinition
	nameCred, emailCred credential.VerifiableCredential
	issuerDoc           ledger.DIDDoc
	issuerPrivKey       ed25519.PrivateKey
	holderDoc           ledger.DIDDoc
	holderPrivKey       ed25519.PrivateKey
}

func makeMeAVerifiablePresentation(t *testing.T, input vpInput) (proof.Verifier, VerifiablePresentation, error) {
	// have the requester sign the presentation definition as a presentation request
	requesterSigner, err := proof.NewEd25519Signer(input.issuerPrivKey, input.issuerDoc.PublicKey[0].ID)
	assert.NoError(t, err)

	suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	assert.NoError(t, err)

	presentationRequest := PresentationRequest{
		ID:         "test-presentation-request",
		Definition: input.definition,
	}
	options := &proof.ProofOptions{ProofPurpose: proof.AssertionMethodPurpose}
	err = suite.Sign(&presentationRequest, requesterSigner, options)
	assert.NoError(t, err)

	// build a signer for the cred holder
	holderSigner, err := proof.NewEd25519Signer(input.holderPrivKey, input.holderDoc.PublicKey[0].ID)
	assert.NoError(t, err)

	// now create the presentation submission
	presSubmission, err := NewPresentationSubmission(input.issuerPrivKey.Public().(ed25519.PublicKey), holderSigner, presentationRequest)
	assert.NoError(t, err)
	assert.NotEmpty(t, presSubmission)

	verifier := proof.Ed25519Verifier{PubKey: input.holderPrivKey.Public().(ed25519.PublicKey)}
	fulfilled, err := presSubmission.FulfillPresentationRequestAsVP([]credential.VerifiableCredential{input.nameCred, input.emailCred})
	vp := VerifiablePresentation{}
	if fulfilled != nil {
		vp = VerifiablePresentation(*fulfilled)
	}
	return &verifier, vp, err
}

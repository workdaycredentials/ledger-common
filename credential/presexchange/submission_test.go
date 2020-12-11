package presexchange

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/decentralized-identity/presentation-exchange-implementations/pkg/definition"
	"github.com/decentralized-identity/presentation-exchange-implementations/pkg/submission"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/ledger"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/email"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/name"
	"github.com/workdaycredentials/ledger-common/proof"
)

func TestFulfillPresentationRequest(t *testing.T) {
	// create an issuer and target holder for the credential
	signatureType := proof.JCSEdSignatureType
	issuerDoc, issuerPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, signatureType)
	holderDoc, holderPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, signatureType)
	input := credGenInput{
		issuerPrivKey: issuerPrivKey,
		issuerDoc:     *issuerDoc,
		holderDoc:     *holderDoc,
	}
	nameCred := makeMeANameCred(t, input)
	assert.NotEmpty(t, nameCred)

	emailCred := makeMeAnEmailCred(t, input)
	assert.NotEmpty(t, emailCred)

	t.Run("Single credential multiple attributes request", func(t *testing.T) {
		builder := definition.NewPresentationDefinitionBuilder()
		builder.SetLocale(enUSLocale)

		err := builder.SetLDPFormat(definition.LDPVP, []string{"JcsEd25519Signature2020"})
		assert.NoError(t, err)

		nameInput := definition.NewInputDescriptor("name_input")
		err = nameInput.SetSchema(definition.Schema{
			URI:     []string{nameCred.Schema.ID},
			Name:    "Name Schema",
			Purpose: "To get an individual's first and last name",
		})
		assert.NoError(t, err)

		// restrict the issuer
		issuerField := definition.NewConstraintsField([]string{"$.issuer"})
		issuerField.SetPurpose("Must be from a known issuer")
		err = issuerField.SetFilter(definition.Filter{
			Type:      "string",
			Pattern:   nameCred.Issuer,
			MinLength: 1,
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

		// make sure the last name is there
		lastNameField := definition.NewConstraintsField([]string{"$.credentialSubject.lastName"})
		lastNameField.SetPurpose("We need your last name")
		err = lastNameField.SetFilter(definition.Filter{
			Type:      "string",
			MinLength: 2,
		})
		assert.NoError(t, err)

		// add all constraints
		err = nameInput.SetConstraints(*issuerField, *firstNameField, *lastNameField)
		assert.NoError(t, err)

		// add the name input descriptor
		err = builder.AddInputDescriptor(*nameInput)
		assert.NoError(t, err)

		presDefHolder, err := builder.Build()
		assert.NoError(t, err)
		assert.NotEmpty(t, presDefHolder)

		// have the requester sign the presentation definition as a presentation request
		requesterSigner, err := proof.NewEd25519Signer(issuerPrivKey, issuerDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
		assert.NoError(t, err)

		presentationRequest := PresentationRequest{
			ID:         "test-presentation-request",
			Definition: presDefHolder.PresentationDefinition,
		}
		options := &proof.ProofOptions{ProofPurpose: proof.AssertionMethodPurpose}
		err = suite.Sign(&presentationRequest, requesterSigner, options)
		assert.NoError(t, err)

		// build a signer for the cred holder
		holderSigner, err := proof.NewEd25519Signer(holderPrivKey, holderDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		// now create the presentation submission
		presSubmission, err := NewPresentationSubmission(issuerPrivKey.Public().(ed25519.PublicKey), holderSigner, presentationRequest)
		assert.NoError(t, err)
		assert.NotEmpty(t, presSubmission)

		// fulfill it with the creds
		fulfilled, err := presSubmission.FulfillPresentationRequestAsVP([]credential.VerifiableCredential{*nameCred})
		assert.NoError(t, err)
		assert.NotNil(t, fulfilled)

		// verify the signature
		verifier := proof.Ed25519Verifier{PubKey: holderPrivKey.Public().(ed25519.PublicKey)}
		v := VerifiablePresentation(*fulfilled)
		err = suite.Verify(&v, &verifier)
		assert.NoError(t, err)

		// assert the three known descriptors are there
		d1 := submission.Descriptor{
			ID:     "name_input",
			Path:   "$.verifiableCredential[0]",
			Format: definition.CredentialFormat(definition.LDPVP),
		}
		assert.Equal(t, 1, len(fulfilled.PresentationSubmission.DescriptorMap))
		assert.Contains(t, fulfilled.PresentationSubmission.DescriptorMap, d1)
	})

	t.Run("Single credential multiple attributes request (does not match pattern)", func(t *testing.T) {
		builder := definition.NewPresentationDefinitionBuilder()
		builder.SetLocale(enUSLocale)

		err := builder.SetLDPFormat(definition.LDPVP, []string{"JcsEd25519Signature2020"})
		assert.NoError(t, err)

		nameInput := definition.NewInputDescriptor("name_input")
		err = nameInput.SetSchema(definition.Schema{
			URI:     []string{nameCred.Schema.ID},
			Name:    "Name Schema",
			Purpose: "To get an individual's first and last name",
		})
		assert.NoError(t, err)

		// restrict the issuer
		issuerField := definition.NewConstraintsField([]string{"$.issuer"})
		issuerField.SetPurpose("Must be from a known issuer")
		err = issuerField.SetFilter(definition.Filter{
			Type:      "string",
			Pattern:   "known:" + nameCred.Issuer,
			MinLength: 1,
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
		err = nameInput.SetConstraints(*issuerField, *firstNameField)
		assert.NoError(t, err)

		// add the name input descriptor
		err = builder.AddInputDescriptor(*nameInput)
		assert.NoError(t, err)

		presDefHolder, err := builder.Build()
		assert.NoError(t, err)
		assert.NotEmpty(t, presDefHolder)

		// have the requester sign the presentation definition as a presentation request
		requesterSigner, err := proof.NewEd25519Signer(issuerPrivKey, issuerDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
		assert.NoError(t, err)

		presentationRequest := PresentationRequest{
			ID:         "test-presentation-request",
			Definition: presDefHolder.PresentationDefinition,
		}
		options := &proof.ProofOptions{ProofPurpose: proof.AssertionMethodPurpose}
		err = suite.Sign(&presentationRequest, requesterSigner, options)
		assert.NoError(t, err)

		// build a signer for the cred holder
		holderSigner, err := proof.NewEd25519Signer(holderPrivKey, holderDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		// now create the presentation submission
		presSubmission, err := NewPresentationSubmission(issuerPrivKey.Public().(ed25519.PublicKey), holderSigner, presentationRequest)
		assert.NoError(t, err)
		assert.NotEmpty(t, presSubmission)

		// fulfill it with the creds
		fulfilled, err := presSubmission.FulfillPresentationRequestAsVP([]credential.VerifiableCredential{*nameCred})
		assert.EqualError(t, err, "Key: 'PresentationSubmission.DescriptorMap' Error:Field validation for 'DescriptorMap' failed on the 'required' tag")
		assert.Nil(t, fulfilled)
	})

	t.Run("Multiple credentials, one attribute from each request", func(t *testing.T) {
		builder := definition.NewPresentationDefinitionBuilder()
		builder.SetLocale(enUSLocale)

		nameInput := definition.NewInputDescriptor("name_input")
		err := nameInput.SetSchema(definition.Schema{
			URI:     []string{nameCred.Schema.ID},
			Name:    "Name Schema",
			Purpose: "To get an individual's first name",
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
		emailInput := definition.NewInputDescriptor("email_input")
		err = emailInput.SetSchema(definition.Schema{
			URI:     []string{emailCred.Schema.ID},
			Name:    "Email Schema",
			Purpose: "To get an individual's email",
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

		// have the requester sign the presentation definition as a presentation request
		requesterSigner, err := proof.NewEd25519Signer(issuerPrivKey, issuerDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
		assert.NoError(t, err)

		presentationRequest := PresentationRequest{
			ID:         "test-presentation-request",
			Definition: presDefHolder.PresentationDefinition,
		}
		options := &proof.ProofOptions{ProofPurpose: proof.AssertionMethodPurpose}
		err = suite.Sign(&presentationRequest, requesterSigner, options)
		assert.NoError(t, err)

		// build a signer for the cred holder
		holderSigner, err := proof.NewEd25519Signer(holderPrivKey, holderDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		// now create the presentation submission
		presSubmission, err := NewPresentationSubmission(issuerPrivKey.Public().(ed25519.PublicKey), holderSigner, presentationRequest)
		assert.NoError(t, err)
		assert.NotEmpty(t, presSubmission)

		// fulfill it with the creds
		fulfilled, err := presSubmission.FulfillPresentationRequestAsVP([]credential.VerifiableCredential{*nameCred, *emailCred})
		assert.NoError(t, err)
		assert.NotEmpty(t, fulfilled)

		// verify the signature
		verifier := proof.Ed25519Verifier{PubKey: holderPrivKey.Public().(ed25519.PublicKey)}
		v := VerifiablePresentation(*fulfilled)
		err = suite.Verify(&v, &verifier)
		assert.NoError(t, err)

		// make sure one of each input is returned
		emailInputSeen, nameInputSeen := false, false
		assert.Equal(t, 2, len(fulfilled.PresentationSubmission.DescriptorMap))
		for _, d := range fulfilled.PresentationSubmission.DescriptorMap {
			if d.ID == "name_input" {
				nameInputSeen = true
			}
			if d.ID == "email_input" {
				emailInputSeen = true
			}
		}
		assert.True(t, nameInputSeen)
		assert.True(t, emailInputSeen)

		// assert disclosure has not been limited from the name cred, meaning there's > 2 fields (id and firstName) returned
		for _, cred := range fulfilled.VerifiableCredential {
			var c credential.VerifiableCredential
			credBytes, err := json.Marshal(cred)
			assert.NoError(t, err)
			assert.NoError(t, json.Unmarshal(credBytes, &c))

			// if it's the name cred, do the check
			if c.ID == nameCred.ID {
				assert.True(t, len(c.CredentialSubject) > 2)
				assert.True(t, len(c.ClaimProofs) > 2)
			}
		}
	})

	// This test requests multiple attributes from the same credential in different input descriptors (first and last name)
	// The point is to illustrate that the response will contain these attributes in a single credential descriptor
	t.Run("Multiple credentials, multiple attributes from each request, limit disclosure", func(t *testing.T) {
		builder := definition.NewPresentationDefinitionBuilder()
		builder.SetLocale(enUSLocale)

		err := builder.SetLDPFormat(definition.LDPVP, []string{"JcsEd25519Signature2020"})
		assert.NoError(t, err)

		firstNameInput := definition.NewInputDescriptor("first_name_input")
		err = firstNameInput.SetSchema(definition.Schema{
			URI:     []string{nameCred.Schema.ID},
			Name:    "Name Schema",
			Purpose: "To get an individual's first name",
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
		err = firstNameInput.SetConstraints(*firstNameField)
		assert.NoError(t, err)

		// add the first name input descriptor
		err = builder.AddInputDescriptor(*firstNameInput)
		assert.NoError(t, err)
		firstNameInput.SetConstraintsLimitDisclosure(true)

		// add the last name input descriptor
		lastNameInput := definition.NewInputDescriptor("last_name_input")
		err = lastNameInput.SetSchema(definition.Schema{
			URI:     []string{nameCred.Schema.ID},
			Name:    "Name Schema",
			Purpose: "To get an individual's last name",
		})
		assert.NoError(t, err)

		lastNameField := definition.NewConstraintsField([]string{"$.credentialSubject.lastName"})
		lastNameField.SetPurpose("We need your last name")
		err = lastNameField.SetFilter(definition.Filter{
			Type:      "string",
			MinLength: 2,
		})
		assert.NoError(t, err)

		// add all constraints
		err = lastNameInput.SetConstraints(*lastNameField)
		assert.NoError(t, err)

		// add the last name input descriptor
		err = builder.AddInputDescriptor(*lastNameInput)
		assert.NoError(t, err)
		firstNameInput.SetConstraintsLimitDisclosure(true)

		// add the email input descriptor
		emailInput := definition.NewInputDescriptor("email_input")
		err = emailInput.SetSchema(definition.Schema{
			URI:     []string{emailCred.Schema.ID},
			Name:    "Email Schema",
			Purpose: "To get an individual's email",
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
		emailInput.SetConstraintsLimitDisclosure(true)

		// Build the presentation definition
		presDefHolder, err := builder.Build()
		assert.NoError(t, err)
		assert.NotEmpty(t, presDefHolder)

		// have the requester sign the presentation definition as a presentation request
		requesterSigner, err := proof.NewEd25519Signer(issuerPrivKey, issuerDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
		assert.NoError(t, err)

		presentationRequest := PresentationRequest{
			ID:         "test-presentation-request",
			Definition: presDefHolder.PresentationDefinition,
		}
		options := &proof.ProofOptions{ProofPurpose: proof.AssertionMethodPurpose}
		err = suite.Sign(&presentationRequest, requesterSigner, options)
		assert.NoError(t, err)

		// build a signer for the cred holder
		holderSigner, err := proof.NewEd25519Signer(holderPrivKey, holderDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		// now create the presentation submission
		presSubmission, err := NewPresentationSubmission(issuerPrivKey.Public().(ed25519.PublicKey), holderSigner, presentationRequest)
		assert.NoError(t, err)
		assert.NotEmpty(t, presSubmission)

		// fulfill it with the creds
		fulfilled, err := presSubmission.FulfillPresentationRequestAsVP([]credential.VerifiableCredential{*nameCred, *emailCred})
		assert.NoError(t, err)
		assert.NotEmpty(t, fulfilled)

		// verify the signature
		verifier := proof.Ed25519Verifier{PubKey: holderPrivKey.Public().(ed25519.PublicKey)}
		v := VerifiablePresentation(*fulfilled)
		err = suite.Verify(&v, &verifier)
		assert.NoError(t, err)

		// make sure one of each input is returned
		emailInputSeen, firstNameInputSeen, lastNameInputSeen := false, false, false
		assert.Equal(t, 3, len(fulfilled.PresentationSubmission.DescriptorMap))
		for _, d := range fulfilled.PresentationSubmission.DescriptorMap {
			if d.ID == "first_name_input" {
				firstNameInputSeen = true
			}
			if d.ID == "last_name_input" {
				lastNameInputSeen = true
			}
			if d.ID == "email_input" {
				emailInputSeen = true
			}
		}
		assert.True(t, firstNameInputSeen)
		assert.True(t, lastNameInputSeen)
		assert.True(t, emailInputSeen)

		// Make sure there are 2 creds for the 3 descriptors, since the results have been merged
		assert.Equal(t, 2, len(fulfilled.VerifiableCredential))

		// assert disclosure has been limited from the name cred, meaning there are only 3 fields (id, firstName, lastName) returned
		for _, cred := range fulfilled.VerifiableCredential {
			var c credential.VerifiableCredential
			credBytes, err := json.Marshal(cred)
			assert.NoError(t, err)
			assert.NoError(t, json.Unmarshal(credBytes, &c))

			// if it's the name cred, do the check
			if c.ID == nameCred.ID {
				assert.True(t, len(c.CredentialSubject) == 3)
				assert.True(t, len(c.ClaimProofs) == 3)
			}
		}
	})

	t.Run("Multiple credentials, one fulfills", func(t *testing.T) {
		builder := definition.NewPresentationDefinitionBuilder()
		builder.SetLocale(enUSLocale)

		nameInput := definition.NewInputDescriptor("name_input")
		err := nameInput.SetSchema(definition.Schema{
			URI:     []string{nameCred.Schema.ID},
			Name:    "Name Schema",
			Purpose: "To get an individual's first name",
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

		// Build the presentation definition
		presDefHolder, err := builder.Build()
		assert.NoError(t, err)
		assert.NotEmpty(t, presDefHolder)

		// have the requester sign the presentation definition as a presentation request
		requesterSigner, err := proof.NewEd25519Signer(issuerPrivKey, issuerDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
		assert.NoError(t, err)

		presentationRequest := PresentationRequest{
			ID:         "test-presentation-request",
			Definition: presDefHolder.PresentationDefinition,
		}
		options := &proof.ProofOptions{ProofPurpose: proof.AssertionMethodPurpose}
		err = suite.Sign(&presentationRequest, requesterSigner, options)
		assert.NoError(t, err)

		// build a signer for the cred holder
		holderSigner, err := proof.NewEd25519Signer(holderPrivKey, holderDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		// now create the presentation submission
		presSubmission, err := NewPresentationSubmission(issuerPrivKey.Public().(ed25519.PublicKey), holderSigner, presentationRequest)
		assert.NoError(t, err)
		assert.NotEmpty(t, presSubmission)

		// fulfill it with the creds, second is unnecessary
		fulfilled, err := presSubmission.FulfillPresentationRequestAsVP([]credential.VerifiableCredential{*nameCred, *emailCred})
		assert.NoError(t, err)
		assert.NotEmpty(t, fulfilled)

		// verify the signature
		verifier := proof.Ed25519Verifier{PubKey: holderPrivKey.Public().(ed25519.PublicKey)}
		v := VerifiablePresentation(*fulfilled)
		err = suite.Verify(&v, &verifier)
		assert.NoError(t, err)

		// assert the known descriptor is there
		d1 := submission.Descriptor{
			ID:     "name_input",
			Path:   "$.verifiableCredential[0]",
			Format: definition.CredentialFormat(definition.LDPVP),
		}
		assert.Equal(t, 1, len(fulfilled.PresentationSubmission.DescriptorMap))
		assert.Contains(t, fulfilled.PresentationSubmission.DescriptorMap, d1)
	})

	t.Run("Multiple credentials, neither fulfills", func(t *testing.T) {
		builder := definition.NewPresentationDefinitionBuilder()
		builder.SetLocale(enUSLocale)

		bigfootInput := definition.NewInputDescriptor("bad_input")
		err := bigfootInput.SetSchema(definition.Schema{
			URI:     []string{nameCred.Schema.ID},
			Name:    "Bigfoot",
			Purpose: "To get something that doesn't exist",
		})
		assert.NoError(t, err)

		// make sure the first name is there
		heightField := definition.NewConstraintsField([]string{"$.credentialSubject.height"})
		heightField.SetPurpose("We need bigfoot's height")
		err = heightField.SetFilter(definition.Filter{
			Type: "integer",
		})
		assert.NoError(t, err)

		// add all constraints
		err = bigfootInput.SetConstraints(*heightField)
		assert.NoError(t, err)

		// add the input descriptor
		err = builder.AddInputDescriptor(*bigfootInput)
		assert.NoError(t, err)

		// Build the presentation definition
		presDefHolder, err := builder.Build()
		assert.NoError(t, err)
		assert.NotEmpty(t, presDefHolder)

		// have the requester sign the presentation definition as a presentation request
		requesterSigner, err := proof.NewEd25519Signer(issuerPrivKey, issuerDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
		assert.NoError(t, err)

		presentationRequest := PresentationRequest{
			ID:         "test-presentation-request",
			Definition: presDefHolder.PresentationDefinition,
		}
		options := &proof.ProofOptions{ProofPurpose: proof.AssertionMethodPurpose}
		err = suite.Sign(&presentationRequest, requesterSigner, options)
		assert.NoError(t, err)

		// build a signer for the cred holder
		holderSigner, err := proof.NewEd25519Signer(holderPrivKey, holderDoc.PublicKey[0].ID)
		assert.NoError(t, err)

		// now create the presentation submission
		presSubmission, err := NewPresentationSubmission(issuerPrivKey.Public().(ed25519.PublicKey), holderSigner, presentationRequest)
		assert.NoError(t, err)
		assert.NotEmpty(t, presSubmission)

		// fulfill it with the creds, neither work
		fulfilled, err := presSubmission.FulfillPresentationRequestAsVP([]credential.VerifiableCredential{*nameCred, *emailCred})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no credentials fit paths")
		assert.Empty(t, fulfilled)
	})
}

func TestFulfillDescriptor(t *testing.T) {
	// create an issuer and target holder for the credential
	issuerDoc, issuerPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	holderDoc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	input := credGenInput{
		issuerPrivKey: issuerPrivKey,
		issuerDoc:     *issuerDoc,
		holderDoc:     *holderDoc,
	}
	nameCred := makeMeANameCred(t, input)
	assert.NotEmpty(t, nameCred)

	emailCred := makeMeAnEmailCred(t, input)
	assert.NotEmpty(t, emailCred)

	t.Run("First name descriptors fulfilled", func(t *testing.T) {
		descriptor := definition.InputDescriptor{
			ID: "name_input",
			Schema: &definition.Schema{
				URI:     []string{nameCred.Schema.ID},
				Name:    "Name credential",
				Purpose: "We need your name.",
			},
			Constraints: &definition.Constraints{
				LimitDisclosure: false,
				Fields: []definition.Field{
					{
						Path:    []string{"$.credentialSubject.firstName"},
						Purpose: "First name needed",
						Filter: &definition.Filter{
							Type: "string",
						},
					},
				},
			},
		}
		fulfilled, err := fulfillDescriptor(descriptor, []credential.VerifiableCredential{*nameCred}, holderDoc.ID)
		assert.NoError(t, err)
		assert.NotEmpty(t, fulfilled)
	})

	t.Run("Email descriptors fulfilled", func(t *testing.T) {
		descriptor := definition.InputDescriptor{
			ID: "email_input",
			Schema: &definition.Schema{
				URI:     []string{emailCred.Schema.ID},
				Name:    "Email credential",
				Purpose: "We need your email.",
			},
			Constraints: &definition.Constraints{
				LimitDisclosure: false,
				Fields: []definition.Field{
					{
						Path:    []string{"$.credentialSubject.emailAddress"},
						Purpose: "Email needed",
						Filter: &definition.Filter{
							Type:   "string",
							Format: "email",
						},
					},
				},
			},
		}
		fulfilled, err := fulfillDescriptor(descriptor, []credential.VerifiableCredential{*emailCred}, holderDoc.ID)
		assert.NoError(t, err)
		assert.NotEmpty(t, fulfilled)
	})

	t.Run("No constraints", func(t *testing.T) {
		descriptor := definition.InputDescriptor{
			ID: "email_input",
			Schema: &definition.Schema{
				URI:     []string{emailCred.Schema.ID},
				Name:    "Email credential",
				Purpose: "We need your email.",
			},
		}
		fulfilled, err := fulfillDescriptor(descriptor, []credential.VerifiableCredential{*emailCred}, holderDoc.ID)
		assert.NoError(t, err)
		assert.NotEmpty(t, fulfilled)
		assert.Equal(t, emailCred.ID, fulfilled[0].CredID)
	})
}

func TestFilterCredentialsForSchemasAndSubject(t *testing.T) {
	// create an issuer and target holder for the credential
	issuerDoc, issuerPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	holderDoc, holderPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	input := credGenInput{
		issuerPrivKey: issuerPrivKey,
		issuerDoc:     *issuerDoc,
		holderDoc:     *holderDoc,
	}
	nameCred := makeMeANameCred(t, input)
	assert.NotEmpty(t, nameCred)

	emailCred := makeMeAnEmailCred(t, input)
	assert.NotEmpty(t, emailCred)

	// self issue name cred
	input = credGenInput{
		issuerPrivKey: holderPrivKey,
		issuerDoc:     *holderDoc,
		holderDoc:     *holderDoc,
	}
	selfIssuedNameCred := makeMeANameCred(t, input)
	assert.NotEmpty(t, selfIssuedNameCred)

	t.Run("Both schema ids match", func(t *testing.T) {
		schemaIDs := []string{nameCred.Schema.ID, emailCred.Schema.ID}
		filtered, err := filterApplicableCredentials(schemaIDs, nil, []credential.VerifiableCredential{*nameCred, *emailCred}, holderDoc.ID)
		assert.NoError(t, err)
		assert.NotEmpty(t, filtered)
		assert.Equal(t, 2, len(filtered))
		assert.Contains(t, filtered, *nameCred, *emailCred)
	})

	t.Run("One schema id match, neither self issued", func(t *testing.T) {
		schemaIDs := []string{nameCred.Schema.ID, emailCred.Schema.ID}
		filtered, err := filterApplicableCredentials(schemaIDs, nil, []credential.VerifiableCredential{*nameCred, *emailCred}, holderDoc.ID)
		assert.NoError(t, err)
		assert.NotEmpty(t, filtered)
		assert.Equal(t, 2, len(filtered))
		assert.Contains(t, filtered, *nameCred, *emailCred)
	})

	t.Run("One schema id matches, not self issued", func(t *testing.T) {
		schemaIDs := []string{nameCred.Schema.ID}
		required := definition.Required
		constraints := definition.Constraints{SubjectIsIssuer: &required}
		filtered, err := filterApplicableCredentials(schemaIDs, &constraints, []credential.VerifiableCredential{*nameCred}, holderDoc.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "subject is issuer required")
		assert.Empty(t, filtered)
	})

	t.Run("One schema id matches, self issued", func(t *testing.T) {
		schemaIDs := []string{selfIssuedNameCred.Schema.ID}
		required := definition.Required
		constraints := definition.Constraints{SubjectIsIssuer: &required}
		filtered, err := filterApplicableCredentials(schemaIDs, &constraints, []credential.VerifiableCredential{*selfIssuedNameCred}, holderDoc.ID)
		assert.NoError(t, err)
		assert.Equal(t, filtered[0].ID, selfIssuedNameCred.ID)
	})

	t.Run("No matches", func(t *testing.T) {
		schemaIDs := []string{"badID"}
		filtered, err := filterApplicableCredentials(schemaIDs, nil, []credential.VerifiableCredential{*nameCred, *emailCred}, holderDoc.ID)
		assert.NoError(t, err)
		assert.Empty(t, filtered)
	})
}

func TestSubjectConstraints(t *testing.T) {
	required := definition.Required
	preferred := definition.Preferred

	t.Run("Neither set", func(t *testing.T) {
		constraints := definition.Constraints{
			SubjectIsIssuer: nil,
			SubjectIsHolder: nil,
		}
		issuer, holder := subjectConstraints(constraints)
		assert.False(t, holder)
		assert.False(t, issuer)
	})

	t.Run("Both set to required", func(t *testing.T) {
		constraints := definition.Constraints{
			SubjectIsIssuer: &required,
			SubjectIsHolder: &required,
		}
		issuer, holder := subjectConstraints(constraints)
		assert.True(t, holder)
		assert.True(t, issuer)
	})

	t.Run("Both set to preferred", func(t *testing.T) {
		constraints := definition.Constraints{
			SubjectIsIssuer: &preferred,
			SubjectIsHolder: &preferred,
		}
		issuer, holder := subjectConstraints(constraints)
		assert.False(t, holder)
		assert.False(t, issuer)
	})

	t.Run("One set to required", func(t *testing.T) {
		constraints := definition.Constraints{
			SubjectIsIssuer: &required,
			SubjectIsHolder: &preferred,
		}
		issuer, holder := subjectConstraints(constraints)
		assert.True(t, issuer)
		assert.False(t, holder)

		constraints = definition.Constraints{
			SubjectIsIssuer: &preferred,
			SubjectIsHolder: &required,
		}
		issuer, holder = subjectConstraints(constraints)
		assert.False(t, issuer)
		assert.True(t, holder)
	})
}

func TestApplyPaths(t *testing.T) {
	// create an issuer and target holder for the credential
	issuerDoc, issuerPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	holderDoc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	input := credGenInput{
		issuerPrivKey: issuerPrivKey,
		issuerDoc:     *issuerDoc,
		holderDoc:     *holderDoc,
	}
	nameCred := makeMeANameCred(t, input)
	assert.NotEmpty(t, nameCred)

	emailCred := makeMeAnEmailCred(t, input)
	assert.NotEmpty(t, emailCred)

	descriptorID := "testID"

	t.Run("Extract issuer", func(t *testing.T) {
		path := "$.issuer"
		toFilter, err := applyPaths(descriptorID, []string{path}, Open, []credential.VerifiableCredential{*nameCred})
		assert.NoError(t, err)
		assert.NotEmpty(t, toFilter)
		assert.Equal(t, 1, len(toFilter))
		assert.Equal(t, nameCred.Issuer, toFilter[0].pathedData)
	})

	t.Run("Extract missing field", func(t *testing.T) {
		path := "$.bad"
		toFilter, err := applyPaths(descriptorID, []string{path}, Open, []credential.VerifiableCredential{*nameCred})
		assert.Error(t, err)
		assert.Empty(t, toFilter)
	})

	t.Run("Multiple good paths", func(t *testing.T) {
		paths := []string{"$.issuer", "$.credentialSubject.id"}
		toFilter, err := applyPaths(descriptorID, paths, Open, []credential.VerifiableCredential{*nameCred})
		assert.NoError(t, err)
		assert.NotEmpty(t, toFilter)
		assert.Equal(t, 2, len(toFilter))
		assert.Equal(t, nameCred.Issuer, toFilter[0].pathedData)
		assert.Equal(t, nameCred.CredentialSubject[credential.SubjectIDAttribute], toFilter[1].pathedData)
	})

	t.Run("Multiple paths, one good one bad", func(t *testing.T) {
		paths := []string{"$.issuer", "$.bad"}
		toFilter, err := applyPaths(descriptorID, paths, Open, []credential.VerifiableCredential{*nameCred})
		assert.NoError(t, err)
		assert.NotEmpty(t, toFilter)
		assert.Equal(t, 1, len(toFilter))
		assert.Equal(t, nameCred.Issuer, toFilter[0].pathedData)
	})

	t.Run("Multiple creds, one path", func(t *testing.T) {
		paths := []string{"$.issuer"}
		toFilter, err := applyPaths(descriptorID, paths, Open, []credential.VerifiableCredential{*nameCred, *emailCred})
		assert.NoError(t, err)
		assert.NotEmpty(t, toFilter)
		assert.Equal(t, 2, len(toFilter))
		assert.Equal(t, nameCred.Issuer, toFilter[0].pathedData)
		assert.Equal(t, emailCred.Issuer, toFilter[1].pathedData)
	})

	t.Run("Multiple creds, path applies to only one", func(t *testing.T) {
		paths := []string{"$.credentialSubject.emailAddress"}
		toFilter, err := applyPaths(descriptorID, paths, Open, []credential.VerifiableCredential{*nameCred, *emailCred})
		assert.NoError(t, err)
		assert.NotEmpty(t, toFilter)
		assert.Equal(t, 1, len(toFilter))
		// an email address contains an @ sign
		assert.Contains(t, toFilter[0].pathedData, "@")
	})

	t.Run("Multiple creds, path applies to none", func(t *testing.T) {
		paths := []string{"$.credentialSubject.bad"}
		toFilter, err := applyPaths(descriptorID, paths, Open, []credential.VerifiableCredential{*nameCred, *emailCred})
		assert.Error(t, err)
		assert.Empty(t, toFilter)
	})
}

func TestApplyPathsLimitingDisclosure(t *testing.T) {
	// create an issuer and target holder for the credential
	issuerDoc, issuerPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	holderDoc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	input := credGenInput{
		issuerPrivKey: issuerPrivKey,
		issuerDoc:     *issuerDoc,
		holderDoc:     *holderDoc,
	}
	nameCred := makeMeANameCred(t, input)
	assert.NotEmpty(t, nameCred)

	emailCred := makeMeAnEmailCred(t, input)
	assert.NotEmpty(t, emailCred)

	descriptorID := "testID"

	t.Run("Extract issuer", func(t *testing.T) {
		path := "$.issuer"
		toFilter, err := applyPaths(descriptorID, []string{path}, Limited, []credential.VerifiableCredential{*nameCred})
		assert.NoError(t, err)
		assert.NotEmpty(t, toFilter)
		assert.Equal(t, 1, len(toFilter))
		assert.Equal(t, nameCred.Issuer, toFilter[0].pathedData)

		// make sure disclosure has been limited, and only the id attribute is returned
		_, ok := toFilter[0].cred.CredentialSubject[credential.SubjectIDAttribute]
		assert.True(t, ok)
		assert.Len(t, toFilter[0].cred.CredentialSubject, 1)
		assert.Len(t, toFilter[0].cred.ClaimProofs, 1)
	})

	t.Run("Extract missing field", func(t *testing.T) {
		path := "$.bad"
		toFilter, err := applyPaths(descriptorID, []string{path}, Limited, []credential.VerifiableCredential{*nameCred})
		assert.Error(t, err)
		assert.Empty(t, toFilter)
	})

	t.Run("Multiple good paths", func(t *testing.T) {
		paths := []string{"$.issuer", "$.credentialSubject.id"}
		toFilter, err := applyPaths(descriptorID, paths, Limited, []credential.VerifiableCredential{*nameCred})
		assert.NoError(t, err)
		assert.NotEmpty(t, toFilter)
		assert.Equal(t, 2, len(toFilter))
		assert.Equal(t, nameCred.Issuer, toFilter[0].pathedData)
		assert.Equal(t, nameCred.CredentialSubject[credential.SubjectIDAttribute], toFilter[1].pathedData)

		// make sure disclosure has been limited, and only the requested attribute is returned from both
		assert.Len(t, toFilter[0].cred.CredentialSubject, 1)
		assert.Len(t, toFilter[0].cred.ClaimProofs, 1)

		assert.Len(t, toFilter[1].cred.CredentialSubject, 1)
		assert.Len(t, toFilter[1].cred.ClaimProofs, 1)
	})

	t.Run("Multiple paths, one good one bad", func(t *testing.T) {
		paths := []string{"$.issuer", "$.bad"}
		toFilter, err := applyPaths(descriptorID, paths, Limited, []credential.VerifiableCredential{*nameCred})
		assert.NoError(t, err)
		assert.NotEmpty(t, toFilter)
		assert.Equal(t, 1, len(toFilter))
		assert.Equal(t, nameCred.Issuer, toFilter[0].pathedData)

		// make sure disclosure has been limited, and only the id attribute is returned
		_, ok := toFilter[0].cred.CredentialSubject[credential.SubjectIDAttribute]
		assert.True(t, ok)
		assert.Len(t, toFilter[0].cred.CredentialSubject, 1)
		assert.Len(t, toFilter[0].cred.ClaimProofs, 1)
	})

	t.Run("Multiple creds, one path", func(t *testing.T) {
		paths := []string{"$.issuer"}
		toFilter, err := applyPaths(descriptorID, paths, Limited, []credential.VerifiableCredential{*nameCred, *emailCred})
		assert.NoError(t, err)
		assert.NotEmpty(t, toFilter)
		assert.Equal(t, 2, len(toFilter))
		assert.Equal(t, nameCred.Issuer, toFilter[0].pathedData)
		assert.Equal(t, emailCred.Issuer, toFilter[1].pathedData)

		// make sure disclosure has been limited, and only the id attribute is returned from both
		_, ok := toFilter[0].cred.CredentialSubject[credential.SubjectIDAttribute]
		assert.True(t, ok)
		assert.Len(t, toFilter[0].cred.CredentialSubject, 1)
		assert.Len(t, toFilter[0].cred.ClaimProofs, 1)

		_, ok = toFilter[1].cred.CredentialSubject[credential.SubjectIDAttribute]
		assert.True(t, ok)
		assert.Len(t, toFilter[1].cred.CredentialSubject, 1)
		assert.Len(t, toFilter[1].cred.ClaimProofs, 1)
	})

	t.Run("Multiple creds, path applies to only one", func(t *testing.T) {
		paths := []string{"$.credentialSubject.emailAddress"}
		toFilter, err := applyPaths(descriptorID, paths, Limited, []credential.VerifiableCredential{*nameCred, *emailCred})
		assert.NoError(t, err)
		assert.NotEmpty(t, toFilter)
		assert.Equal(t, 1, len(toFilter))
		// an email address contains an @ sign
		assert.Contains(t, toFilter[0].pathedData, "@")

		// make sure only requested attribute and id are present
		_, ok := toFilter[0].cred.CredentialSubject[credential.SubjectIDAttribute]
		assert.True(t, ok)

		_, ok = toFilter[0].cred.CredentialSubject["emailAddress"]
		assert.True(t, ok)

		assert.Len(t, toFilter[0].cred.CredentialSubject, 2)
		assert.Len(t, toFilter[0].cred.ClaimProofs, 2)
	})

	t.Run("Multiple creds, path applies to none", func(t *testing.T) {
		paths := []string{"$.credentialSubject.bad"}
		toFilter, err := applyPaths(descriptorID, paths, Limited, []credential.VerifiableCredential{*nameCred, *emailCred})
		assert.Error(t, err)
		assert.Empty(t, toFilter)
	})
}

func TestApplyFilter(t *testing.T) {
	// create an issuer and target holder for the credential
	issuerDoc, issuerPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	holderDoc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	input := credGenInput{
		issuerPrivKey: issuerPrivKey,
		issuerDoc:     *issuerDoc,
		holderDoc:     *holderDoc,
	}
	nameCred := makeMeANameCred(t, input)
	assert.NotEmpty(t, nameCred)

	emailCred := makeMeAnEmailCred(t, input)
	assert.NotEmpty(t, emailCred)

	t.Run("Simple issuer filter", func(t *testing.T) {
		criteria := []criterionToFilter{
			{
				descriptorID: "name_cred",
				pathedData:   nameCred.Issuer,
				cred:         *nameCred,
			},
		}
		filter := definition.Filter{
			Type:    "string",
			Pattern: fmt.Sprintf("%s|did:work:example", nameCred.Issuer),
		}

		fulfilled, err := applyFilter(filter, criteria)
		assert.NoError(t, err)
		assert.NotEmpty(t, fulfilled)
		assert.Equal(t, 1, len(fulfilled))
	})

	t.Run("No fulfilled on issuer filter", func(t *testing.T) {
		criteria := []criterionToFilter{
			{
				descriptorID: "name_cred",
				pathedData:   nameCred.Issuer,
				cred:         *nameCred,
			},
		}
		filter := definition.Filter{
			Type:    "string",
			Pattern: "did:work:example",
		}

		fulfilled, err := applyFilter(filter, criteria)
		assert.NoError(t, err)
		assert.Empty(t, fulfilled)
	})

	t.Run("Multiple creds, both fulfill", func(t *testing.T) {
		criteria := []criterionToFilter{
			{
				descriptorID: "name_cred",
				pathedData:   nameCred.Issuer,
				cred:         *nameCred,
			},
			{
				descriptorID: "email_cred",
				pathedData:   emailCred.Issuer,
				cred:         *emailCred,
			},
		}
		filter := definition.Filter{
			Type:    "string",
			Pattern: fmt.Sprintf("%s|%s", nameCred.Issuer, emailCred.Issuer),
		}

		fulfilled, err := applyFilter(filter, criteria)
		assert.NoError(t, err)
		assert.NotEmpty(t, fulfilled)
		assert.Equal(t, 2, len(fulfilled))
	})

	t.Run("Multiple creds, neither fulfill", func(t *testing.T) {
		criteria := []criterionToFilter{
			{
				descriptorID: "name_cred",
				pathedData:   nameCred.Issuer,
				cred:         *nameCred,
			},
			{
				descriptorID: "email_cred",
				pathedData:   emailCred.Issuer,
				cred:         *emailCred,
			},
		}
		filter := definition.Filter{
			Type:    "string",
			Pattern: "badIssuer",
		}

		fulfilled, err := applyFilter(filter, criteria)
		assert.NoError(t, err)
		assert.Empty(t, fulfilled)
	})
}

func TestCalculateRequirementMinMax(t *testing.T) {
	t.Run("all", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule: "all",
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		defaultMax := 20
		min, max, err := calculateRequirementMinMax(requirement, defaultMax)
		assert.NoError(t, err)
		assert.Equal(t, defaultMax, min)
		assert.Equal(t, defaultMax, max)
	})

	t.Run("all with count/min/max present", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule:    "all",
			Count:   10,
			Minimum: 1,
			Maximum: 5,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		defaultMax := 20
		_, _, err := calculateRequirementMinMax(requirement, defaultMax)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "count, min, and/or max present for all rule")
	})

	t.Run("pick — count, no min or max", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule:  "pick",
			Count: 10,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		defaultMax := 20
		min, max, err := calculateRequirementMinMax(requirement, defaultMax)
		assert.NoError(t, err)
		assert.Equal(t, 10, min)
		assert.Equal(t, 10, max)
	})

	t.Run("pick — min no max", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule:    "pick",
			Minimum: 2,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		defaultMax := 20
		min, max, err := calculateRequirementMinMax(requirement, defaultMax)
		assert.NoError(t, err)
		assert.Equal(t, 2, min)
		assert.Equal(t, 20, max)
	})

	t.Run("pick — max only", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule:    "pick",
			Maximum: 2,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		defaultMax := 20
		min, max, err := calculateRequirementMinMax(requirement, defaultMax)
		assert.NoError(t, err)
		assert.Equal(t, 0, min)
		assert.Equal(t, 2, max)
	})

	t.Run("pick — min and max", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule:    "pick",
			Minimum: 5,
			Maximum: 7,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		defaultMax := 20
		min, max, err := calculateRequirementMinMax(requirement, defaultMax)
		assert.NoError(t, err)
		assert.Equal(t, 5, min)
		assert.Equal(t, 7, max)
	})

	t.Run("pick — error cases", func(t *testing.T) {
		// count, min, and max
		requirement := definition.SubmissionRequirement{
			Rule:    "pick",
			Count:   1,
			Minimum: 5,
			Maximum: 7,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		defaultMax := 20
		_, _, err := calculateRequirementMinMax(requirement, defaultMax)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "count, min, and max present")

		// invalid count
		requirement = definition.SubmissionRequirement{
			Rule:  "pick",
			Count: -1,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		_, _, err = calculateRequirementMinMax(requirement, defaultMax)
		assert.Error(t, err)

		// max greater than default
		requirement = definition.SubmissionRequirement{
			Rule:    "pick",
			Maximum: 500,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		_, _, err = calculateRequirementMinMax(requirement, defaultMax)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is greater than the number of descriptors")
	})

	t.Run("neither pick nor all", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule:    "bad",
			Maximum: 2,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		defaultMax := 20
		_, _, err := calculateRequirementMinMax(requirement, defaultMax)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown rule type")
	})
}

func TestFulfillRequirement(t *testing.T) {
	// create an issuer and target holder for the credential
	issuerDoc, issuerPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	holderDoc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	input := credGenInput{
		issuerPrivKey: issuerPrivKey,
		issuerDoc:     *issuerDoc,
		holderDoc:     *holderDoc,
	}
	nameCred := makeMeANameCred(t, input)
	assert.NotEmpty(t, nameCred)

	emailCred := makeMeAnEmailCred(t, input)
	assert.NotEmpty(t, emailCred)

	t.Run("All rule for a single input descriptor", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule: "all",
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		descriptors := []definition.InputDescriptor{
			{
				ID:    "name_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{nameCred.Schema.ID},
					Name:    "Name",
					Purpose: "We need your name",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.firstName"},
							Purpose: "We need your first name",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
		}
		fulfiller := requestFulfiller{
			responderID: holderDoc.ID,
			descriptors: descriptors,
			credentials: []credential.VerifiableCredential{*nameCred},
		}
		fulfilled, err := fulfiller.fulfillRequirement(requirement)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(fulfilled))
		assert.Equal(t, "name_input", fulfilled[0].DescriptorID)
		assert.Equal(t, nameCred.ID, fulfilled[0].CredID)
	})

	t.Run("All rule for multiple input descriptors with different groups", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule: "all",
			FromOption: definition.FromOption{
				FromNested: []definition.SubmissionRequirement{
					{
						Name: "All from A",
						Rule: "all",
						FromOption: definition.FromOption{
							From: "A",
						},
					},
					{
						Name: "All from B",
						Rule: "all",
						FromOption: definition.FromOption{
							From: "B",
						},
					},
				},
			},
		}
		descriptors := []definition.InputDescriptor{
			{
				ID:    "name_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{nameCred.Schema.ID},
					Name:    "Name",
					Purpose: "We need your name",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.firstName"},
							Purpose: "We need your first name",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
			{
				ID:    "name_input_two",
				Group: []string{"B"},
				Schema: &definition.Schema{
					URI:     []string{nameCred.Schema.ID},
					Name:    "Name",
					Purpose: "We need your name",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.lastName"},
							Purpose: "We need your last name",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
		}
		fulfiller := requestFulfiller{
			responderID: holderDoc.ID,
			descriptors: descriptors,
			credentials: []credential.VerifiableCredential{*nameCred},
		}
		fulfilled, err := fulfiller.fulfillRequirement(requirement)
		assert.NoError(t, err)
		assert.Equal(t, 2, len(fulfilled))
		assert.Equal(t, "name_input", fulfilled[0].DescriptorID)
		assert.Equal(t, nameCred.ID, fulfilled[0].CredID)
		assert.Equal(t, "name_input_two", fulfilled[1].DescriptorID)
		assert.Equal(t, nameCred.ID, fulfilled[1].CredID)
	})

	t.Run("All rule for multiple input descriptors with different groups -- but none provided for B", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule: "all",
			FromOption: definition.FromOption{
				FromNested: []definition.SubmissionRequirement{
					{
						Name: "All from A",
						Rule: "all",
						FromOption: definition.FromOption{
							From: "A",
						},
					},
					{
						Name: "All from B",
						Rule: "all",
						FromOption: definition.FromOption{
							From: "B",
						},
					},
				},
			},
		}
		descriptors := []definition.InputDescriptor{
			{
				ID:    "name_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{nameCred.Schema.ID},
					Name:    "Name",
					Purpose: "We need your name",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.firstName"},
							Purpose: "We need your first name",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
			{
				ID:    "email_input",
				Group: []string{"B"},
				Schema: &definition.Schema{
					URI:     []string{emailCred.Schema.ID},
					Name:    "Email",
					Purpose: "We need your email",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.emailAddress"},
							Purpose: "We need your email",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
		}
		fulfiller := requestFulfiller{
			responderID: holderDoc.ID,
			descriptors: descriptors,
			credentials: []credential.VerifiableCredential{*nameCred},
		}
		_, err := fulfiller.fulfillRequirement(requirement)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "requirement could not be satisfied")
	})

	t.Run("Pick count 2", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule:  "pick",
			Count: 2,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		descriptors := []definition.InputDescriptor{
			{
				ID:    "name_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{nameCred.Schema.ID},
					Name:    "Name",
					Purpose: "We need your name",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.firstName"},
							Purpose: "We need your first name",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
			{
				ID:    "email_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{emailCred.Schema.ID},
					Name:    "Email",
					Purpose: "We need your email",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.emailAddress"},
							Purpose: "We need your email",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
		}
		fulfiller := requestFulfiller{
			responderID: holderDoc.ID,
			descriptors: descriptors,
			credentials: []credential.VerifiableCredential{*nameCred, *emailCred},
		}
		fulfilled, err := fulfiller.fulfillRequirement(requirement)
		assert.NoError(t, err)
		assert.Equal(t, 2, len(fulfilled))
		assert.Equal(t, "name_input", fulfilled[0].DescriptorID)
		assert.Equal(t, nameCred.ID, fulfilled[0].CredID)
		assert.Equal(t, "email_input", fulfilled[1].DescriptorID)
		assert.Equal(t, emailCred.ID, fulfilled[1].CredID)
	})

	t.Run("Pick count 2, only have one", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule:  "pick",
			Count: 2,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		descriptors := []definition.InputDescriptor{
			{
				ID:    "name_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{nameCred.Schema.ID},
					Name:    "Name",
					Purpose: "We need your name",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.firstName"},
							Purpose: "We need your first name",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
			{
				ID:    "email_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{emailCred.Schema.ID},
					Name:    "Email",
					Purpose: "We need your email",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.emailAddress"},
							Purpose: "We need your email",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
		}
		fulfiller := requestFulfiller{
			responderID: holderDoc.ID,
			descriptors: descriptors,
			credentials: []credential.VerifiableCredential{*nameCred},
		}
		_, err := fulfiller.fulfillRequirement(requirement)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "requirement could not be satisfied")
	})

	t.Run("Pick min 1, supply 2, expect 2", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule:    "pick",
			Minimum: 1,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		descriptors := []definition.InputDescriptor{
			{
				ID:    "name_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{nameCred.Schema.ID},
					Name:    "Name",
					Purpose: "We need your name",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.firstName"},
							Purpose: "We need your first name",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
			{
				ID:    "email_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{emailCred.Schema.ID},
					Name:    "Email",
					Purpose: "We need your email",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.emailAddress"},
							Purpose: "We need your email",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
		}
		fulfiller := requestFulfiller{
			responderID: holderDoc.ID,
			descriptors: descriptors,
			credentials: []credential.VerifiableCredential{*nameCred, *emailCred},
		}
		fulfilled, err := fulfiller.fulfillRequirement(requirement)
		assert.NoError(t, err)
		assert.Equal(t, 2, len(fulfilled))
		assert.Equal(t, "name_input", fulfilled[0].DescriptorID)
		assert.Equal(t, nameCred.ID, fulfilled[0].CredID)
		assert.Equal(t, "email_input", fulfilled[1].DescriptorID)
		assert.Equal(t, emailCred.ID, fulfilled[1].CredID)
	})

	t.Run("Pick max 1, supply 2, expect 1", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule:    "pick",
			Maximum: 1,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		descriptors := []definition.InputDescriptor{
			{
				ID:    "name_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{nameCred.Schema.ID},
					Name:    "Name",
					Purpose: "We need your name",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.firstName"},
							Purpose: "We need your first name",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
			{
				ID:    "email_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{emailCred.Schema.ID},
					Name:    "Email",
					Purpose: "We need your email",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.emailAddress"},
							Purpose: "We need your email",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
		}
		fulfiller := requestFulfiller{
			responderID: holderDoc.ID,
			descriptors: descriptors,
			credentials: []credential.VerifiableCredential{*nameCred, *emailCred},
		}
		fulfilled, err := fulfiller.fulfillRequirement(requirement)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(fulfilled))
		assert.Equal(t, "name_input", fulfilled[0].DescriptorID)
		assert.Equal(t, nameCred.ID, fulfilled[0].CredID)
	})

	t.Run("Error cases -- invalid combinations of count, min, max", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule:    "pick",
			Minimum: 5,
			Maximum: 1,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		descriptors := []definition.InputDescriptor{
			{
				ID:    "name_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{nameCred.Schema.ID},
					Name:    "Name",
					Purpose: "We need your name",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.firstName"},
							Purpose: "We need your first name",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
		}
		fulfiller := requestFulfiller{
			responderID: holderDoc.ID,
			descriptors: descriptors,
			credentials: []credential.VerifiableCredential{*nameCred, *emailCred},
		}
		_, err := fulfiller.fulfillRequirement(requirement)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid value for count, min, and/or max")

		requirement = definition.SubmissionRequirement{
			Rule:    "pick",
			Count:   1,
			Minimum: 1,
			Maximum: 1,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		_, err = fulfiller.fulfillRequirement(requirement)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "count, min, and max present")
	})
}

func TestFulfillRequirements(t *testing.T) {
	// create an issuer and target holder for the credential
	issuerDoc, issuerPrivKey := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	holderDoc, _ := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	input := credGenInput{
		issuerPrivKey: issuerPrivKey,
		issuerDoc:     *issuerDoc,
		holderDoc:     *holderDoc,
	}
	nameCred := makeMeANameCred(t, input)
	assert.NotEmpty(t, nameCred)

	emailCred := makeMeAnEmailCred(t, input)
	assert.NotEmpty(t, emailCred)

	t.Run("One requirement, one descriptor", func(t *testing.T) {
		requirements := []definition.SubmissionRequirement{
			{
				Rule: "all",
				FromOption: definition.FromOption{
					From: "A",
				},
			},
		}
		descriptors := []definition.InputDescriptor{
			{
				ID:    "name_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{nameCred.Schema.ID},
					Name:    "Name",
					Purpose: "We need your name",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.firstName"},
							Purpose: "We need your first name",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
		}
		fulfiller := requestFulfiller{
			responderID: holderDoc.ID,
			descriptors: descriptors,
			credentials: []credential.VerifiableCredential{*nameCred},
		}
		fulfilledReqs, err := fulfiller.fulfillRequirements(requirements)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(fulfilledReqs))
		assert.Equal(t, "name_input", fulfilledReqs[0].DescriptorID)
		assert.Equal(t, nameCred.ID, fulfilledReqs[0].CredID)
	})

	t.Run("One requirement, two descriptors, only one fulfills", func(t *testing.T) {
		requirements := []definition.SubmissionRequirement{
			{
				Rule: "all",
				FromOption: definition.FromOption{
					From: "A",
				},
			},
		}
		descriptors := []definition.InputDescriptor{
			{
				ID:    "name_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{nameCred.Schema.ID},
					Name:    "Name",
					Purpose: "We need your name",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.firstName"},
							Purpose: "We need your first name",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
			{
				ID:    "email_input",
				Group: []string{"B"},
				Schema: &definition.Schema{
					URI:     []string{emailCred.Schema.ID},
					Name:    "Email",
					Purpose: "We need your email",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.emailAddress"},
							Purpose: "We need your email",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
		}
		fulfiller := requestFulfiller{
			responderID: holderDoc.ID,
			descriptors: descriptors,
			credentials: []credential.VerifiableCredential{*nameCred},
		}
		fulfilledReqs, err := fulfiller.fulfillRequirements(requirements)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(fulfilledReqs))
		assert.Equal(t, "name_input", fulfilledReqs[0].DescriptorID)
		assert.Equal(t, nameCred.ID, fulfilledReqs[0].CredID)
	})

	t.Run("Two requirements, two descriptors, both fulfill", func(t *testing.T) {
		requirements := []definition.SubmissionRequirement{
			{
				Rule: "all",
				FromOption: definition.FromOption{
					From: "A",
				},
			},
			{
				Rule:  "pick",
				Count: 1,
				FromOption: definition.FromOption{
					From: "B",
				},
			},
		}
		descriptors := []definition.InputDescriptor{
			{
				ID:    "name_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{nameCred.Schema.ID},
					Name:    "Name",
					Purpose: "We need your name",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.firstName"},
							Purpose: "We need your first name",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
			{
				ID:    "email_input",
				Group: []string{"B"},
				Schema: &definition.Schema{
					URI:     []string{emailCred.Schema.ID},
					Name:    "Email",
					Purpose: "We need your email",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.emailAddress"},
							Purpose: "We need your email",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
		}

		fulfiller := requestFulfiller{
			responderID: holderDoc.ID,
			descriptors: descriptors,
			credentials: []credential.VerifiableCredential{*nameCred, *emailCred},
		}
		fulfilledReqs, err := fulfiller.fulfillRequirements(requirements)
		assert.NoError(t, err)
		assert.Equal(t, 2, len(fulfilledReqs))
		assert.Equal(t, "name_input", fulfilledReqs[0].DescriptorID)
		assert.Equal(t, nameCred.ID, fulfilledReqs[0].CredID)
		assert.Equal(t, "email_input", fulfilledReqs[1].DescriptorID)
		assert.Equal(t, emailCred.ID, fulfilledReqs[1].CredID)
	})

	t.Run("No descriptors that are able to fulfill the requirement", func(t *testing.T) {
		requirements := []definition.SubmissionRequirement{
			{
				Rule: "all",
				FromOption: definition.FromOption{
					From: "A",
				},
			},
			{
				Rule:  "pick",
				Count: 1,
				FromOption: definition.FromOption{
					From: "B",
				},
			},
		}
		descriptors := []definition.InputDescriptor{
			{
				ID:    "name_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{nameCred.Schema.ID},
					Name:    "Name",
					Purpose: "We need your name",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.firstName"},
							Purpose: "We need your first name",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
		}

		fulfiller := requestFulfiller{
			responderID: holderDoc.ID,
			descriptors: descriptors,
			credentials: []credential.VerifiableCredential{*nameCred, *emailCred},
		}
		_, err := fulfiller.fulfillRequirements(requirements)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "descriptors could not be found to fulfill the requirement")
	})

	t.Run("Requirement that cannot be fulfilled (no matching cred)", func(t *testing.T) {
		requirements := []definition.SubmissionRequirement{
			{
				Rule: "all",
				FromOption: definition.FromOption{
					From: "A",
				},
			},
		}
		descriptors := []definition.InputDescriptor{
			{
				ID:    "name_input",
				Group: []string{"A"},
				Schema: &definition.Schema{
					URI:     []string{nameCred.Schema.ID},
					Name:    "Name",
					Purpose: "We need your name",
				},
				Constraints: &definition.Constraints{
					LimitDisclosure: true,
					Fields: []definition.Field{
						{
							Path:    []string{"$.credentialSubject.firstName"},
							Purpose: "We need your first name",
							Filter: &definition.Filter{
								Type:      "string",
								MinLength: 1,
							},
						},
					},
				},
			},
		}

		fulfiller := requestFulfiller{
			responderID: holderDoc.ID,
			descriptors: descriptors,
			credentials: []credential.VerifiableCredential{*emailCred},
		}
		_, err := fulfiller.fulfillRequirements(requirements)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "requirement could not be satisfied")
	})
}

func TestGatherInputDescriptorsForRequirement(t *testing.T) {
	testDescriptor := definition.InputDescriptor{
		ID:    "test",
		Group: []string{"A"},
		Schema: &definition.Schema{
			URI:  []string{"test"},
			Name: "test",
		},
	}

	t.Run("multiple groups, 1 matches", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule:    "pick",
			Maximum: 1,
			FromOption: definition.FromOption{
				From: "A",
			},
		}
		descriptors := []definition.InputDescriptor{
			testDescriptor,
			{
				ID:    "test",
				Group: []string{"B"},
				Schema: &definition.Schema{
					URI:  []string{"test"},
					Name: "test",
				},
			},
			{
				ID:    "test",
				Group: []string{"C"},
				Schema: &definition.Schema{
					URI:  []string{"test"},
					Name: "test",
				},
			},
		}
		res, err := gatherInputDescriptorsForRequirement(requirement, descriptors)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(res))
		assert.Contains(t, res, testDescriptor)
	})

	t.Run("multiple groups, all match", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule:    "pick",
			Maximum: 1,
			FromOption: definition.FromOption{
				FromNested: []definition.SubmissionRequirement{
					{
						Rule: "all",
						FromOption: definition.FromOption{
							From: "A",
						},
					},
					{
						Rule: "all",
						FromOption: definition.FromOption{
							From: "B",
						},
					},
					{
						Rule: "all",
						FromOption: definition.FromOption{
							From: "C",
						},
					},
				},
			},
		}
		descriptors := []definition.InputDescriptor{
			testDescriptor,
			{
				ID:    "test",
				Group: []string{"B"},
				Schema: &definition.Schema{
					URI:  []string{"test"},
					Name: "test",
				},
			},
			{
				ID:    "test",
				Group: []string{"C"},
				Schema: &definition.Schema{
					URI:  []string{"test"},
					Name: "test",
				},
			},
		}
		res, err := gatherInputDescriptorsForRequirement(requirement, descriptors)
		assert.NoError(t, err)
		assert.Equal(t, 3, len(res))
		assert.Contains(t, res, testDescriptor)
	})

	t.Run("multiple groups with nesting, A and B match", func(t *testing.T) {
		requirement := definition.SubmissionRequirement{
			Rule:    "pick",
			Maximum: 1,
			FromOption: definition.FromOption{
				FromNested: []definition.SubmissionRequirement{
					{
						Rule: "all",
						FromOption: definition.FromOption{
							FromNested: []definition.SubmissionRequirement{
								{
									Rule: "all",
									FromOption: definition.FromOption{
										From: "A",
									},
								},
								{
									Rule: "all",
									FromOption: definition.FromOption{
										From: "B",
									},
								},
							},
						},
					},
					{
						Rule: "all",
						FromOption: definition.FromOption{
							From: "C",
						},
					},
				},
			},
		}
		descriptors := []definition.InputDescriptor{
			testDescriptor,
			{
				ID:    "test",
				Group: []string{"B"},
				Schema: &definition.Schema{
					URI:  []string{"test"},
					Name: "test",
				},
			},
		}
		res, err := gatherInputDescriptorsForRequirement(requirement, descriptors)
		assert.NoError(t, err)
		assert.Equal(t, 2, len(res))
		assert.Contains(t, res, testDescriptor)
	})
}

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
	ledgerSchema, err := ledger.GenerateLedgerSchema("Name Schema", input.issuerDoc.ID, signer, proof.JCSEdSignatureType, nameSchemaMap)
	assert.NoError(t, err)

	// choose a cred id
	credID := uuid.New().String()

	// create the credential metadata (this one doesn't expire)
	baseRevocationURL := "https://testrevocationservice.com/"
	metadata := credential.NewMetadataWithTimestamp(credID, input.issuerDoc.ID, ledgerSchema.ID, baseRevocationURL, time.Now())

	// build the credential
	cred, err := credential.Builder{
		SubjectDID: input.holderDoc.ID,
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

func makeMeAnEmailCred(t *testing.T, input credGenInput) (cred *credential.VerifiableCredential) {
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
	ledgerSchema, err := ledger.GenerateLedgerSchema("Email Schema", input.issuerDoc.ID, signer, proof.JCSEdSignatureType, emailSchemaMap)
	assert.NoError(t, err)

	// choose a cred id
	credID := uuid.New().String()

	// create the credential metadata (this one doesn't expire)
	baseRevocationURL := "https://testrevocationservice.com/"
	metadata := credential.NewMetadataWithTimestamp(credID, input.issuerDoc.ID, ledgerSchema.ID, baseRevocationURL, time.Now())

	// build the credential
	cred, err = credential.Builder{
		SubjectDID: input.holderDoc.ID,
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
	return
}

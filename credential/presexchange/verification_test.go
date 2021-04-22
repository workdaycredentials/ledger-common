package presexchange

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/decentralized-identity/presentation-exchange-implementations/pkg/definition"
	"github.com/decentralized-identity/presentation-exchange-implementations/pkg/submission"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/ledger"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

func TestVerifyVerifiablePresentation(t *testing.T) {
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

	t.Run("happy path", func(t *testing.T) {
		presDef := makeMeAPresentationDefinition(t, nameCred.Schema.ID, emailCred.Schema.ID)
		verifier, vp, err := makeMeAVerifiablePresentation(t, vpInput{
			definition:    presDef,
			nameCred:      *nameCred,
			emailCred:     *emailCred,
			issuerDoc:     *issuerDoc,
			issuerPrivKey: issuerPrivKey,
			holderDoc:     *holderDoc,
			holderPrivKey: holderPrivKey,
		})
		require.NoError(t, err)
		err = VerifyVerifiablePresentation(verifier, presDef, vp)
		assert.NoError(t, err)
	})

	t.Run("empty fulfillment", func(t *testing.T) {
		err := VerifyVerifiablePresentation(nil, definition.PresentationDefinition{}, VerifiablePresentation{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot verify empty presentation")
	})

	// create generic signer & verifier
	requesterSigner, err := proof.NewEd25519Signer(issuerPrivKey, issuerDoc.PublicKey[0].ID)
	require.NoError(t, err)
	suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	assert.NoError(t, err)
	verifier := proof.Ed25519Verifier{PubKey: issuerPrivKey.Public().(ed25519.PublicKey)}

	t.Run("bad proof", func(t *testing.T) {
		presDef := makeMeAPresentationDefinition(t, nameCred.Schema.ID, emailCred.Schema.ID)
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:           "bad_id",
				DefinitionID: "bad_def_id",
			},
			Proof: &proof.Proof{
				Created:            "never",
				ProofPurpose:       "verification",
				VerificationMethod: "me",
				Nonce:              "0",
				SignatureValue:     "1",
				Type:               proof.JCSEdSignatureType,
			},
		}
		err := VerifyVerifiablePresentation(&verifier, presDef, vp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature verification failed")
	})

	t.Run("good signature, mismatched definition id", func(t *testing.T) {
		presDef := makeMeAPresentationDefinition(t, nameCred.Schema.ID, emailCred.Schema.ID)
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:            "bad_id",
				DefinitionID:  "bad_def_id",
				DescriptorMap: nil,
			},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err := VerifyVerifiablePresentation(&verifier, presDef, vp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf("definition ID<%s> does not match the definition ID in the submission", presDef.ID))
	})

	t.Run("unfulfilled descriptors", func(t *testing.T) {
		presDef := makeMeAPresentationDefinition(t, nameCred.Schema.ID, emailCred.Schema.ID)
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:            "bad_id",
				DefinitionID:  presDef.ID,
				DescriptorMap: nil,
			},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err := VerifyVerifiablePresentation(&verifier, presDef, vp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "descriptors in the definition were unfulfilled: name_input, email_input")
	})

	t.Run("descriptors present without credentials", func(t *testing.T) {
		presDef := makeMeAPresentationDefinition(t, nameCred.Schema.ID, emailCred.Schema.ID)
		badDescriptors := func(desc []definition.InputDescriptor) []submission.Descriptor {
			var res []submission.Descriptor
			for _, d := range desc {
				res = append(res, submission.Descriptor{
					ID:     d.ID,
					Path:   "bad_path",
					Format: definition.CredentialFormat(definition.LDPVP),
				})
			}
			return res
		}
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:            "bad_id",
				DefinitionID:  presDef.ID,
				DescriptorMap: badDescriptors(presDef.InputDescriptors),
			},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err := VerifyVerifiablePresentation(&verifier, presDef, vp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential not found for descriptor<name_input> path")
	})

	t.Run("descriptors present with wrongly pathed credentials", func(t *testing.T) {
		presDef := makeMeAPresentationDefinition(t, nameCred.Schema.ID, emailCred.Schema.ID)
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:           "test_id",
				DefinitionID: presDef.ID,
				DescriptorMap: []submission.Descriptor{
					{
						// actually email cred
						ID:     presDef.InputDescriptors[0].ID,
						Path:   "$.verifiableCredential[1]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
					{
						// actually name cred
						ID:     presDef.InputDescriptors[1].ID,
						Path:   "$.verifiableCredential[0]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
				},
			},
			VerifiableCredential: []interface{}{nameCred, emailCred},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err := VerifyVerifiablePresentation(&verifier, presDef, vp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "submission not accepted, <2>descriptors not able to be fulfilled: name_input, email_input")
	})

	t.Run("descriptors present with one wrongly pathed credential", func(t *testing.T) {
		presDef := makeMeAPresentationDefinition(t, nameCred.Schema.ID, emailCred.Schema.ID)
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:           "test_id",
				DefinitionID: presDef.ID,
				DescriptorMap: []submission.Descriptor{
					{
						// actually email cred
						ID:     presDef.InputDescriptors[0].ID,
						Path:   "$.verifiableCredential[1]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
					{
						// actually name cred
						ID:     presDef.InputDescriptors[1].ID,
						Path:   "$.verifiableCredential[1]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
				},
			},
			VerifiableCredential: []interface{}{nameCred, emailCred},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err := VerifyVerifiablePresentation(&verifier, presDef, vp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "submission not accepted, <1>descriptors not able to be fulfilled: name_input")
	})

	// TODO(gabe): we do not currently verify any signature other than the outer VP wrapper
	// t.Run("descriptors and credentials present, credential has bad signature", func(t *testing.T) {
	// 	var badNameCred credential.VerifiableCredential
	// 	err := util.DeepCopy(&nameCred, &badNameCred)
	// 	badNameCred.Proof.SignatureValue = "bad"
	//
	// 	presDef := makeMeAPresentationDefinition(t, nameCred.Schema.ID, emailCred.Schema.ID)
	// 	vp := VerifiablePresentation{
	// 		Context: defaultVPContexts,
	// 		Type:    defaultVPTypes,
	// 		PresentationSubmission: &submission.PresentationSubmission{
	// 			ID:           "test_id",
	// 			DefinitionID: presDef.ID,
	// 			DescriptorMap: []submission.Descriptor{
	// 				{
	// 					// actually email cred
	// 					ID:     presDef.InputDescriptors[0].ID,
	// 					Path:   "$.verifiableCredential[0]",
	// 					Format: definition.CredentialFormat(definition.LDPVP),
	// 				},
	// 				{
	// 					// actually name cred
	// 					ID:     presDef.InputDescriptors[1].ID,
	// 					Path:   "$.verifiableCredential[1]",
	// 					Format: definition.CredentialFormat(definition.LDPVP),
	// 				},
	// 			},
	// 		},
	// 		VerifiableCredential: []interface{}{badNameCred, emailCred},
	// 	}
	// 	err = suite.Sign(&vp, requesterSigner, nil)
	// 	require.NoError(t, err)
	// 	err = VerifyVerifiablePresentation(&verifier, presDef, vp)
	// 	assert.Error(t, err)
	// })

	t.Run("descriptors and credentials present, credential has a missing attribute", func(t *testing.T) {
		var badNameCred credential.VerifiableCredential
		err := util.DeepCopy(&nameCred, &badNameCred)
		badNameCred.CredentialSubject["firstName"] = ""

		presDef := makeMeAPresentationDefinition(t, nameCred.Schema.ID, emailCred.Schema.ID)
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:           "test_id",
				DefinitionID: presDef.ID,
				DescriptorMap: []submission.Descriptor{
					{
						// actually email cred
						ID:     presDef.InputDescriptors[0].ID,
						Path:   "$.verifiableCredential[0]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
					{
						// actually name cred
						ID:     presDef.InputDescriptors[1].ID,
						Path:   "$.verifiableCredential[1]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
				},
			},
			VerifiableCredential: []interface{}{badNameCred, emailCred},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err = VerifyVerifiablePresentation(&verifier, presDef, vp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "submission not accepted, <1>descriptors not able to be fulfilled: name_input")
	})

	t.Run("simple definition with submission requirement", func(t *testing.T) {
		presDef := definition.PresentationDefinition{
			Name: "test",
			ID:   uuid.New().String(),
			Format: &definition.Format{
				LDPVP: &definition.LDPType{ProofType: []string{string(proof.JCSEdSignatureType)}},
			},
			SubmissionRequirements: []definition.SubmissionRequirement{
				{
					Name:    "name requirement",
					Purpose: "we need your name",
					Rule:    definition.All,
					FromOption: definition.FromOption{
						From: "A",
					},
				},
			},
			InputDescriptors: []definition.InputDescriptor{
				{
					ID:    "one",
					Name:  "name input",
					Group: []string{"A"},
					Schema: []definition.Schema{
						{
							URI:      nameCred.Schema.ID,
							Required: true,
						},
					},
					Constraints: &definition.Constraints{
						LimitDisclosure: false,
						Fields: []definition.Field{
							{
								Path:    []string{"$.credentialSubject.firstName"},
								Purpose: "we need your first name",
								Filter: &definition.Filter{
									Type:      "string",
									MinLength: 2,
								},
							},
						},
					},
				},
			},
		}
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:           "test_id",
				DefinitionID: presDef.ID,
				DescriptorMap: []submission.Descriptor{
					{
						ID:     presDef.InputDescriptors[0].ID,
						Path:   "$.verifiableCredential[0]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
				},
			},
			VerifiableCredential: []interface{}{nameCred},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err = VerifyVerifiablePresentation(&verifier, presDef, vp)
		assert.NoError(t, err)
	})

	t.Run("simple definition with submission requirement, wrong credential format", func(t *testing.T) {
		presDef := definition.PresentationDefinition{
			Name: "test",
			ID:   uuid.New().String(),
			Format: &definition.Format{
				LDPVP: &definition.LDPType{ProofType: []string{string(proof.JCSEdSignatureType)}},
			},
			SubmissionRequirements: []definition.SubmissionRequirement{
				{
					Name:    "name requirement",
					Purpose: "we need your name",
					Rule:    definition.All,
					FromOption: definition.FromOption{
						From: "A",
					},
				},
			},
			InputDescriptors: []definition.InputDescriptor{
				{
					ID:    "one",
					Name:  "name input",
					Group: []string{"A"},
					Schema: []definition.Schema{
						{
							URI:      nameCred.Schema.ID,
							Required: true,
						},
					},
					Constraints: &definition.Constraints{
						LimitDisclosure: false,
						Fields: []definition.Field{
							{
								Path:    []string{"$.credentialSubject.firstName"},
								Purpose: "we need your first name",
								Filter: &definition.Filter{
									Type:      "string",
									MinLength: 2,
								},
							},
						},
					},
				},
			},
		}
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:           "test_id",
				DefinitionID: presDef.ID,
				DescriptorMap: []submission.Descriptor{
					{
						ID:     presDef.InputDescriptors[0].ID,
						Path:   "$.verifiableCredential[0]",
						Format: definition.CredentialFormat(definition.JWTVP),
					},
				},
			},
			VerifiableCredential: []interface{}{nameCred},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err = VerifyVerifiablePresentation(&verifier, presDef, vp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported descriptor format: jwt_vp")
	})

	t.Run("simple definition with submission requirement and excess input descriptors", func(t *testing.T) {
		presDef := definition.PresentationDefinition{
			Name: "test",
			ID:   uuid.New().String(),
			Format: &definition.Format{
				LDPVP: &definition.LDPType{ProofType: []string{string(proof.JCSEdSignatureType)}},
			},
			SubmissionRequirements: []definition.SubmissionRequirement{
				{
					Name:    "name requirement",
					Purpose: "we need your name",
					Rule:    definition.All,
					FromOption: definition.FromOption{
						From: "A",
					},
				},
			},
			InputDescriptors: []definition.InputDescriptor{
				{
					ID:    "one",
					Name:  "name input",
					Group: []string{"A"},
					Schema: []definition.Schema{
						{
							URI:      nameCred.Schema.ID,
							Required: true,
						},
					},
					Constraints: &definition.Constraints{
						LimitDisclosure: false,
						Fields: []definition.Field{
							{
								Path:    []string{"$.credentialSubject.firstName"},
								Purpose: "we need your first name",
								Filter: &definition.Filter{
									Type:      "string",
									MinLength: 2,
								},
							},
						},
					},
				},
				{
					ID:    "bad",
					Name:  "bad input",
					Group: []string{"B"},
					Schema: []definition.Schema{
						{
							URI:      emailCred.Schema.ID,
							Required: true,
						},
					},
				},
			},
		}
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:           "test_id",
				DefinitionID: presDef.ID,
				DescriptorMap: []submission.Descriptor{
					{
						ID:     presDef.InputDescriptors[0].ID,
						Path:   "$.verifiableCredential[0]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
				},
			},
			VerifiableCredential: []interface{}{nameCred},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err = VerifyVerifiablePresentation(&verifier, presDef, vp)
		assert.NoError(t, err)
	})

	t.Run("submission requirement cannot be fulfilled by input", func(t *testing.T) {
		presDef := definition.PresentationDefinition{
			Name: "test",
			ID:   uuid.New().String(),
			Format: &definition.Format{
				LDPVP: &definition.LDPType{ProofType: []string{string(proof.JCSEdSignatureType)}},
			},
			SubmissionRequirements: []definition.SubmissionRequirement{
				{
					Name:    "name requirement",
					Purpose: "we need your name",
					Rule:    definition.All,
					FromOption: definition.FromOption{
						From: "A",
					},
				},
			},
			InputDescriptors: []definition.InputDescriptor{
				{
					ID:   "one",
					Name: "name input",
					// wrong group
					Group: []string{"B"},
					Schema: []definition.Schema{
						{
							URI:      nameCred.Schema.ID,
							Required: true,
						},
					},
					Constraints: &definition.Constraints{
						LimitDisclosure: false,
						Fields: []definition.Field{
							{
								Path:    []string{"$.credentialSubject.firstName"},
								Purpose: "we need your first name",
								Filter: &definition.Filter{
									Type:      "string",
									MinLength: 2,
								},
							},
						},
					},
				},
			},
		}
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:           "test_id",
				DefinitionID: presDef.ID,
				DescriptorMap: []submission.Descriptor{
					{
						ID:     presDef.InputDescriptors[0].ID,
						Path:   "$.verifiableCredential[0]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
				},
			},
			VerifiableCredential: []interface{}{nameCred},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err = VerifyVerifiablePresentation(&verifier, presDef, vp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no descriptors fulfilled for group<A>")
	})

	t.Run("submission requirement with matching descriptor, missing data", func(t *testing.T) {
		var badNameCred credential.VerifiableCredential
		err := util.DeepCopy(&nameCred, &badNameCred)
		badNameCred.CredentialSubject["firstName"] = ""
		presDef := definition.PresentationDefinition{
			Name: "test",
			ID:   uuid.New().String(),
			Format: &definition.Format{
				LDPVP: &definition.LDPType{ProofType: []string{string(proof.JCSEdSignatureType)}},
			},
			SubmissionRequirements: []definition.SubmissionRequirement{
				{
					Name:    "name requirement",
					Purpose: "we need your name",
					Rule:    definition.All,
					FromOption: definition.FromOption{
						From: "A",
					},
				},
			},
			InputDescriptors: []definition.InputDescriptor{
				{
					ID:    "one",
					Name:  "name input",
					Group: []string{"A"},
					Schema: []definition.Schema{
						{
							URI:      nameCred.Schema.ID,
							Required: true,
						},
					},
					Constraints: &definition.Constraints{
						LimitDisclosure: false,
						Fields: []definition.Field{
							{
								Path:    []string{"$.credentialSubject.firstName"},
								Purpose: "we need your first name",
								Filter: &definition.Filter{
									Type:      "string",
									MinLength: 2,
								},
							},
						},
					},
				},
			},
		}
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:           "test_id",
				DefinitionID: presDef.ID,
				DescriptorMap: []submission.Descriptor{
					{
						ID:     presDef.InputDescriptors[0].ID,
						Path:   "$.verifiableCredential[0]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
				},
			},
			VerifiableCredential: []interface{}{badNameCred},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err = VerifyVerifiablePresentation(&verifier, presDef, vp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no descriptors fulfilled for group<A>")
	})

	t.Run("submission requirement with matching descriptor, not enough to fill bound", func(t *testing.T) {
		presDef := definition.PresentationDefinition{
			Name: "test",
			ID:   uuid.New().String(),
			Format: &definition.Format{
				LDPVP: &definition.LDPType{ProofType: []string{string(proof.JCSEdSignatureType)}},
			},
			SubmissionRequirements: []definition.SubmissionRequirement{
				{
					Name:    "name requirement",
					Purpose: "we need your name",
					Rule:    definition.Pick,
					Count:   5,
					FromOption: definition.FromOption{
						From: "A",
					},
				},
			},
			InputDescriptors: []definition.InputDescriptor{
				{
					ID:    "one",
					Name:  "name input",
					Group: []string{"A"},
					Schema: []definition.Schema{
						{
							URI:      nameCred.Schema.ID,
							Required: true,
						},
					},
					Constraints: &definition.Constraints{
						LimitDisclosure: false,
						Fields: []definition.Field{
							{
								Path:    []string{"$.credentialSubject.firstName"},
								Purpose: "we need your first name",
								Filter: &definition.Filter{
									Type:      "string",
									MinLength: 2,
								},
							},
						},
					},
				},
			},
		}
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:           "test_id",
				DefinitionID: presDef.ID,
				DescriptorMap: []submission.Descriptor{
					{
						ID:     presDef.InputDescriptors[0].ID,
						Path:   "$.verifiableCredential[0]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
				},
			},
			VerifiableCredential: []interface{}{nameCred},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err = VerifyVerifiablePresentation(&verifier, presDef, vp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "needed between<5> and <5> descriptors fulfilled from<A> and received <1>")
	})

	t.Run("multiple requirements, both fulfilled", func(t *testing.T) {
		presDef := definition.PresentationDefinition{
			Name: "test",
			ID:   uuid.New().String(),
			Format: &definition.Format{
				LDPVP: &definition.LDPType{ProofType: []string{string(proof.JCSEdSignatureType)}},
			},
			SubmissionRequirements: []definition.SubmissionRequirement{
				{
					Name:    "name requirement",
					Purpose: "we need your name",
					Rule:    definition.Pick,
					Count:   1,
					FromOption: definition.FromOption{
						From: "A",
					},
				},
				{
					Name:    "email requirement",
					Purpose: "we need your email",
					Rule:    definition.All,
					FromOption: definition.FromOption{
						From: "B",
					},
				},
			},
			InputDescriptors: []definition.InputDescriptor{
				{
					ID:    "one",
					Name:  "name input",
					Group: []string{"A"},
					Schema: []definition.Schema{
						{
							URI:      nameCred.Schema.ID,
							Required: true,
						},
					},
					Constraints: &definition.Constraints{
						LimitDisclosure: false,
						Fields: []definition.Field{
							{
								Path:    []string{"$.credentialSubject.firstName"},
								Purpose: "we need your first name",
								Filter: &definition.Filter{
									Type:      "string",
									MinLength: 2,
								},
							},
						},
					},
				},
				{
					ID:    "two",
					Name:  "email input",
					Group: []string{"B"},
					Schema: []definition.Schema{
						{
							URI:      emailCred.Schema.ID,
							Required: true,
						},
					},
					Constraints: &definition.Constraints{
						LimitDisclosure: false,
						Fields: []definition.Field{
							{
								Path:    []string{"$.credentialSubject.emailAddress"},
								Purpose: "we need your email address",
								Filter: &definition.Filter{
									Type:   "string",
									Format: "email",
								},
							},
						},
					},
				},
			},
		}
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:           "test_id",
				DefinitionID: presDef.ID,
				DescriptorMap: []submission.Descriptor{
					{
						ID:     presDef.InputDescriptors[0].ID,
						Path:   "$.verifiableCredential[0]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
					{
						ID:     presDef.InputDescriptors[1].ID,
						Path:   "$.verifiableCredential[1]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
				},
			},
			VerifiableCredential: []interface{}{nameCred, emailCred},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err = VerifyVerifiablePresentation(&verifier, presDef, vp)
		assert.NoError(t, err)
	})

	t.Run("multiple requirements, one fulfilled", func(t *testing.T) {
		presDef := definition.PresentationDefinition{
			Name: "test",
			ID:   uuid.New().String(),
			Format: &definition.Format{
				LDPVP: &definition.LDPType{ProofType: []string{string(proof.JCSEdSignatureType)}},
			},
			SubmissionRequirements: []definition.SubmissionRequirement{
				{
					Name:    "name requirement",
					Purpose: "we need your name",
					Rule:    definition.Pick,
					Count:   1,
					FromOption: definition.FromOption{
						From: "A",
					},
				},
				{
					Name:    "email requirement",
					Purpose: "we need your email",
					Rule:    definition.All,
					FromOption: definition.FromOption{
						From: "B",
					},
				},
			},
			InputDescriptors: []definition.InputDescriptor{
				{
					ID:    "one",
					Name:  "name input",
					Group: []string{"A"},
					Schema: []definition.Schema{
						{
							URI:      nameCred.Schema.ID,
							Required: true,
						},
					},
					Constraints: &definition.Constraints{
						LimitDisclosure: false,
						Fields: []definition.Field{
							{
								Path:    []string{"$.credentialSubject.firstName"},
								Purpose: "we need your first name",
								Filter: &definition.Filter{
									Type:      "string",
									MinLength: 2,
								},
							},
						},
					},
				},
				{
					ID:    "two",
					Name:  "email input",
					Group: []string{"B"},
					Schema: []definition.Schema{
						{
							URI:      emailCred.Schema.ID,
							Required: true,
						},
					},
					Constraints: &definition.Constraints{
						LimitDisclosure: false,
						Fields: []definition.Field{
							{
								Path:    []string{"$.credentialSubject.emailAddress"},
								Purpose: "we need your email address",
								Filter: &definition.Filter{
									Type:   "string",
									Format: "email",
								},
							},
						},
					},
				},
			},
		}
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:           "test_id",
				DefinitionID: presDef.ID,
				DescriptorMap: []submission.Descriptor{
					{
						ID:     presDef.InputDescriptors[0].ID,
						Path:   "$.verifiableCredential[0]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
					{
						ID:     presDef.InputDescriptors[1].ID,
						Path:   "$.verifiableCredential[1]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
				},
			},
			// Don't submit email cred
			VerifiableCredential: []interface{}{nameCred, nameCred},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err = VerifyVerifiablePresentation(&verifier, presDef, vp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no descriptors fulfilled for group<B>")
	})

	t.Run("multiple requirements, nesting groups", func(t *testing.T) {
		presDef := definition.PresentationDefinition{
			Name: "test",
			ID:   uuid.New().String(),
			Format: &definition.Format{
				LDPVP: &definition.LDPType{ProofType: []string{string(proof.JCSEdSignatureType)}},
			},
			SubmissionRequirements: []definition.SubmissionRequirement{
				{
					Name:    "name requirement",
					Purpose: "we need your name",
					Rule:    definition.Pick,
					Count:   2,
					FromOption: definition.FromOption{
						FromNested: []definition.SubmissionRequirement{
							{
								Name:    "name requirement",
								Purpose: "we need your first name",
								Rule:    definition.All,
								FromOption: definition.FromOption{
									From: "A",
								},
							},
							{
								Name:    "email requirement",
								Purpose: "we need your email",
								Rule:    definition.All,
								FromOption: definition.FromOption{
									From: "B",
								},
							},
						},
					},
				},
			},
			InputDescriptors: []definition.InputDescriptor{
				{
					ID:    "one",
					Name:  "name input",
					Group: []string{"A"},
					Schema: []definition.Schema{
						{
							URI:      nameCred.Schema.ID,
							Required: true,
						},
					},
					Constraints: &definition.Constraints{
						LimitDisclosure: false,
						Fields: []definition.Field{
							{
								Path:    []string{"$.credentialSubject.firstName"},
								Purpose: "we need your first name",
								Filter: &definition.Filter{
									Type:      "string",
									MinLength: 2,
								},
							},
						},
					},
				},
				{
					ID:    "two",
					Name:  "email input",
					Group: []string{"B"},
					Schema: []definition.Schema{
						{
							URI:      emailCred.Schema.ID,
							Required: true,
						},
					},
					Constraints: &definition.Constraints{
						LimitDisclosure: false,
						Fields: []definition.Field{
							{
								Path:    []string{"$.credentialSubject.emailAddress"},
								Purpose: "we need your email address",
								Filter: &definition.Filter{
									Type:   "string",
									Format: "email",
								},
							},
						},
					},
				},
			},
		}
		vp := VerifiablePresentation{
			Context: defaultVPContexts,
			Type:    defaultVPTypes,
			PresentationSubmission: &submission.PresentationSubmission{
				ID:           "test_id",
				DefinitionID: presDef.ID,
				DescriptorMap: []submission.Descriptor{
					{
						ID:     presDef.InputDescriptors[0].ID,
						Path:   "$.verifiableCredential[0]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
					{
						ID:     presDef.InputDescriptors[1].ID,
						Path:   "$.verifiableCredential[1]",
						Format: definition.CredentialFormat(definition.LDPVP),
					},
				},
			},
			// Don't submit email cred
			VerifiableCredential: []interface{}{nameCred, emailCred},
		}
		err = suite.Sign(&vp, requesterSigner, nil)
		require.NoError(t, err)
		err = VerifyVerifiablePresentation(&verifier, presDef, vp)
		assert.NoError(t, err)
	})
}

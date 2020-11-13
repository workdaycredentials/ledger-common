package response

import (
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/credential/presentation"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

func GenerateCompositeProofResponse(proofRequest presentation.CompositeProofRequestInstanceChallenge, fulfilledCriteria []presentation.FulfilledCriterion, signer proof.Signer) (*presentation.CompositeProofResponseSubmission, error) {
	proofReq := presentation.CompositeProofResponseSubmission{
		UnsignedCompositeProofResponseSubmission: presentation.UnsignedCompositeProofResponseSubmission{
			ProofReqRespMetadata:   ProofRespMetadata(),
			ProofRequestInstanceID: proofRequest.ProofRequestInstanceID,
			FulfilledCriteria:      fulfilledCriteria,
		},
	}
	// TODO(gabe) variable signature types for proof responses
	signatureType := proof.JCSEdSignatureType
	suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	if err != nil {
		return nil, err
	}
	options := &proof.ProofOptions{ProofPurpose: proof.AssertionMethodPurpose}
	err = suite.Sign(&proofReq, signer, options)
	return &proofReq, err
}

func ProofRespMetadata() presentation.ProofReqRespMetadata {
	return presentation.ProofReqRespMetadata{
		Type:         util.ProofResponseTypeReference_v1_0,
		ModelVersion: util.Version_1_0,
		ID:           uuid.New().String(),
	}
}

func FulfillCriterionForVCs(criterion presentation.Criterion, variables map[string]interface{}, submittedV1Credentials []credential.UnsignedVerifiableCredential, signer proof.Signer) (*presentation.FulfilledCriterion, error) {
	var presentations []presentation.Presentation
	if err := presentation.CheckVCsMatchCriterion(criterion, submittedV1Credentials, variables); err != nil {
		return nil, err
	}
	for _, cred := range submittedV1Credentials {
		filteredCred := cred
		stripUnrequestedAttributesFromCredential(criterion, &filteredCred)
		presentationID := uuid.New().String()
		pres, err := presentation.GeneratePresentationFromVC(filteredCred, signer, proof.JCSEdSignatureType, presentationID)
		if err != nil {
			return nil, err
		}
		presentations = append(presentations, *pres)
	}

	return &presentation.FulfilledCriterion{
		Criterion:     criterion,
		Presentations: presentations,
	}, nil
}

// FilterCredential removes unselected, optional claims and claim proofs from the given credential with respect to the
// proof request criteria. It will also add any missing required attributes with a null value and no associated
// Claim Proof. The function returns the filtered credential.
func FilterCredential(criteria *presentation.CriteriaHolder, cred credential.UnsignedVerifiableCredential, selectedAttributes []string) credential.UnsignedVerifiableCredential {
	stripUnselectedAttributesFromCredential(criteria.Criterion, &cred, selectedAttributes)
	return cred
}

// stripUnrequestedAttributesFromCredential removes any claim attributes and proofs from the credential that were not
// requested in the criterion. Exceptions being that the "id" attribute is always implicitly requested, and optional
// attributes with nil values will be removed.
//
// NOTE: This function may leave attributes without associated Claim Proofs or add nil values for required attributes.
// This may cause a validation error to be returned further down the line. This function does not attempt to make a
// determination about the validity of such a credential.
func stripUnrequestedAttributesFromCredential(criterion presentation.Criterion, credential *credential.UnsignedVerifiableCredential) {
	var requestedAttributes []string
	for _, attr := range criterion.Schema.Attributes {
		requestedAttributes = append(requestedAttributes, attr.AttributeName)
	}
	stripUnselectedAttributesFromCredential(criterion, credential, requestedAttributes)
}

// stripUnselectedAttributesFromCredential removes any claim attributes and proofs from the credential that were not
// required by the criterion or selected by the holder. Exceptions being that the "id" attribute is always implicitly
// requested, and optional attributes with nil values will be removed.
//
// NOTE: This function may leave attributes without associated Claim Proofs or add nil values for required attributes.
// This may cause a validation error to be returned further down the line. This function does not attempt to make a
// determination about the validity of such a credential.
func stripUnselectedAttributesFromCredential(criterion presentation.Criterion, cred *credential.UnsignedVerifiableCredential, selectedAttributes []string) {
	disclosedAttrs := make(map[string]interface{})
	disclosedProofs := make(map[string]proof.Proof)

	if subjectDID, ok := cred.CredentialSubject[credential.SubjectIDAttribute]; ok {
		disclosedAttrs[credential.SubjectIDAttribute] = subjectDID
		if p, ok := cred.ClaimProofs[credential.SubjectIDAttribute]; ok {
			disclosedProofs[credential.SubjectIDAttribute] = p
		}
	} else {
		logrus.Warnf("could not find subject identity %s in credential %s", credential.SubjectIDAttribute, cred.ID)
	}

	selectedAttributeSet := make(map[string]bool)
	for _, attr := range selectedAttributes {
		selectedAttributeSet[attr] = true
	}

	for _, requestedAttr := range criterion.Schema.Attributes {
		name := requestedAttr.AttributeName
		if requestedAttr.Required || selectedAttributeSet[name] {
			value, hasAttr := cred.CredentialSubject[name]
			p, hasProof := cred.ClaimProofs[name]

			if requestedAttr.Required || (hasAttr && value != nil) {
				disclosedAttrs[name] = value
				if hasProof {
					disclosedProofs[name] = p
				}
			}
		}
	}
	cred.CredentialSubject = disclosedAttrs
	cred.ClaimProofs = disclosedProofs
}
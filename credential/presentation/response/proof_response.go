package response

import (
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"go.wday.io/credentials-open-source/ledger-common/credential"
	"go.wday.io/credentials-open-source/ledger-common/credential/presentation"
	"go.wday.io/credentials-open-source/ledger-common/proof"
	"go.wday.io/credentials-open-source/ledger-common/util"
)

func GenerateCompositeProofResponse(proofRequest presentation.CompositeProofRequestInstanceChallenge, fulfilledCriteria []presentation.FulfilledCriterion, signer proof.Signer) (*presentation.CompositeProofResponseSubmission, error) {
	proofReq := presentation.CompositeProofResponseSubmission{
		ProofReqRespMetadata:   ProofRespMetadata(),
		ProofRequestInstanceID: proofRequest.ProofRequestInstanceID,
		FulfilledCriteria:      fulfilledCriteria,
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

func FulfillCriterionForVCs(criterion presentation.Criterion, variables map[string]interface{}, submittedCreds []credential.RawCredential, signer proof.Signer) (*presentation.FulfilledCriterion, error) {
	var presentations []presentation.Presentation
	var creds []credential.VerifiableCredential
	for _, rawCred := range submittedCreds {
		creds = append(creds, rawCred.VerifiableCredential)
	}
	if err := presentation.CheckVCsMatchCriterion(criterion, creds, variables); err != nil {
		return nil, err
	}
	for _, cred := range submittedCreds {
		filtered, err := filterCredential(criterion, cred)
		if err != nil {
			return nil, err
		}
		presentationID := uuid.New().String()
		pres, err := presentation.GeneratePresentationFromVC(filtered, signer, proof.JCSEdSignatureType, presentationID)
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

// filterCredential removes any claim attributes and proofs from the credential that were not
// requested in the criterion. Exceptions being that the "id" attribute is always implicitly
// requested.
func filterCredential(criterion presentation.Criterion, cred credential.RawCredential) (*credential.RawCredential, error) {
	requestedAttrSet := make(map[string]bool)
	for _, attr := range criterion.Schema.Attributes {
		requestedAttrSet[attr.AttributeName] = true
	}

	// Include the `id` attribute.
	if _, ok := cred.CredentialSubject[credential.SubjectIDAttribute]; ok {
		requestedAttrSet[credential.SubjectIDAttribute] = true
	} else {
		logrus.Warnf("could not find subject identity %s in credential %s", credential.SubjectIDAttribute, cred.ID)
	}

	return cred.Filter(requestedAttrSet)
}

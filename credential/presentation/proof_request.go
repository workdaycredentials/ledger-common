package presentation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"
	"time"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/ledger/schema"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

// CheckVCsMatchCriterion returns an error if the credentials do not satisfy the given criterion.
func CheckVCsMatchCriterion(criterion Criterion, credentials []credential.UnsignedVerifiableCredential, variables map[string]interface{}) error {
	for _, c := range credentials {
		if err := CheckVCMatchesCriterion(criterion, c, variables); err != nil {
			return err
		}
	}

	if len(credentials) < criterion.MinRequired || len(credentials) > criterion.MaxRequired {
		err := fmt.Errorf("required between %d and %d credentials, %d submitted", criterion.MinRequired, criterion.MaxRequired, len(credentials))
		return err
	}
	return nil
}

// CheckVCMatchesCriterion returns an error if the credential does not satisfy the given criterion.
func CheckVCMatchesCriterion(criterion Criterion, cred credential.UnsignedVerifiableCredential, variables map[string]interface{}) error {
	if criterion.Schema.AuthorDID == "" || criterion.Schema.ResourceIdentifier == "" || criterion.Schema.SchemaVersionRange == "" {
		if criterion.Schema.SchemaID != cred.Schema.ID {
			schemaErrMsg := fmt.Sprintf("credential schema %s did not match expected schema %s", cred.Schema.ID, criterion.Schema.SchemaID)
			logrus.WithField("credential.Schema", cred.Schema).WithField("criterion", criterion).Error("schemaErrMsg")
			return fmt.Errorf(schemaErrMsg)
		}
	} else {
		schemaID := cred.Schema.ID
		resourceID, err := schema.ExtractSchemaResourceID(schemaID)
		if err != nil {
			return err
		}
		authorDID, err := schema.ExtractSchemaAuthorDID(schemaID)
		if err != nil {
			return err
		}
		if criterion.Schema.AuthorDID != authorDID {
			return fmt.Errorf("invalid author DID. Expected: %s ; Received: %s", criterion.Schema.AuthorDID, authorDID)
		}
		if criterion.Schema.ResourceIdentifier != resourceID {
			return fmt.Errorf("invalid schema resource identifier. Expected: %s ; Received: %s", criterion.Schema.ResourceIdentifier, resourceID)
		}
		isInVersionRange, err := schema.IDIsInVersionRange(cred.Schema.ID, criterion.Schema.SchemaVersionRange)
		if err != nil {
			return err
		}
		if !isInVersionRange {
			return fmt.Errorf("schema ID<%s> is not in version range: %s", cred.Schema.ID, criterion.Schema.SchemaVersionRange)
		}
	}

	if criterion.AllowExpired == nil || !*criterion.AllowExpired {
		if err := validCredentialExpiry(cred); err != nil {
			return err
		}
	}

	if criterion.Issuers.DIDs != nil && len(criterion.Issuers.DIDs) > 0 {
		found := false
		for _, iss := range criterion.Issuers.DIDs {
			if iss == cred.Issuer {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("could not find issuer %s in DID list", cred.Issuer)
		}
	}

	for _, att := range criterion.Schema.Attributes {
		if att.Required {
			if val, exists := cred.CredentialSubject[att.AttributeName]; !exists {
				return fmt.Errorf(`required property "%s" not found credential "%s"`, att.AttributeName, cred.ID)
			} else {
				if _, exists := cred.ClaimProofs[att.AttributeName]; !exists {
					return fmt.Errorf(`required property "%s" did not have claim proof signature in "%s"`, att.AttributeName, cred.ID)
				}
				if val == nil {
					return fmt.Errorf(`required property "%s" value is nil on credential "%s"`, att.AttributeName, cred.ID)
				}
			}
		}
	}

	value, err := EvalConditions(Scope{
		Credential:     cred,
		VariableValues: variables,
	}, criterion.Conditions)
	if err != nil {
		return fmt.Errorf("could not evaluate conditions: %s", err.Error())
	}
	if !value {
		return fmt.Errorf("did not meet condition(s)")
	}
	return nil
}

func GenerateCompositeProofResponse(proofRequest CompositeProofRequestInstanceChallenge, fulfilledCriteria []FulfilledCriterion, signingKeyRef string, signingKey ed25519.PrivateKey) (*CompositeProofResponseSubmission, error) {
	unsignedProofReq := UnsignedCompositeProofResponseSubmission{
		ProofReqRespMetadata:   ProofRespMetadata(),
		ProofRequestInstanceID: proofRequest.ProofRequestInstanceID,
		FulfilledCriteria:      fulfilledCriteria,
	}
	proofReqBytes, err := canonical.Marshal(unsignedProofReq)
	if err != nil {
		return nil, err
	}
	presProof, err := proof.CreateWorkEd25519Proof(proofReqBytes, signingKeyRef, signingKey, uuid.New().String())
	if presProof != nil {
		return &CompositeProofResponseSubmission{
			UnsignedCompositeProofResponseSubmission: unsignedProofReq,
			Proof:                                    []proof.Proof{*presProof},
		}, err
	}
	return nil, err
}

func ProofRespMetadata() ProofReqRespMetadata {
	return ProofReqRespMetadata{
		Type:         util.ProofResponseTypeReference_v1_0,
		ModelVersion: util.Version_1_0,
		ID:           uuid.New().String(),
	}
}

func FulfillCriterionForVCs(criterion Criterion, variables map[string]interface{}, submittedV1Credentials []credential.UnsignedVerifiableCredential, signingKeyRef string, signingKey ed25519.PrivateKey) (*FulfilledCriterion, error) {
	var presentations []Presentation
	if err := CheckVCsMatchCriterion(criterion, submittedV1Credentials, variables); err != nil {
		return nil, err
	}
	for _, cred := range submittedV1Credentials {
		filteredCred := cred
		stripUnrequestedAttributesFromCredential(criterion, &filteredCred)
		uid := uuid.New().String()
		presentation, err := GeneratePresentationFromVC(filteredCred, signingKeyRef, signingKey, uid)
		if err != nil {
			return nil, err
		}
		presentations = append(presentations, *presentation)
	}

	var retVal FulfilledCriterion
	retVal.Criterion = criterion
	retVal.Presentations = presentations
	return &retVal, nil
}

// FilterCredential removes unselected, optional claims and claim proofs from the given credential with respect to the
// proof request criteria. It will also add any missing required attributes with a null value and no associated
// Claim Proof. The function returns the filtered credential as a base64 encoded string.
func FilterCredential(criteria *CriteriaHolder, credentialB64Enc string, selectedAttributes []string) (string, error) {
	var cred credential.UnsignedVerifiableCredential
	if err := decodeAndUnmarshal(credentialB64Enc, &cred); err != nil {
		return "", err
	}
	stripUnselectedAttributesFromCredential(criteria.Criterion, &cred, selectedAttributes)
	jsonBytes, err := json.Marshal(cred)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonBytes), nil
}

func decodeAndUnmarshal(b64Encoded string, v interface{}) error {
	bytes, err := base64.StdEncoding.DecodeString(b64Encoded)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes, &v)
}

// stripUnrequestedAttributesFromCredential removes any claim attributes and proofs from the credential that were not
// requested in the criterion. Exceptions being that the "id" attribute is always implicitly requested, and optional
// attributes with nil values will be removed.
//
// NOTE: This function may leave attributes without associated Claim Proofs or add nil values for required attributes.
// This may cause a validation error to be returned further down the line. This function does not attempt to make a
// determination about the validity of such a credential.
func stripUnrequestedAttributesFromCredential(criterion Criterion, credential *credential.UnsignedVerifiableCredential) {
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
func stripUnselectedAttributesFromCredential(criterion Criterion, cred *credential.UnsignedVerifiableCredential, selectedAttributes []string) {
	disclosedAttrs := make(map[string]interface{})
	disclosedProofs := make(map[string]proof.Proof)

	if subjectDID, ok := cred.CredentialSubject[credential.SubjectIDAttribute]; ok {
		disclosedAttrs[credential.SubjectIDAttribute] = subjectDID
		if proof, ok := cred.ClaimProofs[credential.SubjectIDAttribute]; ok {
			disclosedProofs[credential.SubjectIDAttribute] = proof
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
			proof, hasProof := cred.ClaimProofs[name]

			if requestedAttr.Required || (hasAttr && value != nil) {
				disclosedAttrs[name] = value
				if hasProof {
					disclosedProofs[name] = proof
				}
			}
		}
	}
	cred.CredentialSubject = disclosedAttrs
	cred.ClaimProofs = disclosedProofs
}

func validCredentialExpiry(cred credential.UnsignedVerifiableCredential) error {
	if  cred.ExpirationDate == ""{
		return nil
	}
	now := time.Now().UTC()
	credExp, err := time.Parse(time.RFC3339, cred.ExpirationDate)
	if err != nil {
		return  err
	}
	if now.After(credExp){
		return fmt.Errorf("credential <%s> has expired. expiry: <%s>. current time: <%s>", cred.ID, cred.ExpirationDate, now.Format(time.RFC3339))
	}
	return nil
}

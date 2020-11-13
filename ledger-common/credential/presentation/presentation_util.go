package presentation

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/credential/presentation/conditions"
	"github.com/workdaycredentials/ledger-common/ledger/schema"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

const (
	CredentialsLDContext = "https://w3.org/2018/credentials/v1"
	LDType               = "VerifiablePresentation"
)

// GeneratePresentationFromVC generates a Presentation from a Verifiable Credential, and digitally
// signs it using the key material provided.
func GeneratePresentationFromVC(cred credential.UnsignedVerifiableCredential, signer proof.Signer, signatureType proof.SignatureType, presentationID string) (*Presentation, error) {
	pres := &Presentation{
		UnsignedPresentation: UnsignedPresentation{
			Context:     []string{CredentialsLDContext},
			ID:          presentationID,
			Type:        []string{LDType, util.ProofResponseTypeReference_v1_0},
			Created:     time.Now().UTC().Format(time.RFC3339),
			Credentials: []credential.UnsignedVerifiableCredential{cred},
		},
	}
	suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	if err != nil {
		return nil, err
	}
	options := &proof.ProofOptions{ProofPurpose: proof.AuthenticationPurpose}
	return pres, suite.Sign(pres, signer, options)
}

// CheckVCsMatchCriterion returns an error if the credentials do not satisfy the given criterion.
func CheckVCsMatchCriterion(criterion Criterion, credentials []credential.UnsignedVerifiableCredential, variables map[string]interface{}) error {
	for _, c := range credentials {
		if err := CheckVCMatchesCriterion(criterion, c, variables); err != nil {
			return err
		}
	}

	var err error
	if len(credentials) < criterion.MinRequired || len(credentials) > criterion.MaxRequired {
		err = fmt.Errorf("required between %d and %d credentials, %d submitted", criterion.MinRequired, criterion.MaxRequired, len(credentials))
	}
	return err
}

// CheckVCMatchesCriterion returns an error if the credential does not satisfy the given criterion.
func CheckVCMatchesCriterion(criterion Criterion, cred credential.UnsignedVerifiableCredential, variables map[string]interface{}) error {
	if criterion.Schema.AuthorDID == "" || criterion.Schema.ResourceIdentifier == "" || criterion.Schema.SchemaVersionRange == "" {
		if criterion.Schema.SchemaID != "" && criterion.Schema.SchemaID != cred.Schema.ID {
			schemaErrMsg := fmt.Sprintf("credential schema<%s> did not match expected schema<%s>", cred.Schema.ID, criterion.Schema.SchemaID)
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

	if len(criterion.Issuers.DIDs) > 0 {
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

	value, err := conditions.EvalConditions(conditions.Scope{
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

func validCredentialExpiry(cred credential.UnsignedVerifiableCredential) error {
	if cred.ExpirationDate == "" {
		return nil
	}
	now := time.Now().UTC()
	credExp, err := time.Parse(time.RFC3339, cred.ExpirationDate)
	if err != nil {
		return err
	}
	if now.After(credExp) {
		return fmt.Errorf("credential <%s> has expired. expiry: <%s>. current time: <%s>", cred.ID, cred.ExpirationDate, now.Format(time.RFC3339))
	}
	return nil
}

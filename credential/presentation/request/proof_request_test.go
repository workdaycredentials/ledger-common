package request

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/credential/presentation"
	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/ledger"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

var (
	keySeed              = []byte("12345678901234567890123456789012")
	holderSigningPrivKey = ed25519.NewKeyFromSeed(keySeed)
	holderPublicKey      = holderSigningPrivKey.Public().(ed25519.PublicKey)
)

func TestExtractVerifierFromProofRequest(t *testing.T) {
	var challenge presentation.CompositeProofRequestInstanceChallenge
	err := json.Unmarshal([]byte(proofReqChallenge), &challenge)
	assert.NoError(t, err)

	proofReqStruct := ProofRequestHolder{
		SignedProofRequest: challenge,
	}
	verifierIdentity := proofReqStruct.GetVerifierIdentity()
	expectedID := "did:work:28RB9jAy9HtVet3zFhdWaM"
	assert.Equal(t, expectedID, verifierIdentity)

	numCriteria := proofReqStruct.GetNumberOfCriteria()
	assert.Equal(t, 3, numCriteria)
}

func TestCanGetCriteria(t *testing.T) {
	proofReqStruct := getPopulatedProofRequest()

	contact, err := proofReqStruct.GetCriteria(0)
	assert.NoError(t, err)
	assert.Equal(t, "Contact Information", contact.GetDescription())
	assert.Equal(t, 0, contact.Index)

	add, _ := proofReqStruct.GetCriteria(1)
	assert.NoError(t, err)
	assert.Equal(t, "Billing Address", add.GetDescription())
	assert.Equal(t, 1, add.Index)

	payslip, err := proofReqStruct.GetCriteria(2)
	assert.NoError(t, err)
	assert.Equal(t, "6 Months of payslips", payslip.GetDescription())
	assert.NoError(t, err)
	assert.Equal(t, 2, payslip.Index)

	_, err = proofReqStruct.GetCriteria(3)
	assert.Error(t, err, "index out of bounds 3 elements in the array")
}

func TestCanCheckIfCredMatchesCriteria(t *testing.T) {
	proofReqStruct := getPopulatedProofRequest()

	var contactCred credential.VerifiableCredential
	_ = json.Unmarshal([]byte(contactUnversionedCred), &contactCred)

	var payslipCred credential.VerifiableCredential
	_ = json.Unmarshal([]byte(paySlipCred1), &payslipCred)

	contactHolder, _ := proofReqStruct.GetCriteria(0)
	canFulfill := contactHolder.CanFulfill(contactCred)
	assert.False(t, canFulfill)

	canFulfill = contactHolder.CanFulfill(payslipCred)
	assert.False(t, canFulfill)
}

func TestCanCheckIfV1CredMatchesCriteria(t *testing.T) {
	proofReqStruct := getPopulatedProofRequest()
	contactHolder, _ := proofReqStruct.GetCriteria(0)
	assert.True(t, contactHolder.CanFulfill(contactV1Cred))
	assert.False(t, contactHolder.CanFulfill(paySlipV1Cred1))
}

func TestCheckIfExpiredV1CredMatchesCriteria(t *testing.T) {
	proofReqStruct := getPopulatedProofRequest()
	contactHolder, _ := proofReqStruct.GetCriteria(0)
	expiredCred := contactV1Cred

	expTime := time.Now().Add(-30 * time.Minute).Format(time.RFC3339)
	expiredCred.ExpirationDate = expTime
	assert.False(t, contactHolder.CanFulfill(expiredCred))
}

func TestCheckIfUnExpiredV1CredMatchesCriteria(t *testing.T) {
	proofReqStruct := getPopulatedProofRequest()
	contactHolder, _ := proofReqStruct.GetCriteria(0)
	expiredCred := contactV1Cred

	expTime := time.Now().Add(30 * time.Minute).Format(time.RFC3339)
	expiredCred.ExpirationDate = expTime
	assert.True(t, contactHolder.CanFulfill(expiredCred))
}

func TestAllowedExpiredCredentialCanBeSubmitted(t *testing.T) {
	proofReqStruct := getPopulatedProofRequest()
	allowExpired := true
	proofReqStruct.SignedProofRequest.ProofRequest.Criteria[0].AllowExpired = &allowExpired
	contactHolder, _ := proofReqStruct.GetCriteria(0)
	expiredCred := contactV1Cred

	expTime := time.Now().Add(-30 * time.Minute).Format(time.RFC3339)
	expiredCred.ExpirationDate = expTime
	assert.True(t, contactHolder.CanFulfill(expiredCred))
}

func TestCanCheckIfV1CredMatchesCriteriaFailsIfCriteriaPropertyIsMissingProof(t *testing.T) {
	proofReqStruct := getPopulatedProofRequest()
	paySlipCriteriaHolder, _ := proofReqStruct.GetCriteria(2)

	assert.True(t, paySlipCriteriaHolder.CanFulfill(paySlipV1Cred1))

	missingClaim := make(map[string]proof.Proof)
	for k, v := range paySlipV1Cred1.ClaimProofs {
		if k != "grossPay" {
			missingClaim[k] = v
		}
	}

	paySlipV1Cred1MissingProof := paySlipV1Cred1
	paySlipV1Cred1MissingProof.ClaimProofs = missingClaim
	assert.False(t, paySlipCriteriaHolder.CanFulfill(paySlipV1Cred1MissingProof))

	missingSubject := make(map[string]interface{})
	for k, v := range paySlipV1Cred1.CredentialSubject {
		if k != "payPeriodStart" {
			missingSubject[k] = v
		}
	}
	paySlipV1Cred1MissingReqField := paySlipV1Cred1
	paySlipV1Cred1MissingReqField.CredentialSubject = missingSubject
	assert.False(t, paySlipCriteriaHolder.CanFulfill(paySlipV1Cred1MissingReqField))
}

func TestCanFulfillCriteriaWithV1Credential(t *testing.T) {
	proofReqStruct := getPopulatedProofRequest()
	addressHolder, _ := proofReqStruct.GetCriteria(1)
	addressV1MissingProperty := credential.VerifiableCredential{
		UnsignedVerifiableCredential: credential.UnsignedVerifiableCredential{},
	}
	addressV1MissingProperty.UnsignedVerifiableCredential = addressV1Cred.UnsignedVerifiableCredential
	mapMissingValue := make(map[string]interface{})
	for k, v := range addressV1MissingProperty.CredentialSubject {
		if k != "postalCode" {
			mapMissingValue[k] = v
		}
	}
	addressV1MissingProperty.CredentialSubject = mapMissingValue
	err := proofReqStruct.FulfillCriteria(addressHolder, []credential.UnsignedVerifiableCredential{addressV1MissingProperty.UnsignedVerifiableCredential}, "key-1", holderSigningPrivKey)
	assert.Error(t, err)
	assert.Equal(t, `required property "postalCode" not found credential "422ab006-063e-48f1-91b4-dc09dc512b40"`, err.Error())

	addressV1MissingSig := credential.VerifiableCredential{
		UnsignedVerifiableCredential: credential.UnsignedVerifiableCredential{},
	}
	addressV1MissingSig.UnsignedVerifiableCredential = addressV1Cred.UnsignedVerifiableCredential
	addressV1MissingSig.Proof = addressV1Cred.Proof
	mapMissingSigValue := make(map[string]proof.Proof)
	for k, v := range addressV1MissingSig.ClaimProofs {
		if k != "city" {
			mapMissingSigValue[k] = v
		}
	}
	addressV1MissingSig.ClaimProofs = mapMissingSigValue
	err = proofReqStruct.FulfillCriteria(addressHolder, []credential.UnsignedVerifiableCredential{addressV1MissingSig.UnsignedVerifiableCredential}, "key-1", holderSigningPrivKey)
	assert.Error(t, err)
	assert.Equal(t, `required property "city" did not have claim proof signature in "422ab006-063e-48f1-91b4-dc09dc512b40"`, err.Error())

}

func TestCanFulfilCriteriaWithV1CredentialFailsIfCredentialIsMissingProperties(t *testing.T) {
	proofReqStruct := getPopulatedProofRequest()
	contactHolder, _ := proofReqStruct.GetCriteria(0)
	err := proofReqStruct.FulfillCriteria(contactHolder, []credential.UnsignedVerifiableCredential{contactV1Cred.UnsignedVerifiableCredential}, "key-1", holderSigningPrivKey)
	assert.NoError(t, err)
	assert.Len(t, proofReqStruct.ProofResponseElements, 1)
}

func TestCanGenerateProofRespString(t *testing.T) {
	proofReqStruct := getPopulatedProofRequest()
	contactHolder, _ := proofReqStruct.GetCriteria(0)
	var contactCred credential.VerifiableCredential
	err := json.Unmarshal([]byte(contactUnversionedCred), &contactCred)
	assert.NoError(t, err)

	_ = proofReqStruct.FulfillCriteria(contactHolder, []credential.UnsignedVerifiableCredential{contactCred.UnsignedVerifiableCredential}, "did:work:junk#key-1", holderSigningPrivKey)

	addHolder, _ := proofReqStruct.GetCriteria(1)
	var addressCred credential.VerifiableCredential
	err = json.Unmarshal([]byte(addressCred1), &addressCred)
	_ = proofReqStruct.FulfillCriteria(addHolder, []credential.UnsignedVerifiableCredential{addressCred.UnsignedVerifiableCredential}, "did:work:junk#key-1", holderSigningPrivKey)
}

func credStringToCreds(creds ...string) []credential.UnsignedVerifiableCredential {
	var res []credential.UnsignedVerifiableCredential
	for _, c := range creds {
		var tempCred credential.VerifiableCredential
		json.Unmarshal([]byte(c), &tempCred)
		res = append(res, tempCred.UnsignedVerifiableCredential)
	}
	return res
}

func TestCanGenerateProofRespStringWithV1Credentials(t *testing.T) {
	subjectDID := "did:work:51wzdn5u7nPp944zpDo7b2"
	proofReqStruct := getPopulatedProofRequest()
	keyRef := did.GenerateKeyID(subjectDID, did.InitialKey)

	contactHolder, _ := proofReqStruct.GetCriteria(0)
	err := proofReqStruct.FulfillCriteria(contactHolder, []credential.UnsignedVerifiableCredential{contactV1Cred.UnsignedVerifiableCredential}, keyRef, holderSigningPrivKey)
	assert.NoError(t, err)
	addHolder, _ := proofReqStruct.GetCriteria(1)

	err = proofReqStruct.FulfillCriteria(addHolder, []credential.UnsignedVerifiableCredential{addressV1Cred.UnsignedVerifiableCredential}, keyRef, holderSigningPrivKey)
	assert.NoError(t, err)

	generatedProofResponse, err := proofReqStruct.GenerateProofResponse(keyRef, holderSigningPrivKey)
	assert.NoError(t, err)

	assert.True(t, util.UUIDRegExp.MatchString(generatedProofResponse.ProofReqRespMetadata.ID))
	assert.Equal(t, util.ProofResponseTypeReference_v1_0, generatedProofResponse.ProofReqRespMetadata.Type)
	assert.Equal(t, util.Version_1_0, generatedProofResponse.ProofReqRespMetadata.ModelVersion)
	assert.Len(t, generatedProofResponse.FulfilledCriteria, 2)
	for _, c := range generatedProofResponse.FulfilledCriteria {
		if c.Criterion.Description == "Contact Information" || c.Criterion.Description == "Billing Address" {
			assert.Len(t, c.Presentations, 1)
		} else {
			assert.Len(t, c.Presentations, 6)
		}
		for _, p := range c.Presentations {
			for _, cred := range p.Credentials {
				did, ok := cred.CredentialSubject[credential.SubjectIDAttribute]
				assert.True(t, ok, "subject DID should be available per credentials")
				assert.Equal(t, did, subjectDID)
			}
		}
	}

	p := generatedProofResponse.Proof[0]
	suite, err := proof.SignatureSuites().GetSuiteForProof(p)
	assert.NoError(t, err)
	verifier := &proof.Ed25519Verifier{PubKey: holderPublicKey}
	assert.NoError(t, suite.Verify(generatedProofResponse, verifier))
}

func TestHolderCanReturnDecomposedSchemaQuery(t *testing.T) {
	versionedProofRequest := getPopulatedProofReqWithSchemaRange()
	criteriaHolder, _ := versionedProofRequest.GetCriteria(0)
	assert.True(t, criteriaHolder.CanFulfill(contactV1Cred))
}

func TestHolderSchemaRangeMatchesFiltersCorrectly(t *testing.T) {
	versionedProofRequest := getPopulatedProofReqWithSchemaRange()

	criteriaHolder, _ := versionedProofRequest.GetCriteria(0)
	assert.True(t, criteriaHolder.CanFulfill(contactV1Cred))

	contactV1CredToMod := contactV1Cred
	contactV1CredToMod.Schema.ID = "did:work:6xLyHVb7Fzdq5tcou3y3LL;id=1234-5678-5432;version=1.0"
	assert.False(t, criteriaHolder.CanFulfill(contactV1CredToMod))

	contactV1CredToMod.Schema.ID = "did:work:6xLyHVb7Fzdq5tcou3y3LL;id=1234-5678-5432;version=2.1"
	assert.False(t, criteriaHolder.CanFulfill(contactV1CredToMod))
}

func TestSchemaRangeHolderCanFulfillCriteria(t *testing.T) {
	versionedProofRequest := getPopulatedProofReqWithSchemaRange()
	contactHolder, _ := versionedProofRequest.GetCriteria(0)
	err := versionedProofRequest.FulfillCriteria(contactHolder, []credential.UnsignedVerifiableCredential{contactV1Cred.UnsignedVerifiableCredential}, "did:work:junk#key-1", holderSigningPrivKey)
	assert.NoError(t, err)
}

func getPopulatedProofRequest() ProofRequestHolder {
	var challenge presentation.CompositeProofRequestInstanceChallenge
	_ = json.Unmarshal([]byte(proofReqChallenge), &challenge)
	return ProofRequestHolder{SignedProofRequest: challenge}
}

func getPopulatedProofReqWithSchemaRange() ProofRequestHolder {
	return ProofRequestHolder{SignedProofRequest: proofReqChallengeWithSchemaRange}
}

func Test_isV1Credential(t *testing.T) {
	type args struct {
		credStr string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			args: args{
				credStr: "abcd-claimProof-xyz",
			},
			want: true,
		},
		{
			args: args{
				credStr: "abcd-Proof-xyz",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := IsV1Credential(tt.args.credStr); got != tt.want {
				t.Errorf("IsV1Credential() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_CheckVerifierSignatureWorkEd25519(t *testing.T) {
	// Create a Verifier DIDDoc
	signatureType := proof.JCSEdSignatureType
	verifierDIDDoc, privKey := did.GenerateDIDDoc(proof.Ed25519KeyType, signatureType)
	ledgerDIDDoc := &ledger.DIDDoc{
		Metadata: &ledger.Metadata{
			ID: verifierDIDDoc.ID,
		},
		DIDDoc: verifierDIDDoc,
	}

	// Get test Proof Request and set Verifier
	testProofRequestHolder := getPopulatedProofRequest()
	unsigned := testProofRequestHolder.SignedProofRequest.UnsignedCompositeProofRequestInstanceChallenge
	unsigned.ProofRequest.Verifier = verifierDIDDoc.ID

	// Create proof over Proof Request
	signingKeyRef := did.GenerateKeyID(verifierDIDDoc.ID, did.InitialKey)
	signer, err := proof.NewEd25519Signer(privKey, signingKeyRef)
	assert.NoError(t, err)

	suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	assert.NoError(t, err)

	signed := presentation.CompositeProofRequestInstanceChallenge{
		UnsignedCompositeProofRequestInstanceChallenge: unsigned,
	}
	options := &proof.ProofOptions{ProofPurpose: proof.AssertionMethodPurpose}
	err = suite.Sign(&signed, signer, options)
	assert.NoError(t, err)

	holder := &ProofRequestHolder{
		SignedProofRequest:    signed,
		ProofResponseElements: testProofRequestHolder.ProofResponseElements,
	}

	// Verify
	err = holder.CheckVerifierSignature(*ledgerDIDDoc)
	assert.NoError(t, err)
}

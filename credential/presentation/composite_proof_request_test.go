package presentation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/ledger"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

func TestExtractVerifierFromProofRequest(t *testing.T) {
	proofReqStruct := &ProofRequestHolder{}
	b64Enc := base64.StdEncoding
	b64EncPr := b64Enc.EncodeToString([]byte(proofReqChallenge))

	err := proofReqStruct.Populate(b64EncPr)
	assert.NoError(t, err)

	verifierIdentity := proofReqStruct.GetVerifierIdentity()
	b64encId := b64Enc.EncodeToString([]byte("did:work:28RB9jAy9HtVet3zFhdWaM"))
	assert.Equal(t, b64encId, verifierIdentity)

	numCriteria := proofReqStruct.GetNumberOfCriteria()
	assert.Equal(t, 3, numCriteria)
}

func TestCanGetCriteria(t *testing.T) {
	b64Enc := base64.StdEncoding
	proofReqStruct := getPopulatedProofRequest()

	contact, _ := proofReqStruct.GetCriteria(0)
	descriptionBytes, err := b64Enc.DecodeString(contact.GetDescription())
	assert.NoError(t, err)
	assert.Equal(t, "Contact Information", string(descriptionBytes))
	assert.Equal(t, 0, contact.Index)

	add, _ := proofReqStruct.GetCriteria(1)
	descriptionBytes, err = b64Enc.DecodeString(add.GetDescription())
	assert.NoError(t, err)
	assert.Equal(t, "Billing Address", string(descriptionBytes))
	assert.Equal(t, 1, add.Index)

	payslip, err := proofReqStruct.GetCriteria(2)
	assert.NoError(t, err)
	descriptionBytes, err = b64Enc.DecodeString(payslip.GetDescription())
	assert.Equal(t, "6 Months of payslips", string(descriptionBytes))
	assert.NoError(t, err)
	assert.Equal(t, 2, payslip.Index)

	_, err = proofReqStruct.GetCriteria(3)
	assert.Error(t, err, "index out of bounds 3 elements in the array")
}

func TestCanCheckIfCredMatchesCriteria(t *testing.T) {
	b64Enc := base64.StdEncoding
	proofReqStruct := getPopulatedProofRequest()

	base64V0ContactCred := b64Enc.EncodeToString([]byte(contactUnversionedCred))
	base64PayslipCred := b64Enc.EncodeToString([]byte(paySlipCred1))

	contactHolder, _ := proofReqStruct.GetCriteria(0)
	canFulfill := contactHolder.CanFulfill(base64V0ContactCred)
	assert.False(t, canFulfill)

	canFulfill = contactHolder.CanFulfill(base64PayslipCred)
	assert.False(t, canFulfill)
}

func TestCanCheckIfV1CredMatchesCriteria(t *testing.T) {
	b64Enc := base64.StdEncoding
	proofReqStruct := getPopulatedProofRequest()
	contactHolder, _ := proofReqStruct.GetCriteria(0)

	contactCredV1, _ := canonical.Marshal(contactV1Cred)
	base64ContactCred := b64Enc.EncodeToString(contactCredV1)
	assert.True(t, contactHolder.CanFulfill(base64ContactCred))

	payslip1CredV1, _ := canonical.Marshal(paySlipV1Cred1)
	base64PayslipCred := b64Enc.EncodeToString(payslip1CredV1)
	assert.False(t, contactHolder.CanFulfill(base64PayslipCred))
}

func TestCheckIfExpiredV1CredMatchesCriteria(t *testing.T) {
	b64Enc := base64.StdEncoding
	proofReqStruct := getPopulatedProofRequest()
	contactHolder, _ := proofReqStruct.GetCriteria(0)
	expiredCred := contactV1Cred

	expTime := time.Now().Add(-30 * time.Minute).Format(time.RFC3339)
	expiredCred.ExpirationDate = expTime
	contactCredV1, _ := canonical.Marshal(expiredCred)
	base64ContactCred := b64Enc.EncodeToString(contactCredV1)
	assert.False(t, contactHolder.CanFulfill(base64ContactCred))
}

func TestCheckIfUnExpiredV1CredMatchesCriteria(t *testing.T) {
	b64Enc := base64.StdEncoding
	proofReqStruct := getPopulatedProofRequest()
	contactHolder, _ := proofReqStruct.GetCriteria(0)
	expiredCred := contactV1Cred

	expTime := time.Now().Add(30 * time.Minute).Format(time.RFC3339)
	expiredCred.ExpirationDate = expTime
	contactCredV1, _ := canonical.Marshal(expiredCred)
	base64ContactCred := b64Enc.EncodeToString(contactCredV1)
	assert.True(t, contactHolder.CanFulfill(base64ContactCred))
}

func TestAllowedExpiredCredentialCanBeSubmitted(t *testing.T) {
	b64Enc := base64.StdEncoding
	proofReqStruct := getPopulatedProofRequest()
	allowExpired := true
	proofReqStruct.SignedProofRequest.ProofRequest.Criteria[0].AllowExpired = &allowExpired
	contactHolder, _ := proofReqStruct.GetCriteria(0)
	expiredCred := contactV1Cred

	expTime := time.Now().Add(-30 * time.Minute).Format(time.RFC3339)
	expiredCred.ExpirationDate = expTime
	contactCredV1, _ := canonical.Marshal(expiredCred)
	base64ContactCred := b64Enc.EncodeToString(contactCredV1)
	assert.True(t, contactHolder.CanFulfill(base64ContactCred))
}

func TestCanCheckIfV1CredMatchesCriteriaFailsIfCriteriaPropertyIsMissingProof(t *testing.T) {
	b64Enc := base64.StdEncoding
	proofReqStruct := getPopulatedProofRequest()
	paySlipCriteriaHolder, _ := proofReqStruct.GetCriteria(2)

	payslip1CredV1, _ := json.Marshal(paySlipV1Cred1)
	base64PayslipCred := b64Enc.EncodeToString(payslip1CredV1)
	assert.True(t, paySlipCriteriaHolder.CanFulfill(base64PayslipCred))

	missingClaim := make(map[string]proof.Proof)
	for k, v := range paySlipV1Cred1.ClaimProofs {
		if k != "grossPay" {
			missingClaim[k] = v
		}
	}
	paySlipV1Cred1MissingProof := paySlipV1Cred1
	paySlipV1Cred1MissingProof.ClaimProofs = missingClaim

	payslip1CredV1MissingClaimProof, _ := canonical.Marshal(paySlipV1Cred1MissingProof)
	base64PayslipCredMissingClaimProof := b64Enc.EncodeToString(payslip1CredV1MissingClaimProof)
	assert.False(t, paySlipCriteriaHolder.CanFulfill(base64PayslipCredMissingClaimProof))

	missingSubject := make(map[string]interface{})
	for k, v := range paySlipV1Cred1.CredentialSubject {
		if k != "payPeriodStart" {
			missingSubject[k] = v
		}
	}
	paySlipV1Cred1MissingReqField := paySlipV1Cred1
	paySlipV1Cred1MissingReqField.CredentialSubject = missingSubject
	payslip1CredV1MissingValue, _ := canonical.Marshal(paySlipV1Cred1MissingReqField)
	base64PayslipCredMissingVal := b64Enc.EncodeToString(payslip1CredV1MissingValue)
	assert.False(t, paySlipCriteriaHolder.CanFulfill(base64PayslipCredMissingVal))
}

func TestCanFulfillCriteria(t *testing.T) {
	b64Enc := base64.StdEncoding
	b64EncKeyRef := b64Enc.EncodeToString([]byte("key-1"))
	proofReqStruct := getPopulatedProofRequest()

	contactHolder, _ := proofReqStruct.GetCriteria(0)
	jsonArr := "[" + contactUnversionedCred + "]"
	base64AddCreds := b64Enc.EncodeToString([]byte(jsonArr))
	b64SigningKey := b64Enc.EncodeToString(holderSigningPrivKey)

	err := proofReqStruct.FulfillCriteria(contactHolder, base64AddCreds, b64EncKeyRef, b64SigningKey)
	assert.Equal(t, credential.UnversionedCredError{}, err)
}

func TestCanFulfillCriteriaWithV1Credential(t *testing.T) {
	b64Enc := base64.StdEncoding
	b64EncKeyRef := b64Enc.EncodeToString([]byte("key-1"))
	proofReqStruct := getPopulatedProofRequest()

	addressHolder, _ := proofReqStruct.GetCriteria(1)

	addressV1MissingProperty := credential.VerifiableCredential{
		UnsignedVerifiableCredential: credential.UnsignedVerifiableCredential{},
		Proof:                        nil,
	}
	addressV1MissingProperty.UnsignedVerifiableCredential = addressV1Cred.UnsignedVerifiableCredential
	mapMissingValue := make(map[string]interface{})
	for k, v := range addressV1MissingProperty.CredentialSubject {
		if k != "postalCode" {
			mapMissingValue[k] = v
		}
	}
	addressV1MissingProperty.CredentialSubject = mapMissingValue
	addressMissingProperty, _ := canonical.Marshal(addressV1MissingProperty)

	jsonMissingProperty := "[" + string(addressMissingProperty) + "]"
	base64AddCreds := b64Enc.EncodeToString([]byte(jsonMissingProperty))
	b64SigningKey := b64Enc.EncodeToString(holderSigningPrivKey)

	err := proofReqStruct.FulfillCriteria(addressHolder, base64AddCreds, b64EncKeyRef, b64SigningKey)
	assert.Error(t, err)
	assert.Equal(t, `required property "postalCode" not found credential "422ab006-063e-48f1-91b4-dc09dc512b40"`, err.Error())

	addressV1MissingSig := credential.VerifiableCredential{
		UnsignedVerifiableCredential: credential.UnsignedVerifiableCredential{},
		Proof:                        nil,
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
	addressMissingSig, _ := canonical.Marshal(addressV1MissingSig)

	jsonMissingSig := "[" + string(addressMissingSig) + "]"
	base64AddCredsMissingSig := b64Enc.EncodeToString([]byte(jsonMissingSig))

	err = proofReqStruct.FulfillCriteria(addressHolder, base64AddCredsMissingSig, b64EncKeyRef, b64SigningKey)
	assert.Error(t, err)
	assert.Equal(t, `required property "city" did not have claim proof signature in "422ab006-063e-48f1-91b4-dc09dc512b40"`, err.Error())

}

func TestCanFulfilCriteriaWithV1CredentialFailsIfCredentialIsMissingProperties(t *testing.T) {
	b64Enc := base64.StdEncoding
	b64EncKeyRef := b64Enc.EncodeToString([]byte("key-1"))
	proofReqStruct := getPopulatedProofRequest()

	contactHolder, _ := proofReqStruct.GetCriteria(0)
	contactCredV1, _ := canonical.Marshal(contactV1Cred)
	jsonArr := "[" + string(contactCredV1) + "]"
	base64AddCreds := b64Enc.EncodeToString([]byte(jsonArr))
	b64SigningKey := b64Enc.EncodeToString(holderSigningPrivKey)

	err := proofReqStruct.FulfillCriteria(contactHolder, base64AddCreds, b64EncKeyRef, b64SigningKey)
	assert.NoError(t, err)
	assert.Len(t, proofReqStruct.ProofResponseElements, 1)
}

func TestCanGenerateProofRespString(t *testing.T) {
	b64Enc := base64.StdEncoding
	proofReqStruct := getPopulatedProofRequest()
	b64EncKeyRef := b64Enc.EncodeToString([]byte("did:work:junk#key-1"))
	b64SigningKey := b64Enc.EncodeToString(holderSigningPrivKey)

	contactHolder, _ := proofReqStruct.GetCriteria(0)
	contactJSONarr := "[" + contactUnversionedCred + "]"
	base64ContactCreds := b64Enc.EncodeToString([]byte(contactJSONarr))

	_ = proofReqStruct.FulfillCriteria(contactHolder, base64ContactCreds, b64EncKeyRef, b64SigningKey)

	addHolder, _ := proofReqStruct.GetCriteria(1)
	addJSONArr := "[" + addressCred1 + "]"
	base64AddCreds := b64Enc.EncodeToString([]byte(addJSONArr))
	_ = proofReqStruct.FulfillCriteria(addHolder, base64AddCreds, b64EncKeyRef, b64SigningKey)

	payslipHolder, _ := proofReqStruct.GetCriteria(2)
	payslipJSONArr := fmt.Sprintf("[%s,%s,%s,%s,%s,%s]", paySlipCred1, paySlipCred2, paySlipCred3, paySlipCred4, paySlipCred5, paySlipCred6)
	base64PayslipCreds := b64Enc.EncodeToString([]byte(payslipJSONArr))
	err := proofReqStruct.FulfillCriteria(payslipHolder, base64PayslipCreds, b64EncKeyRef, b64SigningKey)
	assert.Equal(t, credential.UnversionedCredError{}, err)
}

func TestCanGenerateProofRespStringWithV1Credentials(t *testing.T) {
	subjectDID := "did:work:51wzdn5u7nPp944zpDo7b2"
	b64Enc := base64.StdEncoding
	proofReqStruct := getPopulatedProofRequest()
	b64EncKeyRef := b64Enc.EncodeToString([]byte(subjectDID + "#key-1"))
	b64SigningKey := b64Enc.EncodeToString(holderSigningPrivKey)

	contactHolder, _ := proofReqStruct.GetCriteria(0)
	contactCredV1, _ := canonical.Marshal(contactV1Cred)
	contactJsonArr := "[" + string(contactCredV1) + "]"
	base64ContactCreds := b64Enc.EncodeToString([]byte(contactJsonArr))

	err := proofReqStruct.FulfillCriteria(contactHolder, base64ContactCreds, b64EncKeyRef, b64SigningKey)
	assert.NoError(t, err)
	addHolder, _ := proofReqStruct.GetCriteria(1)

	addressV1CredBytes, _ := canonical.Marshal(addressV1Cred)

	addJSONArr := "[" + string(addressV1CredBytes) + "]"
	base64AddCreds := b64Enc.EncodeToString([]byte(addJSONArr))
	err = proofReqStruct.FulfillCriteria(addHolder, base64AddCreds, b64EncKeyRef, b64SigningKey)
	assert.NoError(t, err)

	proofResponse, err := proofReqStruct.GenerateProofResponse(b64EncKeyRef, b64SigningKey)
	assert.NoError(t, err)
	proofResponseBytes, err := b64Enc.DecodeString(proofResponse)
	assert.NoError(t, err)

	var generatedProofResponse CompositeProofResponseSubmission
	err = json.Unmarshal(proofResponseBytes, &generatedProofResponse)
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
				sdid := fmt.Sprintf("%v", did)
				assert.Equal(t, sdid, subjectDID)
			}
		}
	}

	p := generatedProofResponse.Proof[0]
	suite, err := proof.SignatureSuites().GetSuiteForProof(p)
	assert.NoError(t, err)
	verifier := &proof.Ed25519Verifier{PubKey: holderPublicKey}
	assert.NoError(t, suite.Verify(&generatedProofResponse, verifier))
}

func TestHolderCanReturnDecomposedSchemaQuery(t *testing.T) {
	b64Enc := base64.StdEncoding
	versionedProofRequest := getPopulatedProofReqWithSchemaRange()

	criteriaHolder, _ := versionedProofRequest.GetCriteria(0)
	contactCredV1, _ := canonical.Marshal(contactV1Cred)
	base64ContactCred := b64Enc.EncodeToString(contactCredV1)
	assert.True(t, criteriaHolder.CanFulfill(base64ContactCred))
}

func TestHolderSchemaRangeMatchesFiltersCorrectly(t *testing.T) {
	b64Enc := base64.StdEncoding
	versionedProofRequest := getPopulatedProofReqWithSchemaRange()

	criteriaHolder, _ := versionedProofRequest.GetCriteria(0)

	contactCredV1_1dot1, _ := canonical.Marshal(contactV1Cred)
	base64ContactCred_1dot1 := b64Enc.EncodeToString(contactCredV1_1dot1)
	assert.True(t, criteriaHolder.CanFulfill(base64ContactCred_1dot1))

	contactV1CredToMod := contactV1Cred
	contactV1CredToMod.Schema.ID = "did:work:6xLyHVb7Fzdq5tcou3y3LL;id=1234-5678-5432;version=1.0"
	contactCredV1_1dot0, _ := canonical.Marshal(contactV1CredToMod)
	base64ContactCred_1dot0 := b64Enc.EncodeToString(contactCredV1_1dot0)
	assert.False(t, criteriaHolder.CanFulfill(base64ContactCred_1dot0))

	contactV1CredToMod.Schema.ID = "did:work:6xLyHVb7Fzdq5tcou3y3LL;id=1234-5678-5432;version=2.1"
	contactCredV1_2dot1, _ := canonical.Marshal(contactV1CredToMod)
	base64ContactCred_2dot1 := b64Enc.EncodeToString(contactCredV1_2dot1)
	assert.False(t, criteriaHolder.CanFulfill(base64ContactCred_2dot1))

}

func TestSchemaRangeHolderCanFulfillCriteria(t *testing.T) {
	b64Enc := base64.StdEncoding
	versionedProofRequest := getPopulatedProofReqWithSchemaRange()

	contactHolder, _ := versionedProofRequest.GetCriteria(0)

	contactCredV1, _ := canonical.Marshal(contactV1Cred)
	contactJSONarr := "[" + string(contactCredV1) + "]"
	base64ContactCreds := b64Enc.EncodeToString([]byte(contactJSONarr))

	b64EncKeyRef := b64Enc.EncodeToString([]byte("did:work:junk#key-1"))
	b64SigningKey := b64Enc.EncodeToString(holderSigningPrivKey)
	err := versionedProofRequest.FulfillCriteria(contactHolder, base64ContactCreds, b64EncKeyRef, b64SigningKey)
	assert.Nil(t, err)
}

func getPopulatedProofRequest() ProofRequestHolder {
	b64Enc := base64.StdEncoding
	proofReqStruct := &ProofRequestHolder{}
	b64ProofRequest := b64Enc.EncodeToString([]byte(proofReqChallenge))
	_ = proofReqStruct.Populate(b64ProofRequest)
	return *proofReqStruct
}

func getPopulatedProofReqWithSchemaRange() ProofRequestHolder {
	marshaled, _ := json.Marshal(ProofReaChallengeWithSchemaRange)
	b64Enc := base64.StdEncoding
	b64EncPr := b64Enc.EncodeToString(marshaled)
	versionedProofRequest := &ProofRequestHolder{}
	_ = versionedProofRequest.Populate(b64EncPr)
	return *versionedProofRequest
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
			if got := isV1Credential(tt.args.credStr); got != tt.want {
				t.Errorf("isV1Credential() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_CheckVerifierSignatureWorkEd25519(t *testing.T) {
	// Create a Verifier DIDDoc
	verifierDIDDoc, privKey := did.GenerateDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	ledgerDIDDoc := &ledger.DIDDoc{
		Metadata: &ledger.Metadata{
			ID: verifierDIDDoc.ID,
		},
		DIDDoc: verifierDIDDoc,
	}
	verifierDIDDocBytes, err := canonical.Marshal(ledgerDIDDoc)
	assert.NoError(t, err)
	verifierDIDDocB64Encoded := base64.StdEncoding.EncodeToString(verifierDIDDocBytes)

	// Get test Proof Request and set Verifier
	testProofRequestHolder := getPopulatedProofRequest()
	unsigned := testProofRequestHolder.SignedProofRequest.UnsignedCompositeProofRequestInstanceChallenge
	unsigned.ProofRequest.Verifier = verifierDIDDoc.ID

	// Create proof over Proof Request
	signingKeyRef := did.GenerateKeyID(verifierDIDDoc.ID, did.InitialKey)
	signer, err := proof.NewEd25519Signer(privKey, signingKeyRef)
	assert.NoError(t, err)

	suite, err := proof.SignatureSuites().GetSuite(proof.JCSEdSignatureType, proof.V2)
	assert.NoError(t, err)

	signed := CompositeProofRequestInstanceChallenge{
		UnsignedCompositeProofRequestInstanceChallenge: unsigned,
	}
	err = suite.Sign(&signed, signer)
	assert.NoError(t, err)

	holder := &ProofRequestHolder{
		SignedProofRequest:    signed,
		ProofResponseElements: testProofRequestHolder.ProofResponseElements,
	}

	// Verify
	err = holder.CheckVerifierSignature(verifierDIDDocB64Encoded)
	assert.NoError(t, err)
}

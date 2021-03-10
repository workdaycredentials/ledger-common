package request

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.wday.io/credentials-open-source/ledger-common/credential"
	"go.wday.io/credentials-open-source/ledger-common/credential/presentation"
	"go.wday.io/credentials-open-source/ledger-common/did"
	"go.wday.io/credentials-open-source/ledger-common/ledger"
	"go.wday.io/credentials-open-source/ledger-common/proof"
	"go.wday.io/credentials-open-source/ledger-common/util"
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
		ProofRequest: challenge,
	}
	verifierIdentity := proofReqStruct.GetVerifierIdentity()
	expectedID := did.DID("did:work:28RB9jAy9HtVet3zFhdWaM")
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
	proofReqStruct.ProofRequest.ProofRequest.Criteria[0].AllowExpired = &allowExpired
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
	addressV1MissingProperty := addressV1Cred
	mapMissingValue := make(map[string]interface{})
	for k, v := range addressV1MissingProperty.CredentialSubject {
		if k != "postalCode" {
			mapMissingValue[k] = v
		}
	}
	addressV1MissingProperty.CredentialSubject = mapMissingValue
	rawCredential, err := credential.AsRawCredential(addressV1MissingProperty)
	assert.NoError(t, err)

	addressHolder, _ := proofReqStruct.GetCriteria(1)
	err = proofReqStruct.FulfillCriteria(addressHolder, []credential.RawCredential{*rawCredential}, "key-1", holderSigningPrivKey)
	assert.Error(t, err)
	assert.Equal(t, `required property "postalCode" not found credential "422ab006-063e-48f1-91b4-dc09dc512b40"`, err.Error())

	addressV1MissingSig := addressV1Cred
	addressV1MissingSig.Proof = addressV1Cred.Proof
	mapMissingSigValue := make(map[string]proof.Proof)
	for k, v := range addressV1MissingSig.ClaimProofs {
		if k != "city" {
			mapMissingSigValue[k] = v
		}
	}
	addressV1MissingSig.ClaimProofs = mapMissingSigValue
	rawCredential, err = credential.AsRawCredential(addressV1MissingSig)
	assert.NoError(t, err)
	err = proofReqStruct.FulfillCriteria(addressHolder, []credential.RawCredential{*rawCredential}, "key-1", holderSigningPrivKey)
	assert.Error(t, err)
	assert.Equal(t, `required property "city" did not have claim proof signature in "422ab006-063e-48f1-91b4-dc09dc512b40"`, err.Error())
}

func TestCanFulfilCriteriaWithV1CredentialFailsIfCredentialIsMissingProperties(t *testing.T) {
	proofReqStruct := getPopulatedProofRequest()
	rawCredential, err := credential.AsRawCredential(contactV1Cred)
	assert.NoError(t, err)
	contactHolder, _ := proofReqStruct.GetCriteria(0)
	err = proofReqStruct.FulfillCriteria(contactHolder, []credential.RawCredential{*rawCredential}, "key-1", holderSigningPrivKey)
	assert.NoError(t, err)
	assert.Len(t, proofReqStruct.ProofResponseElements, 1)
}

func TestCanGenerateProofRespString(t *testing.T) {
	proofReqStruct := getPopulatedProofRequest()
	var contactCred credential.VerifiableCredential
	err := json.Unmarshal([]byte(contactUnversionedCred), &contactCred)
	assert.NoError(t, err)

	rawCredential, err := credential.AsRawCredential(contactCred)
	assert.NoError(t, err)

	contactHolder, _ := proofReqStruct.GetCriteria(0)
	_ = proofReqStruct.FulfillCriteria(contactHolder, []credential.RawCredential{*rawCredential}, "did:work:junk#key-1", holderSigningPrivKey)

	addHolder, _ := proofReqStruct.GetCriteria(1)
	var addressCred credential.VerifiableCredential
	err = json.Unmarshal([]byte(addressCred1), &addressCred)
	rawCredential, err = credential.AsRawCredential(addressCred)
	assert.NoError(t, err)
	_ = proofReqStruct.FulfillCriteria(addHolder, []credential.RawCredential{*rawCredential}, "did:work:junk#key-1", holderSigningPrivKey)
}

func TestCanGenerateProofRespStringWithV1Credentials(t *testing.T) {
	subjectDID := did.DID("did:work:51wzdn5u7nPp944zpDo7b2")
	proofReqStruct := getPopulatedProofRequest()
	keyRef := did.GenerateKeyID(subjectDID, did.InitialKey)

	rawCredential, err := credential.AsRawCredential(contactV1Cred)
	assert.NoError(t, err)

	contactHolder, _ := proofReqStruct.GetCriteria(0)
	err = proofReqStruct.FulfillCriteria(contactHolder, []credential.RawCredential{*rawCredential}, keyRef, holderSigningPrivKey)
	assert.NoError(t, err)
	addHolder, _ := proofReqStruct.GetCriteria(1)

	rawCredential, err = credential.AsRawCredential(addressV1Cred)
	assert.NoError(t, err)

	err = proofReqStruct.FulfillCriteria(addHolder, []credential.RawCredential{*rawCredential}, keyRef, holderSigningPrivKey)
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
				assert.Equal(t, did, subjectDID.String())
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

	rawCredential, err := credential.AsRawCredential(contactV1Cred)
	assert.NoError(t, err)

	contactHolder, _ := versionedProofRequest.GetCriteria(0)
	err = versionedProofRequest.FulfillCriteria(contactHolder, []credential.RawCredential{*rawCredential}, "did:work:junk#key-1", holderSigningPrivKey)
	assert.NoError(t, err)
}

func getPopulatedProofRequest() ProofRequestHolder {
	var challenge presentation.CompositeProofRequestInstanceChallenge
	_ = json.Unmarshal([]byte(proofReqChallenge), &challenge)
	return ProofRequestHolder{ProofRequest: challenge}
}

func getPopulatedProofReqWithSchemaRange() ProofRequestHolder {
	return ProofRequestHolder{ProofRequest: proofReqChallengeWithSchemaRange}
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

func Test_CheckVerifierSignature(t *testing.T) {
	// Create a Verifier DIDDoc
	signatureType := proof.JCSEdSignatureType
	verifierDIDDoc, privKey := did.GenerateDIDDoc(proof.Ed25519KeyType, signatureType)
	ledgerDIDDoc := &ledger.DIDDoc{
		Metadata: &ledger.Metadata{
			ID: verifierDIDDoc.ID.String(),
		},
		DIDDoc: verifierDIDDoc,
	}

	// Get test Proof Request and set Verifier
	testProofRequestHolder := getPopulatedProofRequest()
	request := testProofRequestHolder.ProofRequest
	request.ProofRequest.Verifier = verifierDIDDoc.ID
	request.SetProof(nil)

	// Create proof over Proof Request
	signingKeyRef := did.GenerateKeyID(verifierDIDDoc.ID, did.InitialKey)
	signer, err := proof.NewEd25519Signer(privKey, signingKeyRef)
	assert.NoError(t, err)

	suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	assert.NoError(t, err)

	options := &proof.ProofOptions{ProofPurpose: proof.AssertionMethodPurpose}
	err = suite.Sign(&request, signer, options)
	assert.NoError(t, err)

	holder := &ProofRequestHolder{
		ProofRequest:          request,
		ProofResponseElements: testProofRequestHolder.ProofResponseElements,
	}

	// Verify
	err = holder.CheckVerifierSignature(*ledgerDIDDoc)
	assert.NoError(t, err)
}

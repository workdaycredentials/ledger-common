package presentation

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

func TestCreationOfPresentationFromBase64EncodedCredential(t *testing.T) {
	b64Cred := base64.StdEncoding.EncodeToString([]byte(signedV0Credential))
	b64KeyRefrence := base64.StdEncoding.EncodeToString([]byte("b64Id:work:PDNabnJyLVCpevvaGrk1LP#key-1"))
	b64SigningKey := base64.StdEncoding.EncodeToString(holderSigningPrivKey)
	uid := uuid.New().String()
	b64Id := base64.StdEncoding.EncodeToString([]byte(uid))

	_, err := GenerateProof(b64Cred, b64KeyRefrence, b64SigningKey, b64Id)
	assert.Equal(t, credential.UnversionedCredError{}, err)
}

func TestCreationOfPresentationFromCredentialV1(t *testing.T) {
	id := uuid.New().String()
	nowUTC := time.Now().UTC()
	signer, err := proof.NewEd25519Signer(holderSigningPrivKey, "id:work:PDNabnJyLVCpevvaGrk1LP#key-1")
	assert.NoError(t, err)

	presentation, err := GeneratePresentationFromVC(signedV1CredentialOldType.UnsignedVerifiableCredential, signer, proof.WorkEdSignatureType, id)
	assert.NoError(t, err)
	verifyPresentationV1Cred(t, *presentation, id, nowUTC.Format(time.RFC3339))

	presentation, err = GeneratePresentationFromVC(signedV1Credential.UnsignedVerifiableCredential, signer, proof.WorkEdSignatureType, id)
	assert.NoError(t, err)
	verifyPresentationV1Cred(t, *presentation, id, nowUTC.Format(time.RFC3339))
}

func verifyPresentationV1Cred(t *testing.T, presentation Presentation, id string, startTimeRFC3339 string) {
	assert.NotNil(t, presentation)
	assert.Equal(t, id, presentation.ID)
	assert.Equal(t, []string{CredentialsLDContext}, presentation.Context)
	assert.Equal(t, []string{LDType, util.ProofResponseTypeReference_v1_0}, presentation.Type)
	startTime, _ := time.Parse(time.RFC3339, startTimeRFC3339)
	presentationTime, _ := time.Parse(time.RFC3339, presentation.Created)
	now := time.Now().UTC()
	assert.True(t, presentationTime.After(startTime) || presentationTime.Equal(startTime))
	assert.True(t, presentationTime.Before(now))

	// verify
	verifier := &proof.Ed25519Verifier{PubKey: holderPublicKey}
	suite, err := proof.SignatureSuites().GetSuiteForProof(presentation.GetProof())
	assert.NoError(t, err)
	assert.NoError(t, suite.Verify(&presentation, verifier))

	assert.Len(t, presentation.Credentials, 1)
	v1NameCred := presentation.Credentials[0].UnsignedVerifiableCredential

	assert.Equal(t, util.Version_1_0, v1NameCred.ModelVersion)
	assert.Equal(t, "422ab006-063e-48f1-91b4-dc09dc512b40", v1NameCred.ID)
	assert.Equal(t, []string{"VerifiableCredential"}, v1NameCred.Type)
	assert.Equal(t, "did:work:BkwQ3sgRjpxZt4GhdMwkDu", v1NameCred.Issuer)
	assert.Equal(t, "2019-01-21T17:49:18Z", v1NameCred.IssuanceDate)

	subjects := v1NameCred.CredentialSubject
	assert.Len(t, subjects, 3)
	assert.Equal(t, "Homer", subjects["firstName"])
	assert.Equal(t, "Jay", subjects["middleName"])
	assert.Equal(t, "Simpson", subjects["lastName"])

	assert.Len(t, v1NameCred.ClaimProofs, 3)
	for k, claimProof := range v1NameCred.ClaimProofs {
		switch k {
		case "firstname":
			assert.True(t, proof.Ed25519SignatureType == claimProof.Type || proof.WorkEdSignatureType == claimProof.Type)
			assert.Equal(t, "2019-01-21T17:49:18Z", claimProof.Created)
			assert.Equal(t, "did:work:QXpMNbNrhjBUPVFbUQTMiu#key-1", claimProof.VerificationMethod)
			assert.Equal(t, "Junk1pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k", claimProof.SignatureValue)
		case "middleName":
			assert.True(t, proof.Ed25519SignatureType == claimProof.Type || proof.WorkEdSignatureType == claimProof.Type)
			assert.Equal(t, "2019-01-21T17:49:18Z", claimProof.Created)
			assert.Equal(t, "did:work:QXpMNbNrhjBUPVFbUQTMiu#key-1", claimProof.VerificationMethod)
			assert.Equal(t, "Junk251krWrSy7ZpN8NHLLoePCKT5sw3aaPX44mdGY3W5SYMWmg8tf5U388eoe7vQ9mbbhYbNZhDKYp28itPtMrc", claimProof.SignatureValue)
		case "lastName":
			assert.True(t, proof.Ed25519SignatureType == claimProof.Type || proof.WorkEdSignatureType == claimProof.Type)
			assert.Equal(t, "2019-01-21T17:49:18Z", claimProof.Created)
			assert.Equal(t, "did:work:QXpMNbNrhjBUPVFbUQTMiu#key-1", claimProof.VerificationMethod)
			assert.Equal(t, "Junk3wDXjymFDduMJtJVTYWQ5qEz4HhVTjWT9WmEj9wabK1PHwhdRaNqUrD91VADWCBikQPVfH4aVkWRrM", claimProof.SignatureValue)
		}
	}
}

var (
	keySeed              = []byte("12345678901234567890123456789012")
	holderSigningPrivKey = ed25519.NewKeyFromSeed(keySeed)
	holderPublicKey      = holderSigningPrivKey.Public().(ed25519.PublicKey)
	signedV0Credential   = `{
    "@context": [
        "https://w3.org/2018/credentials/v1",
        "https://w3id.org/credef/v1"
    ],
    "id": "130c46e5-a57e-4cc3-b6d6-a444d392ee84",
    "type": [
        "VerifiableCredential"
    ],
    "issuerDid": "did:work:BkwQ3sgRjpxZt4GhdMwkDu",
    "schemaId": "did:work:GZcQwzZ9hWXChF9N2G2HXP",
    "issuanceDate": "2019-01-21T17:49:18Z",
    "credentialSubjects": [
        {
            "id": "did:work:XJnjTVG2zvRZfPicnnx7tn",
            "key": "firstName",
            "value": "Homer",
            "proof": [
                {
                    "created": "2019-01-21T17:49:18Z",
                    "creator": "did:work:QXpMNbNrhjBUPVFbUQTMiu#key-1",
                    "nonce": "0dff3bf3-0aac-4b23-af1b-6c477e0c6725",
                    "signatureValue": "2oEw3pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k",
                    "type": "Ed25519VerificationKey2018"
                }
            ]
        },
        {
            "id": "did:work:XJnjTVG2zvRZfPicnnx7tn",
            "key": "middleName",
            "value": "Jay",
            "proof": [
                {
                    "created": "2019-01-21T17:49:18Z",
                    "creator": "did:work:QXpMNbNrhjBUPVFbUQTMiu#key-1",
                    "nonce": "81dc9e6d-704e-4a4e-b21f-687ce8eaaa88",
                    "signatureValue": "3whzw51krWrSy7ZpN8NHLLoePCKT5sw3aaPX44mdGY3W5SYMWmg8tf5U388eoe7vQ9mbbhYbNZhDKYp28itPtMrc",
                    "type": "Ed25519VerificationKey2018"
                }
            ]
        },
        {
            "id": "did:work:XJnjTVG2zvRZfPicnnx7tn",
            "key": "lastName",
            "value": "Simpson",
            "proof": [
                {
                    "created": "2019-01-21T17:49:18Z",
                    "creator": "did:work:QXpMNbNrhjBUPVFbUQTMiu#key-1",
                    "nonce": "02d9b01d-19dd-4ccb-b1c5-04e0409e6fe4",
                    "signatureValue": "2gurFu8jwdwDXjymFDduMJtJVTYWQ5qEz4HhVTjWT9WmEj9wabK1PHwhdRaNqUrD91VADWCBikQPVfH4aVkWRrM",
                    "type": "Ed25519VerificationKey2018"
                }
            ]
        }
    ]
}`

	signedV1CredentialOldType = credential.VerifiableCredential{
		UnsignedVerifiableCredential: credential.UnsignedVerifiableCredential{
			Metadata: credential.Metadata{
				ModelVersion: util.Version_1_0,
				Context:      []string{"https://www.w3.org/2018/credentials/v1"},
				ID:           "422ab006-063e-48f1-91b4-dc09dc512b40",
				Type:         []string{"VerifiableCredential"},
				Issuer:       "did:work:BkwQ3sgRjpxZt4GhdMwkDu",
				IssuanceDate: "2019-01-21T17:49:18Z",
				Schema: credential.Schema{
					ID:   "did:work:GZcQwzZ9hWXChF9N2G2HXP;id=112f1a23ce1747b199265dfcc235049b;version=1.0",
					Type: "NameSchema?",
				},
			},
			CredentialSubject: map[string]interface{}{"firstName": "Homer", "middleName": "Jay", "lastName": "Simpson"},
			ClaimProofs: map[string]proof.Proof{
				"firstName": {
					Type:               "Ed25519VerificationKey2018",
					Created:            "2019-01-21T17:49:18Z",
					VerificationMethod: "did:work:QXpMNbNrhjBUPVFbUQTMiu#key-1",
					Nonce:              "badnonce",
					SignatureValue:     "Junk1pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k",
				},
				"middleName": {
					Type:               "Ed25519VerificationKey2018",
					Created:            "2019-01-21T17:49:18Z",
					VerificationMethod: "did:work:QXpMNbNrhjBUPVFbUQTMiu#key-1",
					Nonce:              "badnonce",
					SignatureValue:     "Junk251krWrSy7ZpN8NHLLoePCKT5sw3aaPX44mdGY3W5SYMWmg8tf5U388eoe7vQ9mbbhYbNZhDKYp28itPtMrc",
				},
				"lastName": {
					Type:               "Ed25519VerificationKey2018",
					Created:            "2019-01-21T17:49:18Z",
					VerificationMethod: "did:work:QXpMNbNrhjBUPVFbUQTMiu#key-1",
					Nonce:              "badnonce",
					SignatureValue:     "Junk3wDXjymFDduMJtJVTYWQ5qEz4HhVTjWT9WmEj9wabK1PHwhdRaNqUrD91VADWCBikQPVfH4aVkWRrM",
				},
			},
		},
		Proof: &proof.Proof{
			Type:               "Ed25519VerificationKey2018",
			Created:            "2019-01-21T17:49:18Z",
			VerificationMethod: "did:work:QXpMNbNrhjBUPVFbUQTMiu#key-1",
			SignatureValue:     "Junk4u8jwdwDXjymFDduMJtJVTYWQ5qEz4HhVTjWT9WmEj9wabK1PHwhdRaNqUrD91VADWCBikQPVfH4aVkWRrM",
		},
	}

	signedV1Credential = credential.VerifiableCredential{
		UnsignedVerifiableCredential: credential.UnsignedVerifiableCredential{
			Metadata: credential.Metadata{
				ModelVersion: util.Version_1_0,
				Context:      []string{"https://www.w3.org/2018/credentials/v1"},
				ID:           "422ab006-063e-48f1-91b4-dc09dc512b40",
				Type:         []string{"VerifiableCredential"},
				Issuer:       "did:work:BkwQ3sgRjpxZt4GhdMwkDu",
				IssuanceDate: "2019-01-21T17:49:18Z",
				Schema: credential.Schema{
					ID:   "did:work:GZcQwzZ9hWXChF9N2G2HXP;id=112f1a23ce1747b199265dfcc235049b;version=1.0",
					Type: "NameSchema?",
				},
			},
			CredentialSubject: map[string]interface{}{"firstName": "Homer", "middleName": "Jay", "lastName": "Simpson"},
			ClaimProofs: map[string]proof.Proof{
				"firstName": {
					Type:               "WorkEd25519Signature2020",
					Created:            "2019-01-21T17:49:18Z",
					VerificationMethod: "did:work:QXpMNbNrhjBUPVFbUQTMiu#key-1",
					Nonce:              "badnonce",
					SignatureValue:     "Junk1pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k",
				},
				"middleName": {
					Type:               "WorkEd25519Signature2020",
					Created:            "2019-01-21T17:49:18Z",
					VerificationMethod: "did:work:QXpMNbNrhjBUPVFbUQTMiu#key-1",
					Nonce:              "badnonce",
					SignatureValue:     "Junk251krWrSy7ZpN8NHLLoePCKT5sw3aaPX44mdGY3W5SYMWmg8tf5U388eoe7vQ9mbbhYbNZhDKYp28itPtMrc",
				},
				"lastName": {
					Type:               "WorkEd25519Signature2020",
					Created:            "2019-01-21T17:49:18Z",
					VerificationMethod: "did:work:QXpMNbNrhjBUPVFbUQTMiu#key-1",
					Nonce:              "badnonce",
					SignatureValue:     "Junk3wDXjymFDduMJtJVTYWQ5qEz4HhVTjWT9WmEj9wabK1PHwhdRaNqUrD91VADWCBikQPVfH4aVkWRrM",
				},
			},
		},
		Proof: &proof.Proof{
			Type:               "WorkEd25519Signature2020",
			Created:            "2019-01-21T17:49:18Z",
			VerificationMethod: "did:work:QXpMNbNrhjBUPVFbUQTMiu#key-1",
			SignatureValue:     "Junk4u8jwdwDXjymFDduMJtJVTYWQ5qEz4HhVTjWT9WmEj9wabK1PHwhdRaNqUrD91VADWCBikQPVfH4aVkWRrM",
		},
	}
)

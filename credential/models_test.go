package credential

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	jcs "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/util"
)

func TestEncodeAttributeClaimDataForSigning(t *testing.T) {
	const (
		expectedEncoding           = `eyJtb2RlbFZlcnNpb24iOiIxLjAiLCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6IjllZjFiNjRmLTJmNzktNDFmOC1iZTk3LWE4MzEyNjQ4NDJmNiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiYTE2ODQyMTEtODUzNy00MTJlLWI2ZjUtNzBhMTVkYzZiNmMzIiwiaXNzdWFuY2VEYXRlIjoiMjAxOS0wOS0yMVQwMToxMjoyMloiLCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiY2FlOGEzYmQtZWU4Ni00ZjQ5LTk5ZDYtMGNiYmVlMDc3ZmNjIiwidHlwZSI6Ikpzb25TY2hlbWFWYWxpZGF0b3JXb3JrZGF5MjAxOSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJwZXQiOiJmaWRvIn19`
		expectedCanonicalEndcoding = `eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiY2FlOGEzYmQtZWU4Ni00ZjQ5LTk5ZDYtMGNiYmVlMDc3ZmNjIiwidHlwZSI6Ikpzb25TY2hlbWFWYWxpZGF0b3JXb3JrZGF5MjAxOSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJwZXQiOiJmaWRvIn0sImlkIjoiOWVmMWI2NGYtMmY3OS00MWY4LWJlOTctYTgzMTI2NDg0MmY2IiwiaXNzdWFuY2VEYXRlIjoiMjAxOS0wOS0yMVQwMToxMjoyMloiLCJpc3N1ZXIiOiJhMTY4NDIxMS04NTM3LTQxMmUtYjZmNS03MGExNWRjNmI2YzMiLCJtb2RlbFZlcnNpb24iOiIxLjAiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl19`
	)

	metadata := Metadata{
		ModelVersion: ModelVersionV1,
		Context:      []string{W3Context},
		ID:           "9ef1b64f-2f79-41f8-be97-a831264842f6",
		Type:         []string{"VerifiableCredential"},
		Issuer:       "a1684211-8537-412e-b6f5-70a15dc6b6c3",
		IssuanceDate: "2019-09-21T01:12:22Z",
		Schema: Schema{
			ID:   "cae8a3bd-ee86-4f49-99d6-0cbbee077fcc",
			Type: "JsonSchemaValidatorWorkday2019",
		},
	}

	encoding, err := EncodeAttributeClaimDataForSigningOption(metadata, "pet", "fido", false)
	require.NoError(t, err)
	assert.Equal(t, expectedEncoding, string(encoding))

	canonicalEncoding, err := EncodeAttributeClaimDataForSigningOption(metadata, "pet", "fido", true)
	require.NoError(t, err)
	assert.Equal(t, expectedCanonicalEndcoding, string(canonicalEncoding))
}

func TestNewMetadataWithTimestamp(t *testing.T) {
	type args struct {
		id                string
		issuer            string
		schema            string
		baseRevocationURL did.URI
		offeredTimestamp  time.Time
	}
	baseRevocationURL := "https://testrevocationservice.com/"
	knownStamp, err := time.Parse(time.RFC3339, "2020-04-29T14:49:25.77922629Z")
	assert.NoError(t, err)
	tests := []struct {
		name string
		args args
		want Metadata
	}{
		{
			name: "Valid",
			args: args{
				id:                "id1",
				issuer:            "issuer1",
				schema:            "schema1",
				baseRevocationURL: baseRevocationURL,
				offeredTimestamp:  knownStamp,
			},
			want: Metadata{
				ModelVersion: ModelVersionV1,
				Context:      []string{W3Context},
				ID:           "id1",
				Type:         []string{Type, util.CredentialTypeReference_v1_0},
				Issuer:       "issuer1",
				IssuanceDate: knownStamp.Format(time.RFC3339),
				Schema: Schema{
					ID:   "schema1",
					Type: SchemaType,
				},
				CredentialStatus: &CredentialStatus{
					ID:   credentialbaseRevocationURL(baseRevocationURL, "issuer1", "id1"),
					Type: RevocationType,
				},
				// NonTransferable: true,
			},
		},
		{
			name: "No revocation",
			args: args{
				id:               "id2",
				issuer:           "issuer2",
				schema:           "schema2",
				offeredTimestamp: knownStamp,
			},
			want: Metadata{
				ModelVersion: ModelVersionV1,
				Context:      []string{W3Context},
				ID:           "id2",
				Type:         []string{Type, util.CredentialTypeReference_v1_0},
				Issuer:       "issuer2",
				IssuanceDate: knownStamp.Format(time.RFC3339),
				Schema: Schema{
					ID:   "schema2",
					Type: SchemaType,
				},
				// NonTransferable: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewMetadataWithTimestamp(tt.args.id, did.DID(tt.args.issuer), tt.args.schema, tt.args.baseRevocationURL, tt.args.offeredTimestamp)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewMetadataWithTimestamp() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// This credential has an `extra` property that is outside of the defined credential model.
const credJSONWithExtra = `
	{
	  "modelVersion": "1.0",
	  "@context": [
	    "https://www.w3.org/2018/credentials/v1"
	  ],
	  "id": "3580d416-3c80-4081-adca-37b3e7181aaa",
	  "type": [
	    "VerifiableCredential",
	    "https://credentials.workday.com/docs/specification/v1.0/credential.json"
	  ],
	  "issuer": "9e62edf0-de1a-4795-b1f9-ea3b55f13a04",
	  "issuanceDate": "2020-11-18T22:55:06-08:00",
	  "credentialSchema": {
	    "id": "4e8a5ae9-df9e-44b2-8b94-0aac850822ef",
	    "type": "JsonSchemaValidatorWorkday2019"
	  },
	  "expirationDate": "2020-11-18T22:55:16-08:00",
	  "credentialStatus": {
	    "id": "https://testrevocationservice.com//A8TtEREjsbFiNUCEMZYkuRTairY99vcbLmeEkBvMt7bh",
	    "type": "WorkdayRevocation2020"
	  },
	  "nonTransferable": true,
	  "credentialSubject": {
	    "Apple": "Pie",
	    "Banana": "Custard",
	    "Cherry": "Jubilee",
	    "Fig": "Pudding",
	    "Gooseberry": "Fool",
	    "id": "0a12b238-a908-4097-ade5-567c5eccd873"
	  },
	  "claimProofs": {
	    "Apple": {
	      "created": "2020-11-19T06:55:06Z",
	      "proofPurpose": "assertionMethod",
	      "verificationMethod": "9e62edf0-de1a-4795-b1f9-ea3b55f13a04#key-1",
	      "nonce": "1e7bb904-813a-49d1-8aa8-1cf6a386f474",
	      "signatureValue": "4uEJeVqpzy9RHJ2APTwxnRyLGqGPMvgkkaXBjCBpTRQg9ALGNbSeKADWyb7sHLm4JhfpdGnzcsEb5UPsaY3k8tCS",
	      "type": "JcsEd25519Signature2020"
	    },
	    "Banana": {
	      "created": "2020-11-19T06:55:06Z",
	      "proofPurpose": "assertionMethod",
	      "verificationMethod": "9e62edf0-de1a-4795-b1f9-ea3b55f13a04#key-1",
	      "nonce": "1e7bb904-813a-49d1-8aa8-1cf6a386f474",
	      "signatureValue": "4436ZSNwv7NJdHRLQepa5zJrxp3XWPBaqdtNgwmQmMYEcRRd3qwidU5DvhV8Ean95idWj7nR62fkPmahWjdSNUkk",
	      "type": "JcsEd25519Signature2020"
	    },
	    "Cherry": {
	      "created": "2020-11-19T06:55:06Z",
	      "proofPurpose": "assertionMethod",
	      "verificationMethod": "9e62edf0-de1a-4795-b1f9-ea3b55f13a04#key-1",
	      "nonce": "1e7bb904-813a-49d1-8aa8-1cf6a386f474",
	      "signatureValue": "6uvz56NjLxyghTSmy9wwRahgYEohbdzAYAqdKVaGA5P4xPSATGaDVt8xZBdhqjGMt2NA3KGQF2MAMya3tndvHLD",
	      "type": "JcsEd25519Signature2020"
	    },
	    "Fig": {
	      "created": "2020-11-19T06:55:06Z",
	      "proofPurpose": "assertionMethod",
	      "verificationMethod": "9e62edf0-de1a-4795-b1f9-ea3b55f13a04#key-1",
	      "nonce": "1e7bb904-813a-49d1-8aa8-1cf6a386f474",
	      "signatureValue": "3ubSiML5GL6odFKsKWD9HKaztdUD5C5ZQwwA5LHG61RCLSHdddJhazjremnnyTLT1FPcEpquyqeMSgP9rHokx4Jt",
	      "type": "JcsEd25519Signature2020"
	    },
	    "Gooseberry": {
	      "created": "2020-11-19T06:55:06Z",
	      "proofPurpose": "assertionMethod",
	      "verificationMethod": "9e62edf0-de1a-4795-b1f9-ea3b55f13a04#key-1",
	      "nonce": "1e7bb904-813a-49d1-8aa8-1cf6a386f474",
	      "signatureValue": "5SiiH7EaqVNhkU8ghC8nkEgpSJRfvvzWde9MQaMh7tGNzCBvn1J6Nr2g1kfmBMb1s88TbjqaM4yr8omobEDLkzBS",
	      "type": "JcsEd25519Signature2020"
	    },
	    "id": {
	      "created": "2020-11-19T06:55:06Z",
	      "proofPurpose": "assertionMethod",
	      "verificationMethod": "9e62edf0-de1a-4795-b1f9-ea3b55f13a04#key-1",
	      "nonce": "1e7bb904-813a-49d1-8aa8-1cf6a386f474",
	      "signatureValue": "4sbg7EqYjngEBHq3qaYq8jeULYfWPPNrSfeF9AQ73iByZ2qPVJV5B7cWVtfFcg54CJRsmh1R7mPuDyUditdpTS4Q",
	      "type": "JcsEd25519Signature2020"
	    }
	  },
	  "extra": "An extra property that doesn't fit the VerifiableCredential model'"
	}`

func TestAsRawCredential(t *testing.T) {
	var cred VerifiableCredential
	assert.NoError(t, json.Unmarshal([]byte(credJSONWithExtra), &cred))

	raw, err := AsRawCredential(cred)
	assert.NoError(t, err)
	assert.Equal(t, cred, raw.VerifiableCredential)

	expected, err := json.Marshal(cred)
	assert.NoError(t, err)
	assert.Equal(t, expected, raw.Raw)

	cred.CredentialSubject["diff"] = "delta"
	assert.NotEqual(t, cred, raw.VerifiableCredential, "changing original cred shouldn't change raw cred")
}

func TestRawCredential_Filter(t *testing.T) {
	var cred VerifiableCredential
	err := json.Unmarshal([]byte(credJSONWithExtra), &cred)
	assert.NoError(t, err)

	rawCredential := RawCredential{
		VerifiableCredential: cred,
		Raw:                  []byte(credJSONWithExtra),
	}

	t.Run("Marshalled RawCredential matches original JSON", func(t *testing.T) {
		rawJSON, err := json.Marshal(rawCredential)
		assert.NoError(t, err)
		assertJSONEquals(t, []byte(credJSONWithExtra), rawJSON)
	})

	t.Run("Filtered RawCredential includes `extra` property", func(t *testing.T) {
		expectedJSON := `
		{
		  "modelVersion": "1.0",
		  "@context": [
		    "https://www.w3.org/2018/credentials/v1"
		  ],
		  "id": "3580d416-3c80-4081-adca-37b3e7181aaa",
		  "type": [
		    "VerifiableCredential",
		    "https://credentials.workday.com/docs/specification/v1.0/credential.json"
		  ],
		  "issuer": "9e62edf0-de1a-4795-b1f9-ea3b55f13a04",
		  "issuanceDate": "2020-11-18T22:55:06-08:00",
		  "credentialSchema": {
		    "id": "4e8a5ae9-df9e-44b2-8b94-0aac850822ef",
		    "type": "JsonSchemaValidatorWorkday2019"
		  },
		  "expirationDate": "2020-11-18T22:55:16-08:00",
		  "credentialStatus": {
		    "id": "https://testrevocationservice.com//A8TtEREjsbFiNUCEMZYkuRTairY99vcbLmeEkBvMt7bh",
		    "type": "WorkdayRevocation2020"
		  },
		  "nonTransferable": true,
		  "credentialSubject": {
		    "Banana": "Custard",
		    "Fig": "Pudding",
		    "id": "0a12b238-a908-4097-ade5-567c5eccd873"
		  },
		  "claimProofs": {
		    "Banana": {
			      "created": "2020-11-19T06:55:06Z",
			      "proofPurpose": "assertionMethod",
		      "verificationMethod": "9e62edf0-de1a-4795-b1f9-ea3b55f13a04#key-1",
		      "nonce": "1e7bb904-813a-49d1-8aa8-1cf6a386f474",
		      "signatureValue": "4436ZSNwv7NJdHRLQepa5zJrxp3XWPBaqdtNgwmQmMYEcRRd3qwidU5DvhV8Ean95idWj7nR62fkPmahWjdSNUkk",
		      "type": "JcsEd25519Signature2020"
		    },
		    "Fig": {
		      "created": "2020-11-19T06:55:06Z",
		      "proofPurpose": "assertionMethod",
		      "verificationMethod": "9e62edf0-de1a-4795-b1f9-ea3b55f13a04#key-1",
		      "nonce": "1e7bb904-813a-49d1-8aa8-1cf6a386f474",
		      "signatureValue": "3ubSiML5GL6odFKsKWD9HKaztdUD5C5ZQwwA5LHG61RCLSHdddJhazjremnnyTLT1FPcEpquyqeMSgP9rHokx4Jt",
		      "type": "JcsEd25519Signature2020"
		    },
		    "id": {
		      "created": "2020-11-19T06:55:06Z",
		      "proofPurpose": "assertionMethod",
		      "verificationMethod": "9e62edf0-de1a-4795-b1f9-ea3b55f13a04#key-1",
		      "nonce": "1e7bb904-813a-49d1-8aa8-1cf6a386f474",
		      "signatureValue": "4sbg7EqYjngEBHq3qaYq8jeULYfWPPNrSfeF9AQ73iByZ2qPVJV5B7cWVtfFcg54CJRsmh1R7mPuDyUditdpTS4Q",
		      "type": "JcsEd25519Signature2020"
		    }
		  },
		  "extra": "An extra property that doesn't fit the VerifiableCredential model'"
		}`

		// Filter the RawCredential to hold a subset of the claims.
		filtered, err := rawCredential.Filter(asSet("id", "Banana", "Fig"))
		assert.NoError(t, err)

		for _, attr := range []string{"id", "Banana", "Fig"} {
			assert.Contains(t, filtered.CredentialSubject, attr)
			assert.Contains(t, filtered.ClaimProofs, attr)
		}
		for _, attr := range []string{"Apple", "Cherry", "Gooseberry"} {
			assert.NotContains(t, filtered.CredentialSubject, attr)
			assert.NotContains(t, filtered.ClaimProofs, attr)
		}

		rawJSON, err := json.Marshal(filtered)
		assert.NoError(t, err)
		assertJSONEquals(t, []byte(expectedJSON), rawJSON)
	})
}

func asSet(vals ...string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, s := range vals {
		m[s] = true
	}
	return m
}

func assertJSONEquals(t *testing.T, expected, actual []byte) {
	expectedJCS, err := jcs.Transform(expected)
	assert.NoError(t, err)
	actualJCS, err := jcs.Transform(actual)
	assert.NoError(t, err)
	expectedBuffer := bytes.Buffer{}
	json.Indent(&expectedBuffer, expectedJCS, "\t", "  ")
	actualBuffer := bytes.Buffer{}
	json.Indent(&actualBuffer, actualJCS, "\t", "  ")
	assert.Equal(t, expectedBuffer.String(), actualBuffer.String())
}

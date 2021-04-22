// +build unit

package response

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/credential/presentation"
)

const (
	criterionJSON = `
		{
			"schema": {
				"id": "did:work:abc123;123456789;version=1.0",
				"did": "did:work:abc123",
				"resource": "123456789",
				"version": "1.0",
				"attributes": [
					{ "name": "Apple", "required": true },
					{ "name": "Banana", "required": true },
					{ "name": "Cherry", "required": false },
					{ "name": "Date", "required": true },
					{ "name": "Elderberry", "required": false },
					{ "name": "Fig", "required": false }
				]
			}
		}`

	credentialJSON = `
		{
			"credentialSubject": {
				"id": "did:work:def456",
				"Apple": "Pie",
				"Banana": "Custard",
				"Cherry": "Jubilee",
				"Fig": "Pudding",
				"Gooseberry": "Fool"
			},
			"claimProofs": {
				"id": {
					"type": "WorkEd25519Signature2020",
					"created": "2020-05-12T13:25:37Z",
					"verificationMethod": "did:work:abc123#key-1",
					"nonce": "1",
					"signatureValue": "1"
				},
				"Apple": {
					"type": "WorkEd25519Signature2020",
					"created": "2020-05-12T13:25:37Z",
					"verificationMethod": "did:work:abc123#key-1",
					"nonce": "12",
					"signatureValue": "22"
				},
				"Banana": {
					"type": "WorkEd25519Signature2020",
					"created": "2020-05-12T13:25:37Z",
					"verificationMethod": "did:work:abc123#key-1",
					"nonce": "123",
					"signatureValue": "333"
				},
				"Cherry": {
					"type": "WorkEd25519Signature2020",
					"created": "2020-05-12T13:25:37Z",
					"verificationMethod": "did:work:abc123#key-1",
					"nonce": "1234",
					"signatureValue": "4444"
				},
				"Fig": {
					"type": "WorkEd25519Signature2020",
					"created": "2020-05-12T13:25:37Z",
					"verificationMethod": "did:work:abc123#key-1",
					"nonce": "12345",
					"signatureValue": "55555"
				},
				"Gooseberry": {
					"type": "WorkEd25519Signature2020",
					"created": "2020-05-12T13:25:37Z",
					"verificationMethod": "did:work:abc123#key-1",
					"nonce": "123456",
					"signatureValue": "666666"
				}
			}
		}`
)

// TestFilterCredential tests that we can remove all of the unrequested attributes from a credential.
func TestFilterCredential(t *testing.T) {
	var criterion presentation.Criterion
	assert.NoError(t, json.Unmarshal([]byte(criterionJSON), &criterion))

	var original credential.RawCredential
	assert.NoError(t, json.Unmarshal([]byte(credentialJSON), &original))

	filtered, err := filterCredential(criterion, original)
	assert.NoError(t, err)

	assert.NotEqual(t, original, filtered)
	assert.Equal(t, 5, len(filtered.CredentialSubject))
	assert.Equal(t, 5, len(filtered.ClaimProofs))

	assertCredentialContains := func(name string) {
		assert.Equal(t, original.CredentialSubject[name], filtered.CredentialSubject[name])
		assert.Equal(t, original.ClaimProofs[name], filtered.ClaimProofs[name])
	}

	// The "id" attribute is implicitly requested
	assertCredentialContains("id")

	// These attributes were requested and required
	assertCredentialContains("Apple")
	assertCredentialContains("Banana")

	// These attributes were requested and optional
	assertCredentialContains("Cherry")
	assertCredentialContains("Fig")

	assertCredentialNotContains := func(name string) {
		assert.NotContains(t, filtered.CredentialSubject, name)
		assert.NotContains(t, filtered.ClaimProofs, name)
	}

	// This attribute was requested and required but not available.
	assertCredentialNotContains("Date")
	// This attribute was requested and optional but not available
	assertCredentialNotContains("Elderberry")
	// This attribute was not requested
	assertCredentialNotContains("Gooseberry")
}

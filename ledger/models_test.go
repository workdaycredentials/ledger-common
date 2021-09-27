package ledger

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

// Simple de/serialization tests to verify the shape of the json objects

func TestLedgerMetadata(t *testing.T) {
	jsonMD := `{
		  "type": "https://credentials.id.workday.com/metadata-type",
		  "modelVersion": "1.0",
		  "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
		  "name": "Metadata",
		  "author": "did:work:6sYe1y3zXhmyrBkgHgAgaq",
		  "authored": "2019-01-01T00:00:00+00:00",
		  "proof": {
		    "created": "2018-01-01T00:00:00+00:0",
		    "verificationMethod": "did:work:6sYe1y3zXhmyrBkgHgAgaq",
		    "nonce": "fd15fe7f1f34498c800e23b9f81d8f1e",
		    "signatureValue": "5AFtmJxXHnhNJMUHeZvJSkSbHn4ieMs1wekodtQRteDCLZoWfbYEiTCHNqcBqcgTTivP9EgJhPjGPGmMQbakVwtu",
		    "type": "WorkEd25519Signature2020"
		  }
		}`

	md := Metadata{
		Type:         "https://credentials.id.workday.com/metadata-type",
		ModelVersion: "1.0",
		ID:           "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
		Name:         "Metadata",
		Author:       "did:work:6sYe1y3zXhmyrBkgHgAgaq",
		Authored:     "2019-01-01T00:00:00+00:00",
		Proof: &proof.Proof{
			Created:            "2018-01-01T00:00:00+00:0",
			VerificationMethod: "did:work:6sYe1y3zXhmyrBkgHgAgaq",
			Nonce:              "fd15fe7f1f34498c800e23b9f81d8f1e",
			SignatureValue:     "5AFtmJxXHnhNJMUHeZvJSkSbHn4ieMs1wekodtQRteDCLZoWfbYEiTCHNqcBqcgTTivP9EgJhPjGPGmMQbakVwtu",
			Type:               "WorkEd25519Signature2020",
		},
	}

	var metadata Metadata
	err := json.Unmarshal([]byte(jsonMD), &metadata)
	assert.NoError(t, err)

	assert.Equal(t, md, metadata)
}

func TestLedgerDIDDoc(t *testing.T) {
	docJSON := `{
				"type": "https://credentials.id.workday.com/diddoc",
				"modelVersion": "1.0",
				"id": "did:work:6sYe1y3zXhmyrBkgHgAgaq",
				"name": "DIDDoc",
				"author": "did:work:6sYe1y3zXhmyrBkgHgAgaq",
				"authored": "2019-01-01T00:00:00+00:00",
				"proof": {
					"created": "2018-01-01T00:00:00+00:0",
					"verificationMethod": "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
					"nonce": "fd15fe7f1f34498c800e23b9f81d8f1e",
					"signatureValue": "5AFtmJxXHnhNJMUHeZvJSkSbHn4ieMs1wekodtQRteDCLZoWfbYEiTCHNqcBqcgTTivP9EgJhPjGPGmMQbakVwtu",
					"type": "WorkEd25519Signature2020"
				},
				"didDoc": {
					"id": "did:work:6sYe1y3zXhmyrBkgHgAgaq",
					"publicKey": [{
						"id": "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
						"type": "WorkEd25519VerificationKey2020",
						"controller": "did:work:6sYe1y3zXhmyrBkgHgAgaq",
						"publicKeyBase58": "4CcKDtU1JNGi8U4D8Rv9CHzfmF7xzaxEAPFA54eQjRHF"
					}],
					"authentication": null,
					"service": null,
					"proof": {
						"created": "2018-01-01T00:00:00+00:0",
						"verificationMethod": "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
						"nonce": "fd15fe7f1f34498c800e23b9f81d8f1e",
						"signatureValue": "5AFtmJxXHnhNJMUHeZvJSkSbHn4ieMs1wekodtQRteDCLZoWfbYEiTCHNqcBqcgTTivP9EgJhPjGPGmMQbakVwtu",
						"type": "WorkEd25519Signature2020"
					}
				}
			}`

	expectedDoc := DIDDoc{
		Metadata: &Metadata{
			Type:         "https://credentials.id.workday.com/diddoc",
			ModelVersion: "1.0",
			ID:           "did:work:6sYe1y3zXhmyrBkgHgAgaq",
			Name:         "DIDDoc",
			Author:       "did:work:6sYe1y3zXhmyrBkgHgAgaq",
			Authored:     "2019-01-01T00:00:00+00:00",
			Proof: &proof.Proof{
				Created:            "2018-01-01T00:00:00+00:0",
				VerificationMethod: "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
				Nonce:              "fd15fe7f1f34498c800e23b9f81d8f1e",
				SignatureValue:     "5AFtmJxXHnhNJMUHeZvJSkSbHn4ieMs1wekodtQRteDCLZoWfbYEiTCHNqcBqcgTTivP9EgJhPjGPGmMQbakVwtu",
				Type:               "WorkEd25519Signature2020",
			},
		},
		DIDDoc: &did.DIDDoc{
			ID: "did:work:6sYe1y3zXhmyrBkgHgAgaq",
			PublicKey: []did.KeyDef{
				{
					ID:              "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
					Type:            "WorkEd25519VerificationKey2020",
					Controller:      "did:work:6sYe1y3zXhmyrBkgHgAgaq",
					PublicKeyBase58: "4CcKDtU1JNGi8U4D8Rv9CHzfmF7xzaxEAPFA54eQjRHF",
				},
			},
			Authentication: nil,
			Service:        nil,
			Proof: &proof.Proof{
				Created:            "2018-01-01T00:00:00+00:0",
				VerificationMethod: "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
				Nonce:              "fd15fe7f1f34498c800e23b9f81d8f1e",
				SignatureValue:     "5AFtmJxXHnhNJMUHeZvJSkSbHn4ieMs1wekodtQRteDCLZoWfbYEiTCHNqcBqcgTTivP9EgJhPjGPGmMQbakVwtu",
				Type:               "WorkEd25519Signature2020",
			},
		},
	}

	var didDoc DIDDoc
	err := json.Unmarshal([]byte(docJSON), &didDoc)
	assert.NoError(t, err)

	assert.Equal(t, expectedDoc, didDoc)
}

func TestLedgerSchema(t *testing.T) {
	schemaJSON := `{
			"type": "https://credentials.id.workday.com/metadata-type",
			"modelVersion": "1.0",
			"id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
			"name": "Metadata",
			"author": "did:work:6sYe1y3zXhmyrBkgHgAgaq",
			"authored": "2019-01-01T00:00:00+00:00",
			"proof": {
				"created": "2018-01-01T00:00:00+00:0",
				"verificationMethod": "did:work:6sYe1y3zXhmyrBkgHgAgaq",
				"nonce": "fd15fe7f1f34498c800e23b9f81d8f1e",
				"signatureValue": "5AFtmJxXHnhNJMUHeZvJSkSbHn4ieMs1wekodtQRteDCLZoWfbYEiTCHNqcBqcgTTivP9EgJhPjGPGmMQbakVwtu",
				"type": "WorkEd25519Signature2020"
			},
			"schema": {
				"$schema": "http://json-schema.org/draft-07/schema#",
				"additionalProperties": false,
				"description": "Name Schema",
				"properties": {
					"firstName": {
						"type": "string"
					},
					"lastName": {
						"type": "string"
					},
					"middleName": {
						"type": "string"
					},
					"suffix": {
						"type": "string"
					},
					"title": {
						"type": "string"
					}
				},
				"required": ["firstName", "lastName"],
				"type": "object"
			}
		}`

	expectedSchema := Schema{
		Metadata: &Metadata{
			Type:         "https://credentials.id.workday.com/metadata-type",
			ModelVersion: "1.0",
			ID:           "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
			Name:         "Metadata",
			Author:       "did:work:6sYe1y3zXhmyrBkgHgAgaq",
			Authored:     "2019-01-01T00:00:00+00:00",
			Proof: &proof.Proof{
				Created:            "2018-01-01T00:00:00+00:0",
				VerificationMethod: "did:work:6sYe1y3zXhmyrBkgHgAgaq",
				Nonce:              "fd15fe7f1f34498c800e23b9f81d8f1e",
				SignatureValue:     "5AFtmJxXHnhNJMUHeZvJSkSbHn4ieMs1wekodtQRteDCLZoWfbYEiTCHNqcBqcgTTivP9EgJhPjGPGmMQbakVwtu",
				Type:               "WorkEd25519Signature2020",
			},
		},
		JSONSchema: &JSONSchema{
			Schema: map[string]interface{}{
				"$schema":     "http://json-schema.org/draft-07/schema#",
				"description": "Name Schema",
				"type":        "object",
				"properties": map[string]interface{}{
					"title": map[string]string{
						"type": "string",
					},
					"firstName": map[string]string{
						"type": "string",
					},
					"lastName": map[string]string{
						"type": "string",
					},
					"middleName": map[string]string{
						"type": "string",
					},
					"suffix": map[string]string{
						"type": "string",
					},
				},
				"required": []string{
					"firstName",
					"lastName",
				},
				"additionalProperties": false,
			},
		},
	}

	var schema Schema
	err := json.Unmarshal([]byte(schemaJSON), &schema)
	assert.NoError(t, err)

	assert.Equal(t, expectedSchema.Metadata, schema.Metadata)
	assert.Equal(t, expectedSchema.Schema.ToJSON(), schema.JSONSchema.Schema.ToJSON())
}

func TestGenerateSchemaID(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		id := GenerateSchemaID("did:work:6sYe1y3zXhmyrBkgHgAgaq", "1.0")
		assert.Contains(t, id, "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=")
		assert.Contains(t, id, "version=1.0")
	})

	t.Run("generate schema id with LFD", func(t *testing.T) {
		id := GenerateSchemaID("did:ion:asdfghjklqwerty:zxcvbnmuiop", "1.0")
		assert.Contains(t, id, "did:ion:asdfghjklqwerty;id=")
		assert.Contains(t, id, "version=1.0")
	})
}

// tests where the given regular expression accurately validates the id property
func TestLedgerSchemaMetadataIDValidation(t *testing.T) {
	valid := Schema{
		Metadata: &Metadata{
			Type:         "https://credentials.id.workday.com/metadata-type",
			ModelVersion: "1.0",
			ID:           "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
			Name:         "Metadata",
			Author:       "did:work:6sYe1y3zXhmyrBkgHgAgaq",
			Authored:     "2019-01-01T00:00:00+00:00",
			Proof: &proof.Proof{
				Created:            "2018-01-01T00:00:00+00:0",
				VerificationMethod: "did:work:6sYe1y3zXhmyrBkgHgAgaq",
				Nonce:              "fd15fe7f1f34498c800e23b9f81d8f1e",
				SignatureValue:     "5AFtmJxXHnhNJMUHeZvJSkSbHn4ieMs1wekodtQRteDCLZoWfbYEiTCHNqcBqcgTTivP9EgJhPjGPGmMQbakVwtu",
				Type:               "WorkEd25519Signature2020",
			},
		},
		JSONSchema: &JSONSchema{
			Schema: map[string]interface{}{
				"$schema":     "http://json-schema.org/draft-07/schema#",
				"description": "Name Schema",
				"type":        "object",
				"properties": map[string]interface{}{
					"title": map[string]string{
						"type": "string",
					},
					"firstName": map[string]string{
						"type": "string",
					},
					"lastName": map[string]string{
						"type": "string",
					},
					"middleName": map[string]string{
						"type": "string",
					},
					"suffix": map[string]string{
						"type": "string",
					},
				},
				"required": []string{
					"firstName",
					"lastName",
				},
				"additionalProperties": false,
			},
		},
	}

	assert.NoError(t, valid.ValidateID())

	invalid := Schema{
		Metadata: &Metadata{
			Type:         "https://credentials.id.workday.com/metadata-type",
			ModelVersion: "1.0",
			ID:           "did:work:abcdefghijklmnop",
			Name:         "Metadata",
			Author:       "did:work:6sYe1y3zXhmyrBkgHgAgaq",
			Authored:     "2019-01-01T00:00:00+00:00",
			Proof: &proof.Proof{
				Created:            "2018-01-01T00:00:00+00:0",
				VerificationMethod: "did:work:6sYe1y3zXhmyrBkgHgAgaq",
				Nonce:              "fd15fe7f1f34498c800e23b9f81d8f1e",
				SignatureValue:     "5AFtmJxXHnhNJMUHeZvJSkSbHn4ieMs1wekodtQRteDCLZoWfbYEiTCHNqcBqcgTTivP9EgJhPjGPGmMQbakVwtu",
				Type:               "WorkEd25519Signature2020",
			},
		},
		JSONSchema: &JSONSchema{
			Schema: map[string]interface{}{
				"$schema":     "http://json-schema.org/draft-07/schema#",
				"description": "Name Schema",
				"type":        "object",
				"properties": map[string]interface{}{
					"title": map[string]string{
						"type": "string",
					},
					"firstName": map[string]string{
						"type": "string",
					},
					"lastName": map[string]string{
						"type": "string",
					},
					"middleName": map[string]string{
						"type": "string",
					},
					"suffix": map[string]string{
						"type": "string",
					},
				},
				"required": []string{
					"firstName",
					"lastName",
				},
				"additionalProperties": false,
			},
		},
	}

	assert.Error(t, invalid.ValidateID())

	invalidWithBadVersion := Schema{
		Metadata: &Metadata{
			Type:         "https://credentials.id.workday.com/metadata-type",
			ModelVersion: "1.0",
			ID:           "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0.0",
			Name:         "Metadata",
			Author:       "did:work:6sYe1y3zXhmyrBkgHgAgaq",
			Authored:     "2019-01-01T00:00:00+00:00",
			Proof: &proof.Proof{
				Created:            "2018-01-01T00:00:00+00:0",
				VerificationMethod: "did:work:6sYe1y3zXhmyrBkgHgAgaq",
				Nonce:              "fd15fe7f1f34498c800e23b9f81d8f1e",
				SignatureValue:     "5AFtmJxXHnhNJMUHeZvJSkSbHn4ieMs1wekodtQRteDCLZoWfbYEiTCHNqcBqcgTTivP9EgJhPjGPGmMQbakVwtu",
				Type:               "WorkEd25519Signature2020",
			},
		},
		JSONSchema: &JSONSchema{
			Schema: map[string]interface{}{
				"$schema":     "http://json-schema.org/draft-07/schema#",
				"description": "Name Schema",
				"type":        "object",
				"properties": map[string]interface{}{
					"title": map[string]string{
						"type": "string",
					},
					"firstName": map[string]string{
						"type": "string",
					},
					"lastName": map[string]string{
						"type": "string",
					},
					"middleName": map[string]string{
						"type": "string",
					},
					"suffix": map[string]string{
						"type": "string",
					},
				},
				"required": []string{
					"firstName",
					"lastName",
				},
				"additionalProperties": false,
			},
		},
	}

	assert.Error(t, invalidWithBadVersion.ValidateID())
}

func TestGetSchemaVersion(t *testing.T) {
	valid := Schema{
		Metadata: &Metadata{
			Type:         "https://credentials.id.workday.com/metadata-type",
			ModelVersion: "1.0",
			ID:           "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
			Name:         "Metadata",
			Author:       "did:work:6sYe1y3zXhmyrBkgHgAgaq",
			Authored:     "2019-01-01T00:00:00+00:00",
			Proof: &proof.Proof{
				Created:            "2018-01-01T00:00:00+00:0",
				VerificationMethod: "did:work:6sYe1y3zXhmyrBkgHgAgaq",
				Nonce:              "fd15fe7f1f34498c800e23b9f81d8f1e",
				SignatureValue:     "5AFtmJxXHnhNJMUHeZvJSkSbHn4ieMs1wekodtQRteDCLZoWfbYEiTCHNqcBqcgTTivP9EgJhPjGPGmMQbakVwtu",
				Type:               "WorkEd25519Signature2020",
			},
		},
		JSONSchema: &JSONSchema{
			Schema: map[string]interface{}{
				"$schema":     "http://json-schema.org/draft-07/schema#",
				"description": "Name Schema",
				"type":        "object",
				"properties": map[string]interface{}{
					"title": map[string]string{
						"type": "string",
					},
					"firstName": map[string]string{
						"type": "string",
					},
					"lastName": map[string]string{
						"type": "string",
					},
					"middleName": map[string]string{
						"type": "string",
					},
					"suffix": map[string]string{
						"type": "string",
					},
				},
				"required": []string{
					"firstName",
					"lastName",
				},
				"additionalProperties": false,
			},
		},
	}

	r, err := valid.Version()
	assert.NoError(t, err)
	assert.Equal(t, "1.0", r)
}

func TestSchemaUtilities(t *testing.T) {
	jsonIn := `{
		"type": "https://credentials.workday.com/docs/specification/v1.0/schema.json",
		"modelVersion": "1.0",
		"id": "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=ea691feb8e4537b9bb5d2b5d5bb984;version=1.0",
		"name": "Name",
		"author": "did:work:6sYe1y3zXhmyrBkgHgAgaq",
		"authored": "2018-01-01T00:00:00+00:00",
		"schema": {
		  "$schema": "http://json-schema.org/draft-07/schema#",
		  "description": "Name Credential Object",
		  "type": "object",
		  "properties": {
			"title": {
			  "type": "string",
			  "format": "fake"
			},
			"firstName": {
			  "type": "string",
			  "format": "fake"
			},
			"lastName": {
			  "type": "string",
			  "format": "fake"
			},
			"middleName": {
			  "type": "string",
			  "format": "fake"
			},
			"suffix": {
			  "type": "string",
			  "format": "fake"
			}
		  },
		  "required": ["firstName", "lastName"],
		  "additionalProperties": false
		},
		"proof": {
		  "created": "2019-08-20T20:45:57Z",
		  "creator": "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
		  "nonce": "0948bb75-60c2-4a92-ad50-01ccee169ae0",
		  "signatureValue": "2y1ksgsrJSZErLn3p55USFQ7jLBzNjJLsRBfVMFgE5zeSnb1whWxQn2asHdtPMDAiMSYvSnnJenqjWi46Dy7G4ZX",
		  "type": "WorkEd25519Signature2020"
		}
	}`

	var s Schema
	err := json.Unmarshal([]byte(jsonIn), &s)
	require.NoError(t, err)

	assert.Equal(t, s.Schema.Description(), "Name Credential Object")

	requiredFields := s.Schema.RequiredFields()
	assert.Equal(t, len(requiredFields), 2)
	assert.True(t, Contains("firstName", requiredFields))
	assert.False(t, Contains("middleName", requiredFields))

	assert.Equal(t, s.Schema.AllowsAdditionalProperties(), false)

	properties := s.Schema.Properties()
	for _, property := range properties {
		assert.Equal(t, Type(property), "string")
		assert.Equal(t, Format(property), "fake")
	}
}

// Ensures no fields are lost marshalling/unmarshalling of JSON schema using schema
func TestLedgerMetadataSchema(t *testing.T) {
	schemaJSON := `{
		"type": "https://credentials.workday.com/docs/specification/v1.0/schema.json",
		"modelVersion": "1.0",
		"id": "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=ea691feb8e4537b9bb5d2b5d5bb984;version=1.0",
		"name": "Name",
		"author": "did:work:6sYe1y3zXhmyrBkgHgAgaq",
		"authored": "2018-01-01T00:00:00+00:00",
		"schema": {
		  "$schema": "http://json-schema.org/draft-07/schema#",
		  "description": "Name Credential Object",
		  "type": "object",
		  "properties": {
			"title": {
			  "type": "string",
			  "format": "fake"
			},
			"firstName": {
			  "type": "string",
			  "format": "fake"
			},
			"lastName": {
			  "type": "string",
			  "format": "fake"
			},
			"middleName": {
			  "type": "string",
			  "format": "fake"
			},
			"suffix": {
			  "type": "string",
			  "format": "fake"
			}
		  },
		  "required": ["firstName", "lastName"],
		  "additionalProperties": false
		},
		"proof": {
		  "created": "2019-08-20T20:45:57Z",
		  "verificationMethod": "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
		  "nonce": "0948bb75-60c2-4a92-ad50-01ccee169ae0",
		  "signatureValue": "2y1ksgsrJSZErLn3p55USFQ7jLBzNjJLsRBfVMFgE5zeSnb1whWxQn2asHdtPMDAiMSYvSnnJenqjWi46Dy7G4ZX",
		  "type": "WorkEd25519Signature2020"
		}
	}`

	schemaSchema := `{
					  "$schema": "http://json-schema.org/draft-07/schema#",
					  "description": "Name Credential Object",
					  "type": "object",
					  "properties": {
						"title": {
						  "type": "string",
						  "format": "fake"
						},
						"firstName": {
						  "type": "string",
						  "format": "fake"
						},
						"lastName": {
						  "type": "string",
						  "format": "fake"
						},
						"middleName": {
						  "type": "string",
						  "format": "fake"
						},
						"suffix": {
						  "type": "string",
						  "format": "fake"
						}
					  },
					  "required": ["firstName", "lastName"],
					  "additionalProperties": false
					 }
					`

	var schema Schema
	err := json.Unmarshal([]byte(schemaJSON), &schema)

	assert.NoError(t, err)
	assert.Equal(t, util.SchemaTypeReference_v1_0, schema.Type)
	assert.Equal(t, "1.0", schema.ModelVersion)
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=ea691feb8e4537b9bb5d2b5d5bb984;version=1.0", schema.ID)
	assert.Equal(t, "Name", schema.Name)
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq", schema.Author.String())
	assert.Equal(t, "2018-01-01T00:00:00+00:00", schema.Authored)
	assert.Equal(t, "2019-08-20T20:45:57Z", schema.Proof.Created)
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1", schema.Proof.GetVerificationMethod())
	assert.Equal(t, "0948bb75-60c2-4a92-ad50-01ccee169ae0", schema.Proof.Nonce)
	assert.Equal(t, "2y1ksgsrJSZErLn3p55USFQ7jLBzNjJLsRBfVMFgE5zeSnb1whWxQn2asHdtPMDAiMSYvSnnJenqjWi46Dy7G4ZX", schema.Proof.SignatureValue)
	assert.Equal(t, proof.WorkEdSignatureType, schema.Proof.Type)

	schemaBytes, _ := json.Marshal(schema.Schema)
	equal, err := util.JSONBytesEqual([]byte(schemaSchema), schemaBytes)
	assert.NoError(t, err)
	assert.True(t, equal)
}

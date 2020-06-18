package schema

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/ledger"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/access"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/address"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/certification"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/course"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/education"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/email"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/employment"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/involvement"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/name"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/payslip"
	"github.com/workdaycredentials/ledger-common/ledger/schema/schemas/phonenumber"
	"github.com/workdaycredentials/ledger-common/proof"
)

// This suite of tests tests the validity of different credentials against their JSON SignedMetadata
// This does not ValidateWithJSONLoader anything past what JSON SignedMetadata can ValidateWithJSONLoader. Post-JSON SignedMetadata validations
// Can be found in other tests (in the future). This test also assumes the input is valid JSON SignedMetadata and valid JSON.

func TestCredentialSchema(t *testing.T) {
	schemaString := credential.VerifiableCredentialSchema

	testConfigs := []struct {
		name          string
		json          string
		errorExpected bool
	}{
		{
			name: "Valid definition json with name subject",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:6sYe1y3zXhmyrBkgHgAgaq#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: false,
		},
		{
			name: "Invalid definition json with invalid version",
			json: `{
                    "version": "1.0",
                    "id": "did:work:abcdefghijklmnoprstuvp#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Certification"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid definition json with invalid id",
			json: `{
                    "version": "1.0.1",
                    "id": "did:work:abcdefghijklmnoprstuv#00112233-4455-6677-8899",
                    "type": ["VerifiableCredential"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Valid definition json with invalid type",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": "Name",
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Valid definition json with missing credential type",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid definition json with invalid issuer did format",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:not",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid definition json with bad credential s id",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:bad/json-s/Name",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid definition json with bad credential s type",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "Unsupported"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid definition json with bad credential no s type",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": []
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid definition json with empty credential subject",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {},
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Valid definition json with valid claim proof",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "claimProof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "claimSignatureValue": {
                            "title": "sample-title-signature"
                        }
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: false,
		},
		{
			name: "Invalid definition json with invalid claim proof type",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "claimProof": {
                        "type": "bad",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "claimSignatureValue": {
                            "title": "sample-title-signature"
                        }
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid definition json with invalid claim proof date",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "claimProof": {
                        "type": "RsaSignature2018",
                        "created": "00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "claimSignatureValue": {
                            "title": "sample-title-signature"
                        }
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid definition json with invalid claim signature (empty)",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "claimProof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "claimSignatureValue": {}
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid definition json with invalid claim proof fields (missing)",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "claimProof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid definition json with bad proof type",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "bad",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid definition json with bad proof created date",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid definition json with bad proof (missing field)",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1"
                    }
                   }`,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(t *testing.T) {
			err := Validate(schemaString, testConfig.json)
			if !testConfig.errorExpected {
				if err != nil {
					t.Errorf("Unexpected error: %s, for json: %s", err.Error(), testConfig.json)
				}
			} else {
				assert.IsType(t, InvalidSchemaError{}, err)
			}
		})
	}
}

func TestValidateNameCredential(t *testing.T) {
	schemaString := name.Name

	testConfigs := []struct {
		name          string
		json          string
		errorExpected bool
	}{
		{
			name: "Valid name credential with all fields",
			json: `{
                    "title": "Mr",
                    "firstName": "Test",
                    "middleName": "Ing",
                    "lastName": "User",
                    "suffix": "III"
                   }`,
			errorExpected: false,
		},
		{
			name: "Valid name credential with minimal fields",
			json: `{
                    "firstName": "Test",
                    "lastName": "User"
                   }`,
			errorExpected: false,
		},
		{
			name: "Invalid name credential (missing required first name field)",
			json: `{
                    "title": "Mr",
                    "lastName":"User"
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid name credential (missing required last name field)",
			json: `{
                    "title": "Mr",
                    "firstName":"Test"
                   }`,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(_ *testing.T) {
			err := Validate(schemaString, testConfig.json)
			if !testConfig.errorExpected {
				if err != nil {
					t.Errorf("Unexpected error: %s, for json: %s", err.Error(), testConfig.json)
				}
			}
		})
	}
}

func TestValidateEmploymentCredential(t *testing.T) {

	schemaString := employment.Employment

	testConfigs := []struct {
		name          string
		json          string
		errorExpected bool
	}{
		{
			name: "Valid employment credential with all fields",
			json: `{
                    "company": "Next",
                    "jobTitle": "Badger Wrangler",
                    "position": "N1",
                    "startDate": "2018-01-01",
                    "endDate": "2015-09-25"
                   }`,
			errorExpected: false,
		},
		{
			name: "Valid employment credential with only required fields",
			json: `{
                    "company": "Next",
                    "jobTitle": "Badger Wrangler",
                    "position": "N1",
                    "startDate": "2018-01-01"
                   }`,
			errorExpected: false,
		},
		{
			name: "Invalid employment credential with missing required fields",
			json: `{
                    "company": "Next",
                    "jobTitle": "Badger Wrangler",
                    "position": "N1"
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid employment credential with improperly formatted date",
			json: `{
                    "company": "Next",
                    "jobTitle": "Badger Wrangler",
                    "position": "N1",
                    "startDate": "2018-01-1"
                   }`,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(_ *testing.T) {
			err := Validate(schemaString, testConfig.json)
			if !testConfig.errorExpected {
				if err != nil {
					t.Errorf("Unexpected error: %s, for json: %s", err.Error(), testConfig.json)
				}
			}
		})
	}
}

func TestValidateEmailCredential(t *testing.T) {

	schemaString := email.Email

	testConfigs := []struct {
		name          string
		json          string
		errorExpected bool
	}{
		{
			name: "Valid contact info credential with all fields",
			json: `{
                    "emailAddress": "test@test.com"
                   }`,
			errorExpected: false,
		},
		{
			name: "Invalid contact info credential with invalid email format",
			json: `{
                    "emailAddress": "test.com"
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid contact info credential with additional fields",
			json: `{
                    "emailAddress": "test@test.com",
                    "name": "111-222-3333"
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid contact info credential missing required field",
			json: `{
                   }`,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(_ *testing.T) {
			err := Validate(schemaString, testConfig.json)
			if !testConfig.errorExpected {
				if err != nil {
					t.Errorf("Unexpected error: %s, for json: %s", err.Error(), testConfig.json)
				}
			}
		})
	}
}

func TestValidateEducationCredential(t *testing.T) {

	schemaString := education.Education

	testConfigs := []struct {
		name          string
		json          string
		errorExpected bool
	}{
		{
			name: "Valid education credential with all fields",
			json: `{
                    "startDate": "2018-01-01",
                    "endDate": "2019-09-25",
                    "institutionName": "NextU",
                    "institutionLocation": "Everywhere (distributed)",
                    "degreeReceivedDate": "2019-09-25",
                    "degree": "Masters of Science",
                    "fieldOfStudy": "Crypto Key Comprehension"
                   }`,
			errorExpected: false,
		},
		{
			name: "Invalid education credential with missing field",
			json: `{
                    "startDate": "2018-01-01",
                    "endDate": "2019-09-25",
                    "institutionName": "NextU",
                    "institutionLocation": "Everywhere (distributed)",
                    "degreeReceivedDate": "2019-09-25",
                    "degree": "Masters of Science"
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid education credential with improperly formatted date",
			json: `{
                    "startDate": "2018-1-01",
                    "endDate": "2019-09-25",
                    "institutionName": "NextU",
                    "institutionLocation": "Everywhere (distributed)",
                    "degreeReceivedDate": "2019-09-25",
                    "degree": "Masters of Science",
                    "fieldOfStudy": "Crypto Key Comprehension"
                   }`,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(_ *testing.T) {
			err := Validate(schemaString, testConfig.json)
			if !testConfig.errorExpected {
				if err != nil {
					t.Errorf("Unexpected error: %s, for json: %s", err.Error(), testConfig.json)
				}
			}
		})
	}
}

func TestValidateInvolvementCredential(t *testing.T) {
	schemaString := involvement.Involvement

	testConfigs := []struct {
		name          string
		json          string
		errorExpected bool
	}{
		{
			name: "Valid involvement credential with all fields",
			json: `{
                    "involvementName": "Philanthropy",
                    "beginDate": "2011-05-15",
                    "endDate": "2020-09-25",
                    "relationship": "Founder",
                    "location": "San Francisco",
                    "organization": "Daves Dogs"
                   }`,
			errorExpected: false,
		},
		{
			name: "Invalid involvement credential with missing field",
			json: `{
                    "beginDate": "2011-05-15",
                    "endDate": "2020-09-25",
                    "relationship": "Caretaker",
                    "location": "San Francisco",
                    "organization": "Daves Dogs"
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid involvement credential with improperly formatted date",
			json: `{
                    "involvementName": "Philanthropy",
                    "beginDate": "2011-5-15",
                    "endDate": "2020-09-25",
                    "relationship": "Founder",
                    "location": "San Francisco",
                    "organization": "Daves Dogs"
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid involvement credential with invalid number",
			json: `{
                    "involvementName": "Philanthropy",
                    "beginDate": "2011-05-15",
                    "endDate": "2020-09-25",
                    "relationship": "Founder",
                    "location": "San Francisco",
                    "organization": "Daves Dogs",
                    "number": "123"
                   }`,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(_ *testing.T) {
			err := Validate(schemaString, testConfig.json)
			if !testConfig.errorExpected {
				if err != nil {
					t.Errorf("Unexpected error: %s, for json: %s", err.Error(), testConfig.json)
				}
			}
		})
	}
}

func TestValidateCourseCredential(t *testing.T) {
	schemaString := course.Course

	testConfigs := []struct {
		name          string
		json          string
		errorExpected bool
	}{
		{
			name: "Valid course credential with all fields",
			json: `{
                    "title": "Math",
                    "startDate": "2011-05-15",
                    "completionDate": "2020-09-25",
                    "required": "true",
                    "provider": "Coursera",
                    "score": "95.50"
                   }`,
			errorExpected: false,
		},
		{
			name: "Invalid course credential with missing field",
			json: `{
                    "startDate": "2011-05-15",
                    "completionDate": "2020-09-25",
                    "required": "true",
                    "provider": "Coursera",
                    "score": "95.50"
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid course credential with improperly formatted date",
			json: `{
                    "title": "Math",
                    "startDate": "2011-5-15",
                    "completionDate": "2020-09-25",
                    "required": "true",
                    "provider": "Coursera",
                    "score": "95.50"
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid course credential with invalid field",
			json: `{
                    "title": "Math",
                    "startDate": "2011-5-15",
                    "completionDate": "2020-09-25",
                    "required": "true",
                    "provider": "Coursera",
                    "score": "95.50",
                    "number": "123"
                   }`,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(_ *testing.T) {
			err := Validate(schemaString, testConfig.json)
			if !testConfig.errorExpected {
				if err != nil {
					t.Errorf("Unexpected error: %s, for json: %s", err.Error(), testConfig.json)
				}
			}
		})
	}
}

func TestValidateCertificationCredential(t *testing.T) {
	schemaString := certification.Certification

	testConfigs := []struct {
		name          string
		json          string
		errorExpected bool
	}{
		{
			name: "Valid certification credential with all fields",
			json: `{
                    "certificationName": "me",
					"certificationIssuer": "also me",
					"examDate": "2018-01-01",
                    "examScore": "A+",
                    "details": "'murica",
                    "issuedDate": "2018-01-01",
                    "expirationDate": "2019-09-25",
                    "certificationNumber": "1111"
                   }`,
			errorExpected: false,
		},
		{
			name: "Valid certification credential with only required fields",
			json: `{
                    "certificationName": "me",
					"certificationIssuer": "also me",
					"issuedDate": "2018-01-01"
                   }`,
			errorExpected: false,
		},
		{
			name: "Invalid certification credential with missing required fields",
			json: `{
                    "name": "me",
                    "examScore": "A-"
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid certification credential with empty array",
			json: `{
                    "certificationName": "me",
					"certificationIssuer": "also me",
					"examDate": "2018-01-01",
                    "examScore": "A+",
                    "details": "'murica",
                    "issuedDate": "2018-01-01",
                    "expirationDate": "2019-09-25",
                    "certificationNumber": "100"
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid certification credential with improperly formatted date",
			json: `{
                    "certificationName": "me",
					"certificationIssuer": "also me",
                    "issuedDate": "2018-1-01",
                    "expirationDate": "2019-09-25",
                    "number": "Everywhere"
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid certification credential with invalid number",
			json: `{
                    "certificationName": "me",
					"certificationIssuer": "also me",
					"issuedDate": "2018-01-01",
                    "expirationDate": "2019-09-25",
                    "number": "1"
                   }`,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(_ *testing.T) {
			err := Validate(schemaString, testConfig.json)
			if !testConfig.errorExpected {
				if err != nil {
					t.Errorf("Unexpected error: %s, for json: %s", err.Error(), testConfig.json)
				}
			}
		})
	}
}

func TestValidatePhoneNumberCredential(t *testing.T) {
	schemaString := phonenumber.PhoneNumber

	testConfigs := []struct {
		name          string
		json          string
		errorExpected bool
	}{
		{
			name: "Valid phone number credential with all fields",
			json: `{
                    "phoneNumber": "123-456-7890",
					"country": "USA"
                   }`,
			errorExpected: false,
		},
		{
			name: "Valid phone number credential with all fields 2",
			json: `{
                    "phoneNumber": "(123) 456-7890",
					"country": "USA"
                   }`,
			errorExpected: false,
		},
		{
			name: "Valid phone number credential with all fields 3",
			json: `{
                    "phoneNumber": "+1 123 456 7890",
					"country": "USA"
                   }`,
			errorExpected: false,
		},
		{
			name: "Invalid phone number credential with invalid number format",
			json: `{
                    "phoneNumber": "4442221",
					"country": "USA"
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid phone number credential with additional fields",
			json: `{
                    "phoneNumber": "111-222-3333",
                    "country": "USA"
                   }`,
			errorExpected: true,
		},
		{
			name: "Invalid phone number credential missing required field",
			json: `{
					 "country": "+1"
                   }`,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(_ *testing.T) {
			err := Validate(schemaString, testConfig.json)
			if !testConfig.errorExpected {
				if err != nil {
					t.Errorf("Unexpected error: %s, for json: %s", err.Error(), testConfig.json)
				}
			}
		})
	}
}

func TestValidateAddressCredential(t *testing.T) {
	schemaString := address.Address

	testConfigs := []struct {
		name          string
		json          string
		errorExpected bool
	}{
		{
			name: "Valid address credential with all fields",
			json: `{
                      "street1": "6110 Stoneridge Mall Rd",
                      "street2": "#1",
                      "city": "Pleasanton",
                      "state": "CA",
                      "postalCode": "94588",
                      "country": "USA"
                    }`,
			errorExpected: false,
		},
		{
			name: "Valid address credential with all required fields",
			json: `{
                      "street1": "6110 Stoneridge Mall Rd",
                      "city": "Pleasanton",
                      "state": "CA",
                      "postalCode": "94588",
                      "country": "USA"
                    }`,
			errorExpected: false,
		},
		{
			name: "Invalid address credential with missing field",
			json: `{
                      "street2": "#1",
                      "city": "Pleasanton",
                      "state": "CA",
                      "postalCode": "94588",
                      "country": "USA"
                    }`,
			errorExpected: true,
		},
		{
			name: "Invalid address credential with additional field",
			json: `{
                      "street1": "6110 Stoneridge Mall Rd",
                      "city": "Pleasanton",
                      "state": "CA",
                      "postalCode": "94588",
                      "country": "USA",
                      "favoriteBird": "Penguin"
                    }`,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(_ *testing.T) {
			err := Validate(schemaString, testConfig.json)
			if !testConfig.errorExpected {
				if err != nil {
					t.Errorf("Unexpected error: %s, for json: %s", err.Error(), testConfig.json)
				}
			}
		})
	}
}

func TestValidateAccessCredential(t *testing.T) {
	schemaString := access.Access

	testConfigs := []struct {
		name          string
		json          string
		errorExpected bool
	}{
		{
			name: "Valid access credential with all fields",
			json: `{
                      "expirationDate": "2018-01-01T00:00:00+00:00",
                      "tenantName": "oms",
                      "tenantType": "impl",
                      "auditInfo": "dev"
                    }`,
			errorExpected: false,
		},
		{
			name: "Invalid access credential with bad date",
			json: `{
                      "expirationDate": "2018-01-01,
                      "tenantName": "oms",
                      "tenantType": "impl",
                      "auditInfo": "dev"
                    }`,
			errorExpected: true,
		},
		{
			name: "Invalid access credential missing field (tenantName)",
			json: `{
                      "expirationDate": "2018-01-01T00:00:00+00:00",
                      "tenantType": "impl",
                      "auditInfo": "dev"
                    }`,
			errorExpected: true,
		},
		{
			name: "Invalid access credential missing field (auditInfo)",
			json: `{
                      "expirationDate": "2018-01-01T00:00:00+00:00",
                      "tenantName": "oms",
                      "tenantType": "impl",
                      "tenant": "oms"
                    }`,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(_ *testing.T) {
			err := Validate(schemaString, testConfig.json)
			if !testConfig.errorExpected {
				if err != nil {
					t.Errorf("Unexpected error: %s, for json: %s", err.Error(), testConfig.json)
				}
			}
		})
	}
}

func TestValidatePayslipCredential(t *testing.T) {
	schemaString := payslip.Payslip

	testConfigs := []struct {
		name          string
		json          string
		errorExpected bool
	}{
		{
			name: "Valid payslip credential with all fields",
			json: `{
                      "payPeriodStart": "2018-01-01T00:00:00+00:00",
                      "payPeriodEnd": "2019-01-01T00:00:00+00:00",
                      "grossPay": "2.00",
                      "netPay": "1.00",
                      "currency": "USD"
                    }`,
			errorExpected: false,
		},
		{
			name: "Invalid payslip credential with missing field",
			json: `{
                      "payPeriodStart": "2018-01-01T00:00:00+00:00",
                      "payPeriodEnd": "2019-01-01T00:00:00+00:00",
                      "grossPay": "2.00",
                      "netPay": "1.00"
                    }`,
			errorExpected: true,
		},
		{
			name: "Invalid payslip credential with bad regex",
			json: `{
                      "payPeriodStart": "2018-01-01T00:00:00+00:00",
                      "payPeriodEnd": "2019-01-01T00:00:00+00:00",
                      "grossPay": "200",
                      "netPay": "1.00",
                      "currency": "USD"
                    }`,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(_ *testing.T) {
			err := Validate(schemaString, testConfig.json)
			if !testConfig.errorExpected {
				if err != nil {
					t.Errorf("Unexpected error: %s, for json: %s", err.Error(), testConfig.json)
				}
			}
		})
	}
}

func TestFullCredentialSchema(t *testing.T) {

	var (
		credentialString            = credential.VerifiableCredentialSchema
		credentialSubjectNameString = name.Name
	)

	testConfigs := []struct {
		name          string
		json          string
		errorExpected bool
	}{
		{
			name: "Valid full credential and credential subject json with name s",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: false,
		},
		{
			name: "Invalid credential json with valid subject json (missing version field)",
			json: `{
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Valid credential json with invalid subject json (missing required field)",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:abcdefghijklmnoprstuv",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
		{
			name: "Valid definition json with invalid holder did",
			json: `{
                    "version": "1.0.0",
                    "id": "did:work:abcdefghijklmnoprstuv#f6545054-f958-4b90-a7cd-d9b207af0acb",
                    "type": ["VerifiableCredential", "Name"],
                    "issuer": "did:work:abcdefghijklmnoprstuv",
                    "issuanceDate": "2018-01-01T00:00:00+00:00",
                    "targetHolder": "did:work:",
                    "credentialSchema": {
                        "id": "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
                        "type": "JsonSchemaValidator2018"
                    },
                    "credentialSubject": {
                        "title": "Mr",
                        "firstName": "Test",
                        "middleName": "Ing",
                        "lastName": "User",
                        "suffix": "III"
                    },
                    "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                    }
                   }`,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(t *testing.T) {
			err := ValidateCredential(credentialString, credentialSubjectNameString, testConfig.json)
			if !testConfig.errorExpected {
				if err != nil {
					t.Errorf("Unexpected error: %s, for json: %s", err.Error(), testConfig.json)
				}
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestValidateLedgerSchemaRequest(t *testing.T) {
	testConfigs := []struct {
		name          string
		document      interface{}
		version       string
		errorExpected bool
	}{
		{
			name: "Valid Version 1 Bundle",
			document: ledger.Schema{
				Metadata: &ledger.Metadata{
					Type:         "https://credentials.id.workday.com/metadata-type",
					ModelVersion: "1.0",
					ID:           "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
					Name:         "Metadata",
					Author:       "did:work:6sYe1y3zXhmyrBkgHgAgaq",
					Authored:     "2019-01-01T00:00:00+00:00",
					Proof: &proof.Proof{
						Created:            "2019-08-20T20:45:57Z",
						VerificationMethod: "did:work:6sYe1y3zXhmyrBkgHgAgaq",
						Nonce:              "fd15fe7f1f34498c800e23b9f81d8f1e",
						SignatureValue:     "5AFtmJxXHnhNJMUHeZvJSkSbHn4ieMs1wekodtQRteDCLZoWfbYEiTCHNqcBqcgTTivP9EgJhPjGPGmMQbakVwtu",
						Type:               "WorkEd25519Signature2020",
					},
				},
				JSONSchema: &ledger.JSONSchema{
					Schema: map[string]interface{}{
						"$schema":     "http://json-schema.org/draft-07/schema#",
						"description": "Name JSONSchema",
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
			},
			version:       "1",
			errorExpected: false,
		},
		{
			name: "invalid Version 1 Bundle",
			document: ledger.Schema{
				Metadata: &ledger.Metadata{
					Type:         "https://credentials.id.workday.com/metadata-type",
					ModelVersion: "1.0",
					ID:           "did:work:8RcWPSBtB4QwfC68yneDxC;id=860285e2-183d-4fe3-9767-babc744396b8;version=1.0",
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
				JSONSchema: &ledger.JSONSchema{
					Schema: map[string]interface{}{
						"$schema":     "http://json-schema.org/draft-07/schema#",
						"description": "Name JSONSchema",
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
			},
			version:       "1",
			errorExpected: true,
		},
		{
			name:          "Invalid Version 1 Bundle with bad document",
			document:      "document",
			version:       "1",
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(_ *testing.T) {
			err := ValidateSchemaRequest(context.Background(), testConfig.document, testConfig.version)
			if !testConfig.errorExpected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestRFC3339Validation(t *testing.T) {
	checker := RFC3339FormatChecker{}

	// Valid formats
	good := checker.IsFormat("2006-01-02T15:04:05+07:00")
	assert.True(t, good)

	good = checker.IsFormat("2006-01-02T15:04:05+04:00")
	assert.True(t, good)

	good = checker.IsFormat("2006-01-02T15:04:05Z")
	assert.True(t, good)

	good = checker.IsFormat("2006-01-02T15:04:05+00:00")
	assert.True(t, good)

	// Invalid formats
	bad := checker.IsFormat("200601-02T15:04:05+07:00")
	assert.False(t, bad)

	bad = checker.IsFormat("2006-01-02T15:04:05Z04:00")
	assert.False(t, bad)

	bad = checker.IsFormat("2006-01-02T15:04:05")
	assert.False(t, bad)

	bad = checker.IsFormat("2006-01-02+15:04:05+00:00")
	assert.False(t, bad)
}

func TestIsJson(t *testing.T) {
	json := "{}"
	json1 := `{
                "proof": {
                        "type": "RsaSignature2018",
                        "created": "2018-01-01T00:00:00+00:00",
                        "creator": "https://example.com/jdoe/keys/1",
                        "signatureValue": "BavEll0/I1zpYw8XNi1bgVg/sCneO4Jugez8RwDg/="
                        }
              }`
	json2 := `{
                "street1": "6110 Stoneridge Mall Rd",
                "street2": "#1",
                "city": "Pleasanton",
                "state": "CA",
                "postalCode": "94588",
                "country": "USA"
              }`
	assert.True(t, isJSON(json))
	assert.True(t, isJSON(json1))
	assert.True(t, isJSON(json2))

	notJson := `"abcd": 1234`
	notJson1 := "{abcd}"
	notJson2 := "{abcd: 1324}"
	assert.False(t, isJSON(notJson))
	assert.False(t, isJSON(notJson1))
	assert.False(t, isJSON(notJson2))
}

// Tests validation on ledger metadata for incorrectly formed metadata
func TestLedgerMetadataValidation(t *testing.T) {
	schemaString := ledger.MetadataSchema

	testConfigs := []struct {
		name          string
		json          string
		errorExpected bool
	}{
		{
			name: "Valid ledger metadata",
			json: `{
                    "type": "https://credentials.workday.com/docs/specification/v1.0/schema.json",
                    "modelVersion": "1.0",
					"id": "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=ea691feb8e4537b9bb5d2b5d5bb984;version=1.0",
                    "name": "Name",
                    "author": "did:work:abcdefghijklmnoprstuv",
                    "authored": "2018-01-01T00:00:00+00:00",
					"proof": {
					  "created": "2019-08-20T20:45:57Z",
		  			  "creator": "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
				      "nonce": "0948bb75-60c2-4a92-ad50-01ccee169ae0",
				      "signatureValue": "2y1ksgsrJSZErLn3p55USFQ7jLBzNjJLsRBfVMFgE5zeSnb1whWxQn2asHdtPMDAiMSYvSnnJenqjWi46Dy7G4ZX",
				      "type": "WorkEd25519Signature2020"
					}
                   }`,
			errorExpected: false,
		},
		{
			name: "invalid ledger metadata version",
			json: `{
                    "type": "https://credentials.workday.com/docs/specification/v1.0/schema.json",
                    "modelVersion": "1.0.0",
					"id": "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=ea691feb8e4537b9bb5d2b5d5bb984;version=1.0",
                    "name": "Name",
                    "author": "did:work:abcdefghijklmnoprstuv",
                    "authored": "2018-01-01T00:00:00+00:00",
					"proof": {
					  "created": "2019-08-20T20:45:57Z",
		  			  "creator": "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
				      "nonce": "0948bb75-60c2-4a92-ad50-01ccee169ae0",
				      "signatureValue": "2y1ksgsrJSZErLn3p55USFQ7jLBzNjJLsRBfVMFgE5zeSnb1whWxQn2asHdtPMDAiMSYvSnnJenqjWi46Dy7G4ZX",
				      "type": "WorkEd25519Signature2020"
					}
                   }`,
			errorExpected: true,
		},
		{
			name: "invalid ledger metadata author",
			json: `{
                    "type": "https://credentials.workday.com/docs/specification/v1.0/schema.json",
                    "modelVersion": "1.0",
					"id": "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=ea691feb8e4537b9bb5d2b5d5bb984;version=1.0",
                    "name": "Name",
                    "author": "did:bad:abcdefghijklmnoprstuv",
                    "authored": "2018-01-01T00:00:00+00:00",
					"proof": {
					  "created": "2019-08-20T20:45:57Z",
		  			  "creator": "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
				      "nonce": "0948bb75-60c2-4a92-ad50-01ccee169ae0",
				      "signatureValue": "2y1ksgsrJSZErLn3p55USFQ7jLBzNjJLsRBfVMFgE5zeSnb1whWxQn2asHdtPMDAiMSYvSnnJenqjWi46Dy7G4ZX",
				      "type": "WorkEd25519Signature2020"
					}
                   }`,
			errorExpected: true,
		},
		{
			name: "invalid ledger metadata date",
			json: `{
                    "type": "https://credentials.workday.com/docs/specification/v1.0/schema.json",
                    "modelVersion": "1.0",
					"id": "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=ea691feb8e4537b9bb5d2b5d5bb984;version=1.0",
                    "name": "Name",
                    "author": "did:work:abcdefghijklmnoprstuv",
                    "authored": "12_april_1993",
					"proof": {
					  "created": "2019-08-20T20:45:57Z",
		  			  "creator": "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
				      "nonce": "0948bb75-60c2-4a92-ad50-01ccee169ae0",
				      "signatureValue": "2y1ksgsrJSZErLn3p55USFQ7jLBzNjJLsRBfVMFgE5zeSnb1whWxQn2asHdtPMDAiMSYvSnnJenqjWi46Dy7G4ZX",
				      "type": "WorkEd25519Signature2020"
					}
                   }`,
			errorExpected: true,
		},
		{
			name: "invalid ledger metadata proof date",
			json: `{
                    "type": "https://credentials.workday.com/docs/specification/v1.0/schema.json",
                    "modelVersion": "1.0",
					"id": "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=ea691feb8e4537b9bb5d2b5d5bb984;version=1.0",
                    "name": "Name",
                    "author": "did:work:abcdefghijklmnoprstuv",
                    "authored": "12_april_1993",
					"proof": {
					  "created": "12_april_2020",
		  			  "creator": "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
				      "nonce": "0948bb75-60c2-4a92-ad50-01ccee169ae0",
				      "signatureValue": "2y1ksgsrJSZErLn3p55USFQ7jLBzNjJLsRBfVMFgE5zeSnb1whWxQn2asHdtPMDAiMSYvSnnJenqjWi46Dy7G4ZX",
				      "type": "WorkEd25519Signature2020"
					}
                   }`,
			errorExpected: true,
		},
		{
			name: "invalid ledger metadata proof - missing nonce (any missing field should fail)",
			json: `{
                    "type": "https://credentials.workday.com/docs/specification/v1.0/schema.json",
                    "modelVersion": "1.0",
					"id": "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=ea691feb8e4537b9bb5d2b5d5bb984;version=1.0",
                    "name": "Name",
                    "author": "did:work:abcdefghijklmnoprstuv",
                    "authored": "2019-08-20T20:45:57Z",
					"proof": {
					  "created": "2019-08-20T20:45:57Z",
		  			  "creator": "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
				      "signatureValue": "2y1ksgsrJSZErLn3p55USFQ7jLBzNjJLsRBfVMFgE5zeSnb1whWxQn2asHdtPMDAiMSYvSnnJenqjWi46Dy7G4ZX",
				      "type": "WorkEd25519Signature2020"
					}
                   }`,
			errorExpected: true,
		},
		{
			name: "invalid ledger metadata missing proof (any missing field should fail)",
			json: `{
                    "type": "https://credentials.workday.com/docs/specification/v1.0/schema.json",
                    "modelVersion": "1.0",
					"id": "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=ea691feb8e4537b9bb5d2b5d5bb984;version=1.0",
                    "name": "Name",
                    "author": "did:work:abcdefghijklmnoprstuv",
                    "authored": "2019-08-20T20:45:57Z",
                   }`,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(t *testing.T) {
			err := Validate(schemaString, testConfig.json)
			if !testConfig.errorExpected {
				if err != nil {
					t.Errorf("Unexpected error: %s, for json: %s", err.Error(), testConfig.json)
				}
			} else {
				assert.Error(t, err, "Expected error but received none for: %s, with data: %s", testConfig.name, testConfig.json)
			}
		})
	}
}

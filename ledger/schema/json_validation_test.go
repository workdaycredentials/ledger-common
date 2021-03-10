package schema

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"go.wday.io/credentials-open-source/ledger-common/credential"
	"go.wday.io/credentials-open-source/ledger-common/credential/schema"
	"go.wday.io/credentials-open-source/ledger-common/did"
	"go.wday.io/credentials-open-source/ledger-common/ledger"
	"go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas"
	"go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas/access"
	"go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas/address"
	"go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas/certification"
	"go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas/course"
	"go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas/education"
	"go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas/email"
	"go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas/employment"
	"go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas/involvement"
	"go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas/name"
	"go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas/payslip"
	"go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas/phonenumber"
	"go.wday.io/credentials-open-source/ledger-common/proof"
)

// This suite of tests tests the validity of different credentials against their JSON SignedMetadata
// This does not ValidateWithJSONLoader anything past what JSON SignedMetadata can ValidateWithJSONLoader. Post-JSON SignedMetadata validations
// Can be found in other tests (in the future). This test also assumes the input is valid JSON SignedMetadata and valid JSON.

// Mainly validates the builder generates valid credentials against the schema
func TestCredentialSchema(t *testing.T) {
	schemaString, err := schema.GetSchema(schema.VerifiableCredentialSchema)
	assert.NoError(t, err)

	testSchema := `{
	  "$schema": "http://json-schema.org/draft-07/schema#",
	  "description": "Name",
	  "type": "object",
	  "properties": {
		"title": {
		  "type": "string"
		},
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
		}
	  },
	  "required": ["firstName", "lastName"],
	  "additionalProperties": false
	 }
	`
	var s ledger.JSONSchemaMap
	if err := json.Unmarshal([]byte(testSchema), &s); err != nil {
		panic(err)
	}

	issuerDoc, pk := ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	signer, err := proof.NewEd25519Signer(pk, issuerDoc.PublicKey[0].ID)
	assert.NoError(t, err)
	ls, err := ledger.GenerateLedgerSchema("Name", issuerDoc.DIDDoc.ID, signer, proof.JCSEdSignatureType, s)
	assert.NoError(t, err)

	baseRevocationURL := "https://testrevocationservice.com/"
	t.Run("happy path cred with expiry", func(t *testing.T) {
		now := time.Now()
		expiry := now.Add(time.Hour * 24)
		credID := uuid.New().String()
		metadata := credential.NewMetadataWithTimestampAndExpiry(credID, issuerDoc.DIDDoc.ID, ls.ID, baseRevocationURL, now, expiry)
		cred, err := credential.Builder{
			SubjectDID: did.DID("did:example:" + credID),
			Data: map[string]interface{}{
				"firstName": "Genghis",
			},
			Metadata:      &metadata,
			Signer:        signer,
			SignatureType: proof.JCSEdSignatureType,
		}.Build()
		assert.NoError(t, err)

		credBytes, err := json.Marshal(cred)
		assert.NoError(t, err)
		assert.NoError(t, Validate(schemaString, string(credBytes)))
	})

	t.Run("happy path cred without expiry", func(t *testing.T) {
		now := time.Now()
		credID := uuid.New().String()
		metadata := credential.NewMetadataWithTimestamp(credID, issuerDoc.DIDDoc.ID, ls.ID, baseRevocationURL, now)
		cred, err := credential.Builder{
			SubjectDID: did.DID("did:example:" + credID),
			Data: map[string]interface{}{
				"firstName": "Genghis",
			},
			Metadata:      &metadata,
			Signer:        signer,
			SignatureType: proof.JCSEdSignatureType,
		}.Build()
		assert.NoError(t, err)

		credBytes, err := json.Marshal(cred)
		assert.NoError(t, err)
		assert.NoError(t, Validate(schemaString, string(credBytes)))
	})

	t.Run("missing metadata", func(t *testing.T) {
		credID := uuid.New().String()
		_, err := credential.Builder{
			SubjectDID: did.DID("did:example:" + credID),
			Data: map[string]interface{}{
				"firstName": "Genghis",
			},
			Signer:        signer,
			SignatureType: proof.JCSEdSignatureType,
		}.Build()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Field validation for 'Metadata' failed")
	})

	t.Run("missing proof", func(t *testing.T) {
		now := time.Now()
		credID := uuid.New().String()
		metadata := credential.NewMetadataWithTimestamp(credID, issuerDoc.DIDDoc.ID, ls.ID, baseRevocationURL, now)
		cred, err := credential.Builder{
			SubjectDID: did.DID("did:example:" + credID),
			Data: map[string]interface{}{
				"bad": "Genghis",
			},
			Metadata:      &metadata,
			Signer:        signer,
			SignatureType: proof.JCSEdSignatureType,
		}.Build()
		assert.NoError(t, err)

		cred.Proof = nil
		credBytes, err := json.Marshal(cred)
		assert.NoError(t, err)
		assert.Error(t, Validate(schemaString, string(credBytes)))
	})
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
					t.Errorf("Unexpected error: %s, for schema: %s", err.Error(), testConfig.json)
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
					t.Errorf("Unexpected error: %s, for schema: %s", err.Error(), testConfig.json)
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
					t.Errorf("Unexpected error: %s, for schema: %s", err.Error(), testConfig.json)
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
					t.Errorf("Unexpected error: %s, for schema: %s", err.Error(), testConfig.json)
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
					t.Errorf("Unexpected error: %s, for schema: %s", err.Error(), testConfig.json)
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
			err := ValidateSchemaRequest(testConfig.document, testConfig.version)
			if !testConfig.errorExpected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestIsJSON(t *testing.T) {
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
	assert.True(t, IsJSON(json))
	assert.True(t, IsJSON(json1))
	assert.True(t, IsJSON(json2))

	notJson := `"abcd": 1234`
	notJson1 := "{abcd}"
	notJson2 := "{abcd: 1324}"
	assert.False(t, IsJSON(notJson))
	assert.False(t, IsJSON(notJson1))
	assert.False(t, IsJSON(notJson2))
}

// Tests validation on ledger metadata for incorrectly formed metadata
func TestLedgerMetadataValidation(t *testing.T) {
	schemaString, err := schemas.GetJSONFile(schemas.LedgerMetadataSchema)
	assert.NoError(t, err)

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
                    "type": "https://credentials.workday.com/docs/specification/v1.0/schema.schema",
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

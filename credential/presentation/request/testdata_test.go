package request

import (
	"go.wday.io/credentials-open-source/ledger-common/credential"
	"go.wday.io/credentials-open-source/ledger-common/credential/presentation"
	"go.wday.io/credentials-open-source/ledger-common/did"
	"go.wday.io/credentials-open-source/ledger-common/proof"
	"go.wday.io/credentials-open-source/ledger-common/util"
)

var proofReqChallengeWithSchemaRange = presentation.CompositeProofRequestInstanceChallenge{
	ProofRequestInstanceID: "93d90cba-eb20-41ca-93ee-2d030dda0b60",
	ProofResponseURL:       "https://responseendppint.com/path",
	ProofRequest: &presentation.CompositeProofRequest{
		ProofReqRespMetadata: presentation.ProofReqRespMetadata{},
		Description:          "Credit card application information",
		Verifier:             "did:work:28RB9jAy9HtVet3zFhdWaM",
		Criteria: []presentation.Criterion{
			{
				Description: "Contact Information",
				Reason:      "Send information regarding your application",
				Issuers: presentation.Issuers{
					DIDs: []did.DID{
						"did:work:PyBScGDehBULWHoZJC7Efk",
						"did:work:W4Qi2D1DpBZig513ztvCFC",
						"did:work:7SWNtygraxEPqNKhuWpw8f",
					},
				},
				MaxRequired: 1,
				MinRequired: 1,
				Schema: presentation.SchemaReq{
					AuthorDID:          "did:work:6xLyHVb7Fzdq5tcou3y3LL",
					ResourceIdentifier: "1234-5678-5432",
					SchemaVersionRange: "^1.1",
					Attributes: []presentation.AttributeReq{
						{
							AttributeName: "emailAddress",
							Required:      true,
						},
					},
				},
			},
		},
	},
}

var proofReqChallenge = `{
    "proofRequestInstanceId": "93d90cba-eb20-41ca-93ee-2d030dda0b60",
    "proofURL": "https://responseendppint.com/path",
    "proofRequest": {
        "description": "Credit card application information",
        "verifier": "did:work:28RB9jAy9HtVet3zFhdWaM",
        "criteria": [
            {
                "description": "Contact Information",
                "reason": "Send information regarding your application",
                "issuers": {
                    "dids": [
                        "did:work:PyBScGDehBULWHoZJC7Efk",
                        "did:work:W4Qi2D1DpBZig513ztvCFC",
                        "did:work:7SWNtygraxEPqNKhuWpw8f"
                    ]
                },
                "max": 1,
                "min": 1,
                "schema": {
                    "id": "did:work:6xLyHVb7Fzdq5tcou3y3LL;id=1234-5678-5432;version=1.1",
                    "attributes": [
                        {
                            "name": "emailAddress",
                            "required": true
                        }
                    ]
                }
            },
            {
                "description": "Billing Address",
                "reason": "Regulations require a billing address",
                "issuers": {
                    "dids": [
                        "did:work:28RB9jAy9HtVet3zFhdWaM",
                        "did:work:LuDnjs3yKyCHGxhmn72TuN",
                        "did:work:7SWNtygraxEPqNKhuWpw8f"
                    ]
                },
                "max": 1,
                "min": 1,
                "schema": {
                    "id": "did:work:DvRUw55c9dDkkHgA2PW2Wi",
                    "attributes": [
                        {
                            "name": "city",
                            "required": true
                        },
                        {
                            "name": "country",
                            "required": true
                        },
                        {
                            "name": "postalCode",
                            "required": true
                        },
                        {
                            "name": "street1",
                            "required": true
                        },
                        {
                            "name": "street2",
                            "required": false
                        }
                    ]
                }
            },
            {
                "description": "6 Months of payslips",
                "reason": "Payslips are used to determin credit worthiness",
                "issuers": {
                    "dids": [
                        "did:work:74Rr1UctAUoXPXfAyAXgav"
                    ]
                },
                "max": 12,
                "min": 6,
                "schema": {
                    "id": "did:work:6BYw7U4u2PBG2u4jfup9Yp",
                    "attributes": [
                        {
                            "name": "currency",
                            "required": true
                        },
                        {
                            "name": "grossPay",
                            "required": true
                        },
                        {
                            "name": "payPeriodEnd",
                            "required": true
                        },
                        {
                            "name": "payPeriodStart",
                            "required": true
                        }
                    ]
                }
            }
        ]
    },
    "proof": {
        "created": "2019-03-28T12:51:22Z",
        "creator": "key-1",
        "nonce": "0abc48d8-925e-42a2-9bc0-a663681cba90",
        "signatureValue": "2wAdfJdtj1V6CW7VgK6VSaZDWaSfDyQpKFcY2rJH8hRae3qDXAndcPLowtsYDNv2aSMm9BphcEArsTAeuKWuxjHG",
        "type": "WorkEd25519Signature2020"
    }
}`

var contactV1Cred = credential.VerifiableCredential{
	Metadata: credential.Metadata{
		ModelVersion: util.Version_1_0,
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		ID:           "422ab006-063e-48f1-91b4-dc09dc512b40",
		Type:         []string{"VerifiableCredential"},
		Issuer:       "did:work:PyBScGDehBULWHoZJC7Efk",
		IssuanceDate: "2019-03-28T11:11:49.456858506Z",
		Schema: credential.Schema{
			ID:   "did:work:6xLyHVb7Fzdq5tcou3y3LL;id=1234-5678-5432;version=1.1",
			Type: "ContactSchema",
		},
	},
	CredentialSubject: map[string]interface{}{"emailAddress": "scott.mangino@crawdad.com", credential.SubjectIDAttribute: "did:work:51wzdn5u7nPp944zpDo7b2"},
	ClaimProofs: map[string]proof.Proof{"emailAddress": {
		Type:               "WorkEd25519Signature2020",
		Created:            "2019-01-21T17:49:18Z",
		VerificationMethod: "did:work:PyBScGDehBULWHoZJC7Efk#key-1",
		Nonce:              "2019-01-21T17:49:18Z",
		SignatureValue:     "Junk1u8jwdwDXjymFDduMJtJVTYWQ5qEz4HhVTjWT9WmEj9wabK1PHwhdRaNqUrD91VADWCBikQPVfH4aVkWRrM",
	},
	},
	Proof: &proof.Proof{
		Type:               "WorkEd25519Signature2020",
		Created:            "2019-01-21T17:49:18Z",
		VerificationMethod: "did:work:PyBScGDehBULWHoZJC7Efk#key-1",
		Nonce:              "18a294fe-376c-4c8d-beaf-ef9b656a98b1",
		SignatureValue:     "Junk2u8jwdwDXjymFDduMJtJVTYWQ5qEz4HhVTjWT9WmEj9wabK1PHwhdRaNqUrD91VADWCBikQPVfH4aVkWRrM",
	},
}

var contactUnversionedCred = `{
    "@context": [
        "https://w3.org/2018/credentials/v1",
        "https://w3id.org/credef/v1"
    ],
    "id": "89b9dc63-2040-49e0-a28c-b0867db86825",
    "type": [
        "VerifiableCredential"
    ],
    "issuerDid": "did:work:PyBScGDehBULWHoZJC7Efk",
    "schemaId": "did:work:6xLyHVb7Fzdq5tcou3y3LL",
    "issuanceDate": "2019-03-28T11:11:49.456858506Z",
    "credentialSubjects": [
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "emailAddress",
            "value": "scott.mangino@crawdad.com",
            "proof": [
                {
                    "created": "2019-03-28T11:11:49Z",
                    "creator": "did:work:7E3rCgprcewWsUeCwGgiar#key-1",
                    "nonce": "ef383cb7-beda-4c63-9eb8-ae35521676d2",
                    "signatureValue": "235qxSEh7G3PdjGo6PkZaS8RXsAqhiXTdkXAK6Gbj6siShimpkomZg7PzAAkGCbpwXKvVaQmfVMQFnsNJoCP1mtH",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        }
    ]
}`

var addressV1Cred = credential.VerifiableCredential{
	Metadata: credential.Metadata{
		ModelVersion: util.Version_1_0,
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		ID:           "422ab006-063e-48f1-91b4-dc09dc512b40",
		Type:         []string{"VerifiableCredential"},
		Issuer:       "did:work:28RB9jAy9HtVet3zFhdWaM",
		IssuanceDate: "2019-03-28T11:11:49.456858506Z",
		Schema: credential.Schema{
			ID:   "did:work:DvRUw55c9dDkkHgA2PW2Wi",
			Type: "AddressSchema",
		},
	},
	CredentialSubject: map[string]interface{}{
		"city":                        "San Francisco",
		"country":                     "United States of America",
		"postalCode":                  "CA 94117",
		"state":                       "California",
		"street1":                     "940 Grove St",
		"street2":                     "Steiner St",
		credential.SubjectIDAttribute: "did:work:51wzdn5u7nPp944zpDo7b2",
	},
	ClaimProofs: map[string]proof.Proof{
		"city": {
			Type:               "WorkEd25519Signature2020",
			Created:            "2019-01-21T17:49:18Z",
			VerificationMethod: "did:work:28RB9jAy9HtVet3zFhdWaM#key-1",
			Nonce:              "badnonce",
			SignatureValue:     "Junk1pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k",
		},
		"country": {
			Type:               "WorkEd25519Signature2020",
			Created:            "2019-01-21T17:49:18Z",
			VerificationMethod: "did:work:28RB9jAy9HtVet3zFhdWaM#key-1",
			Nonce:              "badnonce",
			SignatureValue:     "Junk2pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k",
		},
		"postalCode": {
			Type:               "WorkEd25519Signature2020",
			Created:            "2019-01-21T17:49:18Z",
			VerificationMethod: "did:work:28RB9jAy9HtVet3zFhdWaM#key-1",
			Nonce:              "badnonce",
			SignatureValue:     "Junk3pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k",
		},
		"state": {
			Type:               "WorkEd25519Signature2020",
			Created:            "2019-01-21T17:49:18Z",
			VerificationMethod: "did:work:28RB9jAy9HtVet3zFhdWaM#key-1",
			Nonce:              "badnonce",
			SignatureValue:     "Junk4pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k",
		},
		"street1": {
			Type:               "WorkEd25519Signature2020",
			Created:            "2019-01-21T17:49:18Z",
			VerificationMethod: "did:work:28RB9jAy9HtVet3zFhdWaM#key-1",
			Nonce:              "badnonce",
			SignatureValue:     "Junk5pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k",
		},
		"street2": {
			Type:               "WorkEd25519Signature2020",
			Created:            "2019-01-21T17:49:18Z",
			VerificationMethod: "did:work:28RB9jAy9HtVet3zFhdWaM#key-1",
			Nonce:              "badnonce",
			SignatureValue:     "Junk6pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k",
		},
	},
	Proof: &proof.Proof{
		Type:               "WorkEd25519Signature2020",
		Created:            "2019-01-21T17:49:18Z",
		VerificationMethod: "did:work:28RB9jAy9HtVet3zFhdWaM#key-1",
		SignatureValue:     "Junk4u8jwdwDXjymFDduMJtJVTYWQ5qEz4HhVTjWT9WmEj9wabK1PHwhdRaNqUrD91VADWCBikQPVfH4aVkWRrM",
	},
}

var addressCred1 = `{
    "@context": [
        "https://w3.org/2018/credentials/v1",
        "https://w3id.org/credef/v1"
    ],
    "id": "fc0354fe-2fcb-490e-a8dd-d9074c612015",
    "type": [
        "VerifiableCredential"
    ],
    "issuerDid": "did:work:28RB9jAy9HtVet3zFhdWaM",
    "schemaId": "did:work:DvRUw55c9dDkkHgA2PW2Wi",
    "issuanceDate": "2019-03-28T12:01:03.917967141Z",
    "credentialSubjects": [
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "city",
            "value": "San Francisco",
            "proof": [
                {
                    "created": "2019-03-28T12:01:03Z",
                    "creator": "did:work:Q7HrDT6zn1Eo3nbRxHdZ8F#key-1",
                    "nonce": "499da701-23d1-468c-a000-233b317a62aa",
                    "signatureValue": "4ByfUCiJ4mm25htQnXfWsQ4RWUoRjBA9LbU8fFUh9am1EP6YTizR31VZat2yjWCMXNRHaGE8AseYNWRyEjptf87x",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "country",
            "value": "United States of America",
            "proof": [
                {
                    "created": "2019-03-28T12:01:03Z",
                    "creator": "did:work:Q7HrDT6zn1Eo3nbRxHdZ8F#key-1",
                    "nonce": "20b22b38-c85b-4e6a-80e5-16aed380fc68",
                    "signatureValue": "D4fc9zsF1GxHQ21rMpVAMhQxMwvqaTE2ZD3DravuLysb3D8aMwcz51XAHVGi7m8JMaMffM5hKxNYkaTxHLAgYRz",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "postalCode",
            "value": "CA 94117",
            "proof": [
                {
                    "created": "2019-03-28T12:01:03Z",
                    "creator": "did:work:Q7HrDT6zn1Eo3nbRxHdZ8F#key-1",
                    "nonce": "21d538d8-0fdc-42da-bca8-84002471c9d0",
                    "signatureValue": "5bRGHCJrMUbvnruoqehQsrhrY2WpXboUtTY5YipiZrDGaU1U6x2hRA2AsXehj8w5F3fmDhEZeh4rkrVRnToUpTMQ",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "state",
            "value": "California",
            "proof": [
                {
                    "created": "2019-03-28T12:01:03Z",
                    "creator": "did:work:Q7HrDT6zn1Eo3nbRxHdZ8F#key-1",
                    "nonce": "0e4e517f-dd47-40f0-88e4-33f16693a094",
                    "signatureValue": "2VMu4vwT5urBLgsx769a4gS96C3iTufNp2QPjA7DuNJiu9mjsMZihQqd1NYakPqVNtYZ8qNsYfJnbvs63MXUcFhP",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "street1",
            "value": "940 Grove St",
            "proof": [
                {
                    "created": "2019-03-28T12:01:03Z",
                    "creator": "did:work:Q7HrDT6zn1Eo3nbRxHdZ8F#key-1",
                    "nonce": "ea1e876a-97a4-48e0-8c57-2908b6c1d654",
                    "signatureValue": "2riyQr6ErZof1bJM9AHnSRrFKNBfjzHRJPDhKUNnbEg42WmCAQsVimzB34Sfry3meEUvTikvTKDTRhmavC32tU42",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "street2",
            "value": "Steiner St",
            "proof": [
                {
                    "created": "2019-03-28T12:01:04Z",
                    "creator": "did:work:Q7HrDT6zn1Eo3nbRxHdZ8F#key-1",
                    "nonce": "dc813b8a-3fef-49f1-89da-a8b833c08093",
                    "signatureValue": "5xRnu6hYj72adthQVAgSjqGyCsQjnE8AeLJuQpCfvRa7par1EvfwfgLNNrdSjceFvf2xXaPuPHWeKnh9yMHA5GSL",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        }
    ]
}`

var paySlipV1Cred1 = credential.VerifiableCredential{
	Metadata: credential.Metadata{
		ModelVersion: util.Version_1_0,
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		ID:           "422ab006-063e-48f1-91b4-dc09dc512b40",
		Type:         []string{"VerifiableCredential"},
		Issuer:       "did:work:74Rr1UctAUoXPXfAyAXgav",
		IssuanceDate: "2019-03-28T11:11:49.456858506Z",
		Schema: credential.Schema{
			ID:   "did:work:6BYw7U4u2PBG2u4jfup9Yp",
			Type: "ContactSchema",
		},
	},
	CredentialSubject: map[string]interface{}{"payPeriodStart": "03/01/2019", "currency": "USD", "grossPay": "10000", "netPay": "7000", "payPeriodEnd": "03/31/2019"},
	ClaimProofs: map[string]proof.Proof{
		"payPeriodStart": {
			Type:               "WorkEd25519Signature2020",
			Created:            "2019-01-21T17:49:18Z",
			VerificationMethod: "did:work:PyBScGDehBULWHoZJC7Efk#key-1",
			Nonce:              "anotherbadnonce",
			SignatureValue:     "Junk1pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k",
		},
		"currency": {
			Type:               "WorkEd25519Signature2020",
			Created:            "2019-01-21T17:49:18Z",
			VerificationMethod: "did:work:PyBScGDehBULWHoZJC7Efk#key-1",
			Nonce:              "anotherbadnonce",
			SignatureValue:     "Junk2pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k",
		},
		"grossPay": {
			Type:               "WorkEd25519Signature2020",
			Created:            "2019-01-21T17:49:18Z",
			VerificationMethod: "did:work:PyBScGDehBULWHoZJC7Efk#key-1",
			Nonce:              "anotherbadnonce",
			SignatureValue:     "Junk3pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k",
		},
		"netPay": {
			Type:               "WorkEd25519Signature2020",
			Created:            "2019-01-21T17:49:18Z",
			VerificationMethod: "did:work:PyBScGDehBULWHoZJC7Efk#key-1",
			Nonce:              "anotherbadnonce",
			SignatureValue:     "Junk4pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k",
		},
		"payPeriodEnd": {
			Type:               "WorkEd25519Signature2020",
			Created:            "2019-01-21T17:49:18Z",
			VerificationMethod: "did:work:PyBScGDehBULWHoZJC7Efk#key-1",
			Nonce:              "anotherbadnonce",
			SignatureValue:     "Junk5pHjmMHVHdDsdede7kiQtgf5xuNv7LrdyCmX9kBqfzaJuwC56ZKz9U6DEBtJpGJgCUo9a2VwatXhxzTGJE3k",
		},
	},
	Proof: &proof.Proof{
		Type:               "WorkEd25519Signature2020",
		Created:            "2019-01-21T17:49:18Z",
		VerificationMethod: "did:work:PyBScGDehBULWHoZJC7Efk#key-1",
		SignatureValue:     "Junk4u8jwdwDXjymFDduMJtJVTYWQ5qEz4HhVTjWT9WmEj9wabK1PHwhdRaNqUrD91VADWCBikQPVfH4aVkWRrM",
	},
}

var paySlipCred1 = `{
    "@context": [
        "https://w3.org/2018/credentials/v1",
        "https://w3id.org/credef/v1"
    ],
    "id": "19eded77-da75-44ee-a364-6ad41ff1a6fc",
    "type": [
        "VerifiableCredential"
    ],
    "issuerDid": "did:work:74Rr1UctAUoXPXfAyAXgav",
    "schemaId": "did:work:6BYw7U4u2PBG2u4jfup9Yp",
    "issuanceDate": "2019-03-28T12:21:03.8779344Z",
    "credentialSubjects": [
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "payPeriodStart",
            "value": "03/01/2019",
            "proof": [
                {
                    "created": "2019-03-28T12:21:03Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "f6cea3a2-be62-4c8d-9131-b36a3da0c878",
                    "signatureValue": "4mPKJmaQE6NgBRvMwhG1yqkaQLSYL4MYgFG2uvHSZEuR76BPL21K5ErGPMocKyKJStGkBQvYHRfxLEwXDT9g1vGx",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "currency",
            "value": "USD",
            "proof": [
                {
                    "created": "2019-03-28T12:21:03Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "a685ca2f-29e3-4dfa-9916-19baf979f06d",
                    "signatureValue": "56472tFJvDdd4Ec3ADCNgcbhh9SJNcyZAtGLSLiz6tvKmpRjtzPDFPYN7Cdf3DxbYBHP8F7xfMvXSMconbm9zwaA",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "grossPay",
            "value": "10000",
            "proof": [
                {
                    "created": "2019-03-28T12:21:03Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "bde81ee7-d7af-45ee-93bb-5d59d6534583",
                    "signatureValue": "2ArHDuXLaQjijGdGQ6UqJVFjoGA2oiiz9pfZiNuRqpKcH3Vz6Rx6odDsuSGJXbdYW4F87WY9byH4C6kooj23Bd1f",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "netPay",
            "value": "7000",
            "proof": [
                {
                    "created": "2019-03-28T12:21:03Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "144be046-dded-455e-91f3-eb0571931940",
                    "signatureValue": "4FgdAyyqGgV2Mkwf2hTDCccgGKrtY3Z3Cx33UfnXyBmQAwvePCpcVRZi4u4fd2Ys1nGaFMNseH8owo2tYFJMftA7",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "payPeriodEnd",
            "value": "03/31/2019",
            "proof": [
                {
                    "created": "2019-03-28T12:21:03Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "9f45d41e-49de-4730-9feb-16744e24573f",
                    "signatureValue": "65JD3ioYYvN7YDvf4CiSbCLKcZ2GVP6LeCRqRYMrs1hS5VcQRgRiLmAJFWGvJqksLZRZkrUFMtqDqVGE3dXxEXMN",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        }
    ]
}`

var paySlipCred2 = `{
    "@context": [
        "https://w3.org/2018/credentials/v1",
        "https://w3id.org/credef/v1"
    ],
    "id": "f619a47a-73f0-49b4-a654-f79e0edc22a5",
    "type": [
        "VerifiableCredential"
    ],
    "issuerDid": "did:work:74Rr1UctAUoXPXfAyAXgav",
    "schemaId": "did:work:6BYw7U4u2PBG2u4jfup9Yp",
    "issuanceDate": "2019-03-28T12:21:43.599648533Z",
    "credentialSubjects": [
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "payPeriodStart",
            "value": "02/01/2019",
            "proof": [
                {
                    "created": "2019-03-28T12:21:43Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "329fac15-e073-4906-88d2-0b4d5c860783",
                    "signatureValue": "KFiJ6ke3NJUojMry45PSsm1M37fUzejYxsBxno9DfXPD4VMpbqxAuEb6qjs2irBf8oE9FgcqRTSLqZYDazEUvCt",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "currency",
            "value": "USD",
            "proof": [
                {
                    "created": "2019-03-28T12:21:43Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "03c5960c-d192-4a6b-92a6-9831387f2d80",
                    "signatureValue": "3ucbvvCLJoJuVJoJQ5DX34JshZVmde5nMcEF3Dh5das9ZcJh5EZREcuaCNjJhzSkdtbLJh9yiNN639LiMr8MjZYC",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "grossPay",
            "value": "10000",
            "proof": [
                {
                    "created": "2019-03-28T12:21:43Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "d30af0fa-955a-471b-931d-2b4aa74af201",
                    "signatureValue": "4JuzZha27XGhQFCfsP5o8qhMpzFG3BgASga6syjomfWHmuMXKkGERSqLb9BTvuq9WMDPs146xQEA468KyR44qfTz",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "netPay",
            "value": "7000",
            "proof": [
                {
                    "created": "2019-03-28T12:21:43Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "15f5fc4f-7b6a-4b29-bdad-7761fc6da45d",
                    "signatureValue": "3hS2bQzPKS6TQSN3Vey8BL9Vg4fRqigFBddv2TduGCGD1uE9u6DUNtsesw6WVcm5RrktQpAFAGJGETcwSo7ebDXo",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "payPeriodEnd",
            "value": "02/28/2019",
            "proof": [
                {
                    "created": "2019-03-28T12:21:43Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "d90d85dc-fb98-4841-bdba-81b5c5e45396",
                    "signatureValue": "2TAfSscC83MyWUWgTWwrnGUMucco86MiB43T9Mmo7EQRM6dre8gLVXZUzQMfcDgNxTDrpXYVZhHEZz6Z5SxHfKzB",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        }
    ]
}`

var paySlipCred3 = `{
    "@context": [
        "https://w3.org/2018/credentials/v1",
        "https://w3id.org/credef/v1"
    ],
    "id": "124c77ab-e3f8-4463-bd3d-fa834ddc4012",
    "type": [
        "VerifiableCredential"
    ],
    "issuerDid": "did:work:74Rr1UctAUoXPXfAyAXgav",
    "schemaId": "did:work:6BYw7U4u2PBG2u4jfup9Yp",
    "issuanceDate": "2019-03-28T12:22:01.698664972Z",
    "credentialSubjects": [
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "payPeriodStart",
            "value": "01/01/2019",
            "proof": [
                {
                    "created": "2019-03-28T12:22:01Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "316aa33c-0f80-4a93-aa32-63664e1b654a",
                    "signatureValue": "41GjKDfzHuP4j9DyMLD7qEze5U3VBYfCpQfz14CcMZPMsxJbr4j8MxxeougadotbjtdcrPdQhoh5LaeCahgCYuZF",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "currency",
            "value": "USD",
            "proof": [
                {
                    "created": "2019-03-28T12:22:01Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "d237e7e8-0872-420c-bce1-cd77975b1040",
                    "signatureValue": "UfQTcNnyxPHUqF764QufU2EzDKHkQH4F7uyXWH3fJhV7cqNpcrooRJ4cdCEhbLMwHe3t57PrDDj43NHvafPW653",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "grossPay",
            "value": "10000",
            "proof": [
                {
                    "created": "2019-03-28T12:22:01Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "bdc0f032-7938-40db-9d9f-a8e842fe4b21",
                    "signatureValue": "UVZfZhXg3AX5o2iTKRmPx9vWq7jTTJuWTz1hjmvYdyufsiQk8hnGunquoe3Wz8MxBTdR2hZ3xvQ8FvpQ4mY1gNK",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "netPay",
            "value": "7000",
            "proof": [
                {
                    "created": "2019-03-28T12:22:01Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "823ff433-3ac6-4157-b82d-48b9f568015c",
                    "signatureValue": "4dbXnkeujcUU19QQ4XGZ2LZb6GS8srG7iCmRLJQvT61q2xs8WfhVaxgnPL9kSPoy1dVtWYwqC4nXx7ax7QALnXhc",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "payPeriodEnd",
            "value": "01/31/2019",
            "proof": [
                {
                    "created": "2019-03-28T12:22:01Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "0e5e29f3-ebcf-49ea-b250-861daa9fab25",
                    "signatureValue": "y7Z38yJE33R6so5pwVGKgAExQ2emWKeTcv9fC6JiETFXaFojsngyM3AAyVHe1pKizL9oQkfGuaXAQL9UkNRSXY5",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        }
    ]
}`

var paySlipCred4 = `{
    "@context": [
        "https://w3.org/2018/credentials/v1",
        "https://w3id.org/credef/v1"
    ],
    "id": "8c0abd3a-c32f-4c4f-ae1f-f5471d817316",
    "type": [
        "VerifiableCredential"
    ],
    "issuerDid": "did:work:74Rr1UctAUoXPXfAyAXgav",
    "schemaId": "did:work:6BYw7U4u2PBG2u4jfup9Yp",
    "issuanceDate": "2019-03-28T12:22:40.039194475Z",
    "credentialSubjects": [
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "payPeriodStart",
            "value": "12/01/2018",
            "proof": [
                {
                    "created": "2019-03-28T12:22:40Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "445cbdea-506b-4a40-a4a4-3fd805d6ca3e",
                    "signatureValue": "4YFM7Te3aHSYbqp6KAALgmg8yT7Sr9ELVvZ47p6MH8PaBg8CUVRtsFUqFpJ8GFMVi3614BwsbRzdAxwN66U8cEjm",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "currency",
            "value": "USD",
            "proof": [
                {
                    "created": "2019-03-28T12:22:40Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "b0e418cd-c987-46d4-8d37-08200fcb2a78",
                    "signatureValue": "5vYbk1Dz2vFYxPserv3AnVcLw6BdWRFAzVekvmWqnGUrzKNJcyPSfwNgmsFXkHueVybPvL5JhUV4ANnF32vRcYnd",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "grossPay",
            "value": "10000",
            "proof": [
                {
                    "created": "2019-03-28T12:22:40Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "f7af8690-27b1-43a6-b16a-6b4af5433e25",
                    "signatureValue": "2PWbvjZjA63wvRPbSdzNt96QDU4tHn9cUnHHnmwEDRzN3P9kKcMHbwSD2ePAACefL9QxqZxRfoJMFHWSvFszAr55",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "netPay",
            "value": "7000",
            "proof": [
                {
                    "created": "2019-03-28T12:22:40Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "7022ff06-a14e-4b7e-8652-a8ffdb3a19df",
                    "signatureValue": "2jpcxyPyPr3SMqFoas5MAxpfoPoYvgWd17MooAxEgW2FR8PsGzPLmxt8NJXqe82WNtMJwsThdrhebXTcL62Z9zG5",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "payPeriodEnd",
            "value": "12/31/2018",
            "proof": [
                {
                    "created": "2019-03-28T12:22:40Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "d58807af-379b-43da-9278-da984aefdc8f",
                    "signatureValue": "3zP1sTeeicPMLqrWNk1aGvaK6H5YB1bWHriyGz7wBRkxzMKDnUMwJASpVJrRZgsGtRqmafScuoY46k7RVE5HxqDr",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        }
    ]
}`

var paySlipCred5 = `{
    "@context": [
        "https://w3.org/2018/credentials/v1",
        "https://w3id.org/credef/v1"
    ],
    "id": "00d2083d-1c2a-4b43-ac71-1b034fc77188",
    "type": [
        "VerifiableCredential"
    ],
    "issuerDid": "did:work:74Rr1UctAUoXPXfAyAXgav",
    "schemaId": "did:work:6BYw7U4u2PBG2u4jfup9Yp",
    "issuanceDate": "2019-03-28T12:23:01.018620809Z",
    "credentialSubjects": [
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "payPeriodEnd",
            "value": "11/31/2018",
            "proof": [
                {
                    "created": "2019-03-28T12:23:01Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "28d3aaef-592a-405b-81ca-dbb0e58a797a",
                    "signatureValue": "5FGtZoRBX1NZYsNhky5859nHDNjYuFNv5iEdYo7rQ1nHASgmuZSV6qF8uyQPaREcfe7ywYan55YN72CnnJn2uLnR",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "payPeriodStart",
            "value": "11/01/2018",
            "proof": [
                {
                    "created": "2019-03-28T12:23:01Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "72df7c4a-a82f-4aee-812f-b010fb3b6402",
                    "signatureValue": "MEdQmDiX7npF2Rpmhw7aXc8tLosyC93U4KJ9XSz2wbdcg3bhKGh4RZqhxpntKu9yJBz2fs4gzc3eoVdwSkDMLiJ",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "currency",
            "value": "USD",
            "proof": [
                {
                    "created": "2019-03-28T12:23:01Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "02f88ba8-2816-4239-8f4c-cdeae8e13be3",
                    "signatureValue": "3gZ1VaSaabEmKHrFZRi7YBpVeZGd9XiEha38zJgf5ukjkruSJMHa2PPqf4NgvEHasDbWxa3wPYGTStiP8a8zdENh",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "grossPay",
            "value": "10000",
            "proof": [
                {
                    "created": "2019-03-28T12:23:01Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "eb2e4a41-fdd6-49a7-a3c9-df39af5e6c4a",
                    "signatureValue": "4hDuvSA9wwysVmyPvFr4vnsDrtLbdDhKXxyYTf9JX4kNNTSkWXGPY81gkkNCu12dGheyJBXQDXKRQh6DXY3F45Ph",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "netPay",
            "value": "7000",
            "proof": [
                {
                    "created": "2019-03-28T12:23:01Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "0f5617e7-770e-47f5-a705-f0c4623874bf",
                    "signatureValue": "47gWL7ugtFezyyXWrNchMavri1cAfN7f6EUFQziLhKj2wkpfawVmEeH24Dc5pqBpTLmjvVY9gW38U65L4dpjGvb5",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        }
    ]
}`

var paySlipCred6 = `{
    "@context": [
        "https://w3.org/2018/credentials/v1",
        "https://w3id.org/credef/v1"
    ],
    "id": "4ecaa5f5-c370-4422-8610-0b76334fc824",
    "type": [
        "VerifiableCredential"
    ],
    "issuerDid": "did:work:74Rr1UctAUoXPXfAyAXgav",
    "schemaId": "did:work:6BYw7U4u2PBG2u4jfup9Yp",
    "issuanceDate": "2019-03-28T12:23:17.537761601Z",
    "credentialSubjects": [
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "netPay",
            "value": "7000",
            "proof": [
                {
                    "created": "2019-03-28T12:23:17Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "fd0808bc-8a8a-4595-8b0a-47859c88bc21",
                    "signatureValue": "2jjXXN2CMKFwRfTSJNitpsnMjuFEe8zCfeB1D28fevLznSDyXcqmxDhKg5zZeq4J8pkWw6Ep7RxinCERkmgxCwBd",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "payPeriodEnd",
            "value": "10/31/2018",
            "proof": [
                {
                    "created": "2019-03-28T12:23:17Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "fb394f2f-bdb8-43e7-9bc7-797a9f9a01f9",
                    "signatureValue": "4rdZe1L9dxBMP9BCZrR1wH1aWydhPRnnGfmHKVNaUvsuACAWEcptCWrdwad8PsNNVgb36EBh6fTH8E37C2i9vp27",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "payPeriodStart",
            "value": "10/01/2018",
            "proof": [
                {
                    "created": "2019-03-28T12:23:17Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "3c40c1fe-43c4-4abc-bb83-c3d49415b7d6",
                    "signatureValue": "2UFxCfnxZxqh5MzTePg9VtkPSUn9Fbf5vCZHJykrKReQsF2Z1C1GSXDJt2uy1TTn6NWbawYScwK5aoH2DYFKVkXh",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "currency",
            "value": "USD",
            "proof": [
                {
                    "created": "2019-03-28T12:23:17Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "06130eeb-02e7-49bb-ac50-b179a96d36e2",
                    "signatureValue": "32aEfEPLJAjx1KMJcKgGCpiDbNKsTbELiB1YmPnaoNSKgPdPLrMrcHPkQtzUmBUs4sLTg2Uysd5C9DS96ee4tfov",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        },
        {
            "id": "did:work:VUVK144CrtiJiZJH85Fntc",
            "key": "grossPay",
            "value": "10000",
            "proof": [
                {
                    "created": "2019-03-28T12:23:17Z",
                    "creator": "did:work:KN1NxycqCUgeN2Kp8a3rMg#key-1",
                    "nonce": "d5b33215-c8c9-4675-9429-b699c1930c9f",
                    "signatureValue": "HvvWQAVXFo7J6AppeUJJTfxcvEZTyTXE4fHnbzg1J6EcVAyafcZyfFkuLiLKrkgnVx9ohGn8vskW1XW2Rd25qWA",
                    "type": "WorkEd25519Signature2020"
                }
            ]
        }
    ]
}`

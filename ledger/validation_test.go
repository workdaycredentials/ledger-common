package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

// DID //

func TestValidateDIDDoc(t *testing.T) {
	ledgerDIDDoc, _ := GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	provider := TestDIDDocProvider{map[string]*DIDDoc{ledgerDIDDoc.Metadata.ID: ledgerDIDDoc}}
	assert.NoError(t, ledgerDIDDoc.Validate(context.Background(), provider.GetDIDDoc))
}

func TestValidateDeactivatedDIDDoc(t *testing.T) {
	ledgerDIDDoc, _ := GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	assert.Error(t, ledgerDIDDoc.ValidateDeactivated())

	ledgerDIDDoc.PublicKey = nil
	assert.NoError(t, ledgerDIDDoc.ValidateDeactivated())
}

func TestValidateDIDDocStatic(t *testing.T) {
	ledgerDIDDoc, _ := GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	assert.NoError(t, ledgerDIDDoc.ValidateStatic())
}

func TestValidateDID(t *testing.T) {
	assert.NoError(t, ValidateDID("did:work:NozwAq71nnDdNimgqmktei"))
	assert.Error(t, ValidateDID("did:example:NozwAq71nnDdNimgqmktei"), "bad did method")
	assert.Error(t, ValidateDID("did:work:NozwAq71nnDdNim"), "too short")
}

func TestValidateDIDMetadata(t *testing.T) {
	doc := DIDDoc{
		Metadata: &Metadata{
			ID:           "notempty",
			Type:         util.DIDDocTypeReference_v1_0,
			ModelVersion: util.Version_1_0,
		},
		DIDDoc: &did.DIDDoc{
			ID: "notempty",
		},
	}
	assert.NoError(t, doc.ValidateMetadata())

	doc1 := DIDDoc{
		Metadata: &Metadata{
			Type:         util.DIDDocTypeReference_v1_0,
			ModelVersion: util.Version_1_0,
		},
		DIDDoc: &did.DIDDoc{
			ID: "notempty",
		},
	}
	assert.EqualError(t, doc1.ValidateMetadata(), "invalid ID: notempty")

	doc2 := DIDDoc{
		Metadata: &Metadata{
			ID:           "notempty",
			Type:         "wrong type",
			ModelVersion: "1.0",
		},
		DIDDoc: &did.DIDDoc{
			ID: "notempty",
		},
	}
	assert.EqualError(t, doc2.ValidateMetadata(), "invalid type: wrong type")

	doc3 := DIDDoc{
		Metadata: &Metadata{
			ID:           "notempty",
			Type:         util.DIDDocTypeReference_v1_0,
			ModelVersion: "0.1",
		},
		DIDDoc: &did.DIDDoc{
			ID: "notempty",
		},
	}
	assert.EqualError(t, doc3.ValidateMetadata(), "invalid modelVersion: 0.1")
}

func TestValidateDIDDocProof(t *testing.T) {
	ledgerDIDDoc, _ := GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	assert.NoError(t, ledgerDIDDoc.ValidateProof())

	provider := TestDIDDocProvider{Records: map[string]*DIDDoc{didDoc.Metadata.ID: didDoc}}
	assert.NoError(t, didDoc.Validate(context.Background(), provider.GetDIDDoc))

	// set the signature to a random value
	ledgerDIDDoc.DIDDoc.Proof.SignatureValue = "4Y4dfA7qXvSBa9YETYSkAQdQEsCrz29HMAPjbedF9iJMEKCXWcsqkuad2Rz2SqnfdGMbnUvVyDyESPBVQh8WHRx8"
	assert.Error(t, ledgerDIDDoc.ValidateProof())
}

func TestValidateDIDDocProofSecp256k1(t *testing.T) {
	secp256k1DIDDoc := `{
        "type": "https://credentials.workday.com/docs/specification/v1.0/did-doc.json",
        "modelVersion": "1.0",
        "id": "did:work:6yC74B5q8GzAWJENN6y5S2",
        "author": "did:work:6yC74B5q8GzAWJENN6y5S2",
        "authored": "2020-03-27T18:02:36Z",
        "proof": {
            "created": "2020-03-27T18:02:36Z",
            "creator": "did:work:6yC74B5q8GzAWJENN6y5S2#key-1",
            "nonce": "48101b4b-be0e-4faf-8389-21d4aaccdb2e",
            "signatureValue": "381yXYu6qKSap63grMufCcwtXYjkT5tRGcu2zUQZp7x3K2Q7HWiiQiLtGDJp82p6MTEm2vbKRhLhb6qLCb18qka3htZXah7j",
            "type": "EcdsaSecp256k1Signature2019"
        },
        "didDoc": {
            "id": "did:work:6yC74B5q8GzAWJENN6y5S2",
            "publicKey": [
                {
                    "id": "did:work:6yC74B5q8GzAWJENN6y5S2#key-1",
                    "type": "EcdsaSecp256k1VerificationKey2019",
                    "controller": "did:work:6yC74B5q8GzAWJENN6y5S2",
                    "publicKeyBase58": "PZ8Tyr4Nx8MHsRAGMpZmZ6TWY63dXWSCyvU4i1s2kuZSNc7Q3s2mgyztPmZEe1633ogwMYUt7vwLtitTc5LfYF4CJxdNiEso3XuJwx4SqoBoGRoa9ynZCMaS"
                }
            ],
            "authentication": null,
            "service": null,
            "proof": {
                "created": "2020-03-27T18:02:36Z",
                "creator": "did:work:6yC74B5q8GzAWJENN6y5S2#key-1",
                "nonce": "170f7203-9cfc-4bf8-9215-e84d49ccd586",
                "signatureValue": "iKx1CJMH89jD3DC5GieSvkeDFkjWQRGuaN4hk1XNwv3JvAT69RE1CjshukeqxQuEcCJt81rKWvFCUL3UDE2gq79HNaqXhArgre",
                "type": "EcdsaSecp256k1Signature2019"
            }
        }
    }`

	var ledgerDIDDoc DIDDoc
	err := json.Unmarshal([]byte(secp256k1DIDDoc), &ledgerDIDDoc)
	require.NoError(t, err)

	err = ledgerDIDDoc.ValidateProof()
	assert.NoError(t, err)
}

func TestValidateDIDUniqueness(t *testing.T) {
	doc1, _ := GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	doc2, _ := GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	provider := TestDIDDocProvider{map[string]*DIDDoc{doc2.Metadata.ID: doc2}}

	// no existing record
	assert.NoError(t, doc1.ValidateUniqueness(context.Background(), provider.GetDIDDoc))

	// same as existing record to simulate retrying a registration
	assert.NoError(t, doc2.ValidateUniqueness(context.Background(), provider.GetDIDDoc))

	// deep copy doc2
	var copy DIDDoc
	assert.NoError(t, util.DeepCopy(doc2, &copy))

	// mutate the record
	provider.Records[doc2.Metadata.ID].DIDDoc.Proof.VerificationMethod = "did:work:0000000000000000"

	// attempting to publish a doc that's different from an existing record
	// simulates a DID collision.
	assert.Error(t, copy.ValidateUniqueness(context.Background(), provider.GetDIDDoc))
}

type TestDIDDocProvider struct {
	Records map[string]*DIDDoc
}

func (t TestDIDDocProvider) GetDIDDoc(_ context.Context, id did.DID) (*DIDDoc, error) {
	if record, ok := t.Records[id.String()]; ok {
		return record, nil
	}
	return nil, fmt.Errorf("did<%s> not found", id)
}

// Revocation //

const (
	CredentialID  = "36abc9d6-b363-44c3-81f0-9d28ecbec2be"
	CredentialID2 = "63def9d6-b363-44c3-81f0-9d28ecbec2be"
)

var (
	ctx             = context.Background()
	keyType         = proof.Ed25519KeyType
	didDoc, privKey = GenerateLedgerDIDDoc(keyType, proof.JCSEdSignatureType)
	keyRef          = didDoc.PublicKey[0].ID
	signer, _       = proof.NewEd25519Signer(privKey, keyRef)
	r, _            = GenerateLedgerRevocation(CredentialID, didDoc.DIDDoc.ID, signer, proof.JCSEdSignatureType)
)

func TestValidateRevocation(t *testing.T) {
	provider := RevTestProvider{
		DIDs:        map[string]*DIDDoc{didDoc.Metadata.ID: didDoc},
		Revocations: map[string]*Revocation{r.UnsignedRevocation.ID: r},
	}
	ledgerProvider := BuildRevTestLedgerProvider(provider)
	assert.NoError(t, r.Validate(ctx, ledgerProvider))
}

func TestValidateRevocations(t *testing.T) {
	didDoc2, privKey2 := GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	keyRef2 := didDoc2.PublicKey[0].ID

	signer, err := proof.NewEd25519Signer(privKey2, keyRef2)
	assert.NoError(t, err)

	revocation2, err := GenerateLedgerRevocation(CredentialID2, didDoc2.DIDDoc.ID, signer, proof.JCSEdSignatureType)
	assert.NoError(t, err)

	provider := RevTestProvider{
		DIDs:        map[string]*DIDDoc{didDoc.Metadata.ID: didDoc, didDoc2.Metadata.ID: didDoc2},
		Revocations: map[string]*Revocation{r.UnsignedRevocation.ID: r, revocation2.UnsignedRevocation.ID: revocation2},
	}
	ledgerProvider := BuildRevTestLedgerProvider(provider)
	assert.NoError(t, ValidateRevocations(ctx, []Revocation{*r, *revocation2}, ledgerProvider))
}

func TestValidateRevocationStatic(t *testing.T) {
	assert.NoError(t, r.ValidateStatic())
}

func Test_validateRevocationKey(t *testing.T) {
	assert.NoError(t, r.ValidateKey())

	var newRevocation Revocation
	assert.NoError(t, util.DeepCopy(r, &newRevocation))

	// Change the id
	newRevocation.Metadata.ID = "bad"
	newRevocation.UnsignedRevocation.ID = "really bad"
	assert.Error(t, newRevocation.ValidateKey())
}

func Test_validateRevocationMetadata(t *testing.T) {
	var newRevocation Revocation
	assert.NoError(t, util.DeepCopy(r, &newRevocation))

	assert.NoError(t, r.ValidateMetadata())

	// make it bad
	newRevocation.Metadata.ModelVersion = "-1"
	newRevocation.Metadata.Type = util.SchemaTypeReference_v1_0
	assert.Error(t, newRevocation.ValidateMetadata())
}

func Test_validateRevocationProof(t *testing.T) {
	var newRevocation Revocation
	assert.NoError(t, util.DeepCopy(r, &newRevocation))

	provider := RevTestProvider{
		DIDs:        map[string]*DIDDoc{didDoc.Metadata.ID: didDoc},
		Revocations: map[string]*Revocation{r.UnsignedRevocation.ID: r},
	}
	ledgerProvider := BuildRevTestLedgerProvider(provider)

	assert.NoError(t, newRevocation.ValidateProof(ctx, ledgerProvider.DIDDocProvider))

	// make it bad
	newRevocation.Proof.Nonce = uuid.New().String()
	assert.Error(t, newRevocation.ValidateProof(ctx, ledgerProvider.DIDDocProvider))
}

func Test_validateRevocationUniqueness(t *testing.T) {
	provider := RevTestProvider{
		DIDs:        map[string]*DIDDoc{didDoc.Metadata.ID: didDoc},
		Revocations: map[string]*Revocation{r.UnsignedRevocation.ID: r},
	}
	ledgerProvider := BuildRevTestLedgerProvider(provider)

	assert.NoError(t, r.ValidateUniqueness(ctx, ledgerProvider.RevocationProvider))

	// same revocation with different id
	var copy Revocation
	assert.NoError(t, util.DeepCopy(r, &copy))
	provider.Revocations[r.UnsignedRevocation.ID].Author = did.DID("did:work:badbadbad")

	// Collision on id
	assert.Error(t, copy.ValidateUniqueness(ctx, ledgerProvider.RevocationProvider))
}

type RevTestProvider struct {
	DIDs        map[string]*DIDDoc
	Revocations map[string]*Revocation
}

func BuildRevTestLedgerProvider(t RevTestProvider) Provider {
	GetDIDDoc := func(ctx context.Context, id did.DID) (*DIDDoc, error) {
		if record, ok := t.DIDs[id.String()]; ok {
			return record, nil
		}
		return nil, fmt.Errorf("did<%s> not found", id)
	}
	GetSchema := func(ctx context.Context, id string) (*Schema, error) {
		return nil, nil
	}
	GetRevocation := func(ctx context.Context, credentialID, revocationID string) (*Revocation, error) {
		if record, ok := t.Revocations[revocationID]; ok {
			return record, nil
		}
		return nil, fmt.Errorf("revocation<%s> not found", revocationID)
	}
	return Provider{SchemaProvider: GetSchema, RevocationProvider: GetRevocation, DIDDocProvider: GetDIDDoc}
}

// Schema //

var (
	testSchema = `{
	  "$schema": "http://json-schema.org/draft-07/schema#",
	  "description": "Name",
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
	s = generateSchema(*didDoc.DIDDoc, privKey)
)

func TestValidateSchema(t *testing.T) {
	provider := SchemaTestProvider{
		DIDs:    map[string]*DIDDoc{didDoc.Metadata.ID: didDoc},
		Schemas: map[string]*Schema{s.ID: s},
	}
	ledgerProvider := BuildSchemaTestLedgerProvider(provider)

	assert.NoError(t, s.Validate(ctx, ledgerProvider))
}

func TestValidateSchemaStatic(t *testing.T) {
	assert.NoError(t, s.ValidateStatic())
}

func Test_validateSchemaID(t *testing.T) {
	assert.NoError(t, ValidateSchemaID(s.ID))

	// copy + make it ion
	var copy Schema
	assert.NoError(t, util.DeepCopy(s, &copy))

	copy.ID = strings.Replace(s.ID, "did:work", "did:ion:test", 1)
	assert.NoError(t, ValidateSchemaID(copy.ID))

	// make it bad
	copy.ID = "badbadrealbad"
	assert.Error(t, ValidateSchemaID(copy.ID))
}

func Test_validateSchemaMetadata(t *testing.T) {
	assert.NoError(t, s.ValidateMetadata())

	// copy + make it bad
	var copy Schema
	assert.NoError(t, util.DeepCopy(s, &copy))

	copy.ID = "superbad"
	assert.Error(t, ValidateSchemaID(copy.ID))
}

func Test_validateSchemaProof(t *testing.T) {
	provider := SchemaTestProvider{
		DIDs: map[string]*DIDDoc{didDoc.Metadata.ID: didDoc},
	}
	ledgerProvider := BuildSchemaTestLedgerProvider(provider)

	assert.NoError(t, s.ValidateProof(ctx, ledgerProvider.DIDDocProvider))

	// copy + make it bad
	var copy Schema
	assert.NoError(t, util.DeepCopy(s, &copy))

	copy.ID = "badlybad"
	assert.Error(t, copy.ValidateProof(ctx, ledgerProvider.DIDDocProvider))
}

func Test_validateSchemaUniqueness(t *testing.T) {
	provider := SchemaTestProvider{
		DIDs:    map[string]*DIDDoc{didDoc.Metadata.ID: didDoc},
		Schemas: map[string]*Schema{s.ID: s},
	}
	ledgerProvider := BuildSchemaTestLedgerProvider(provider)

	assert.NoError(t, s.ValidateUniqueness(ctx, ledgerProvider.SchemaProvider))

	// same schema with different author
	var copy Schema
	assert.NoError(t, util.DeepCopy(s, &copy))
	provider.Schemas[s.ID].Author = "wasntme"

	// Collision on id
	assert.Error(t, copy.ValidateUniqueness(ctx, ledgerProvider.SchemaProvider))
}

type SchemaTestProvider struct {
	DIDs    map[string]*DIDDoc
	Schemas map[string]*Schema
}

func BuildSchemaTestLedgerProvider(t SchemaTestProvider) Provider {
	GetDIDDoc := func(ctx context.Context, id did.DID) (*DIDDoc, error) {
		if record, ok := t.DIDs[id.String()]; ok {
			return record, nil
		}
		return nil, fmt.Errorf("did<%s> not found", id)
	}
	GetSchema := func(ctx context.Context, id string) (*Schema, error) {
		if record, ok := t.Schemas[id]; ok {
			return record, nil
		}
		return nil, fmt.Errorf("schema<%s> not found", id)
	}
	GetRevocation := func(ctx context.Context, credentialID, revocationID string) (*Revocation, error) {
		return nil, nil
	}
	return Provider{SchemaProvider: GetSchema, RevocationProvider: GetRevocation, DIDDocProvider: GetDIDDoc}
}

func generateSchema(didDoc did.DIDDoc, privKey ed25519.PrivateKey) *Schema {
	var s JSONSchemaMap
	if err := json.Unmarshal([]byte(testSchema), &s); err != nil {
		panic(err)
	}
	signer, err := proof.NewEd25519Signer(privKey, didDoc.PublicKey[0].ID)
	if err != nil {
		panic(err)
	}
	schema, err := GenerateLedgerSchema("Name", didDoc.ID, signer, proof.JCSEdSignatureType, s)
	if err != nil {
		panic(err)
	}
	return schema
}

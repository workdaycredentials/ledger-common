package ledger

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

const (
	pubKeyB64 = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEskkOL4FWlPT6lvfNRen0TU6d6LtzbAnSuTZv0j5Ey1X9jj+TB6kckk8QVBrSIB1D83w2W7ABAnJkLnyomNCUOw=="
)

var (
	keySeed       = []byte("12345678901234567890123456789012")
	issuerPrivKey = ed25519.NewKeyFromSeed(keySeed) // this matches the public key in didDocJson
	issuerPubKey  = issuerPrivKey.Public().(ed25519.PublicKey)
)

func TestSignatureOfGeneratedLedgerDIDDoc(t *testing.T) {
	id := "did:work:9999999999999"

	unsignedDIDDoc := did.UnsignedDIDDoc{
		SchemaContext: "https://w3id.org/did/v1",
		ID:            id,
		PublicKey:     []did.KeyDef{},
	}

	p := proof.Proof{
		Created:        "2020-03-12T10:19:26Z",
		Creator:        "did:work:123456789012345#key-1",
		Nonce:          "c04d4351-8fa3-4b23-8096-6ad5821f806b",
		SignatureValue: "AN1rKpdgkGvZ68kvZ3upDgUyMU4JBJFMwc3DRetqHfx4FDvNF8Zd1ZkDoNF7SqdHHJ5LEdC3Mtrb73GayjG3MQZ8HJHSVFjUc",
		Type:           "EcdsaSecp256k1VerificationKey2019",
	}

	docBytes, err := canonical.Marshal(unsignedDIDDoc)
	require.NoError(t, err)

	unsignedPlusNonce := util.AddNonceToDoc(docBytes, p.Nonce)
	unsignedPlusNonceB64 := base64.StdEncoding.EncodeToString(unsignedPlusNonce)

	base58PublicKey, err := util.Base64ToBase58(pubKeyB64)
	require.NoError(t, err)

	verified, err := proof.VerifySecp256k1Signature(base58PublicKey, unsignedPlusNonceB64, p.SignatureValue)
	require.NoError(t, err)
	require.True(t, verified)

	signedDIDDoc := &did.DIDDoc{
		UnsignedDIDDoc: unsignedDIDDoc,
		Proof:          &p,
	}

	ledgerDIDDocProof := &proof.Proof{
		Created:        "2020-03-12T10:19:26Z",
		Creator:        "did:work:123456789012345#key-1",
		Nonce:          "dfb4c3ef-6ea2-4809-aaf5-da7a5e3c5f5d",
		SignatureValue: "iKx1CJLi3888eaTrPqpLTDGx4hWrNKcGMNXaLuhmFi2hPuKER6GXpuffubPcMnd4d5E4wkVUs1rLR6kr4wvSUMv5qpb7KRWqC9",
		Type:           "EcdsaSecp256k1VerificationKey2019",
	}

	ledgerMetadata := &Metadata{
		Type:         "https://credentials.workday.com/docs/specification/v1.0/did-doc.json",
		ModelVersion: "1.0",
		ID:           "did:work:9999999999999",
		Author:       "did:work:123456789012345#key-1",
		Authored:     "2020-03-12T10:19:26Z",
	}

	ledgerDIDDoc := DIDDoc{
		DIDDoc:   signedDIDDoc,
		Metadata: ledgerMetadata,
	}

	ledgerDIDDocBytes, err := canonical.Marshal(ledgerDIDDoc)
	require.NoError(t, err)

	var ledgerDIDDocBuffer bytes.Buffer
	ledgerDIDDocBuffer.Write(ledgerDIDDocBytes)
	ledgerDIDDocBuffer.Write([]byte("." + ledgerDIDDocProof.Nonce))
	ledgerDIDDocPlusNonce := ledgerDIDDocBuffer.Bytes()

	ledgerDIDDocPlusNonceB64 := base64.StdEncoding.EncodeToString(ledgerDIDDocPlusNonce)

	verifiedLedgerDIDDoc, err := proof.VerifySecp256k1Signature(base58PublicKey, ledgerDIDDocPlusNonceB64, ledgerDIDDocProof.SignatureValue)
	require.NoError(t, err)
	require.True(t, verifiedLedgerDIDDoc)
}

func TestVerifyAdminSignatureDIDDoc(t *testing.T) {
	pubKeyB64 := "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEskkOL4FWlPT6lvfNRen0TU6d6LtzbAnSuTZv0j5Ey1X9jj+TB6kckk8QVBrSIB1D83w2W7ABAnJkLnyomNCUOw=="
	base58PublicKey, err := util.Base64ToBase58(pubKeyB64)
	require.NoError(t, err)

	adminPublicKey := did.KeyDef{
		ID:              "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
		Type:            proof.EcdsaSecp256k1KeyType,
		Controller:      "did:work:6sYe1y3zXhmyrBkgHgAgaq",
		PublicKeyBase58: base58PublicKey,
	}

	id := "did:work:9999999999999"

	unsignedDIDDoc := did.UnsignedDIDDoc{
		SchemaContext: "https://w3id.org/did/v1",
		ID:            id,
		PublicKey:     []did.KeyDef{},
	}

	p := proof.Proof{
		Created:            "2020-03-12T10:19:26Z",
		VerificationMethod: "did:work:123456789012345#key-1",
		Nonce:              "c04d4351-8fa3-4b23-8096-6ad5821f806b",
		SignatureValue:     "AN1rKpdgkGvZ68kvZ3upDgUyMU4JBJFMwc3DRetqHfx4FDvNF8Zd1ZkDoNF7SqdHHJ5LEdC3Mtrb73GayjG3MQZ8HJHSVFjUc",
		Type:               "EcdsaSecp256k1Signature2019",
	}

	docBytes, err := canonical.Marshal(unsignedDIDDoc)
	require.NoError(t, err)

	withNonce := util.AddNonceToDoc(docBytes, p.Nonce)
	didDocB64Message := base64.StdEncoding.EncodeToString(withNonce)
	didDocVerified, err := proof.VerifySecp256k1Signature(adminPublicKey.PublicKeyBase58, didDocB64Message, p.SignatureValue)
	require.NoError(t, err)
	require.True(t, didDocVerified)

	didInvalid := "did:work:invalid"
	unsignedDIDDocInvalid := &did.UnsignedDIDDoc{
		ID:        didInvalid,
		PublicKey: []did.KeyDef{},
	}

	docBytesInvalid, err := canonical.Marshal(unsignedDIDDocInvalid)
	require.NoError(t, err)

	withNonce = util.AddNonceToDoc(docBytesInvalid, p.Nonce)
	invalidDIDDocB64Message := base64.StdEncoding.EncodeToString(withNonce)
	didDocVerified, err = proof.VerifySecp256k1Signature(adminPublicKey.PublicKeyBase58, invalidDIDDocB64Message, p.SignatureValue)
	require.NoError(t, err)
	require.False(t, didDocVerified)
}

func TestVerifySchemaProof(t *testing.T) {
	testSchema := `{
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

	var s JSONSchemaMap
	assert.NoError(t, json.Unmarshal([]byte(testSchema), &s))

	didDoc, privKey := did.GenerateDIDDoc(proof.WorkEdSignatureType)
	now := time.Now().UTC().Format(time.RFC3339)
	pubKey, err := base58.Decode(didDoc.PublicKey[0].PublicKeyBase58)
	assert.NoError(t, err)

	unsignedSchema := Schema{
		Metadata: &Metadata{
			Type:         util.SchemaTypeReference_v1_0,
			ModelVersion: util.Version_1_0,
			ID:           GenerateSchemaID(didDoc.ID, "1.0"),
			Name:         "Name",
			Author:       didDoc.ID,
			Authored:     now,
		},
		JSONSchema: &JSONSchema{Schema: s},
	}

	err = SignLedgerDoc(unsignedSchema, privKey, didDoc.PublicKey[0].ID)
	assert.NoError(t, err)
	assert.NoError(t, VerifyLedgerProof(unsignedSchema, pubKey))
}

// Revocation //

func TestHashing(t *testing.T) {
	var signingDID = "did:work:UpguDp5Sq4py71M9mqKHJA"

	key := GenerateRevocationKey(signingDID, CredentialID)
	assert.Equal(t, "GjqBiRAsdSbZgUKB2AtMWYyhrs7WtNH3eoAvQ6qY7q2v", key)
}

func TestVerifyRevocationProof(t *testing.T) {
	didDoc, privKey := did.GenerateDIDDoc(proof.WorkEdSignatureType)
	keyRef := didDoc.PublicKey[0].ID

	revocation, err := GenerateLedgerRevocation(CredentialID, didDoc.ID, proof.WorkEd25519Signer{PrivKey: privKey}, keyRef)
	assert.NoError(t, err)

	pubKey, err := base58.Decode(didDoc.PublicKey[0].PublicKeyBase58)
	assert.NoError(t, err)
	assert.NoError(t, VerifyLedgerProof(*revocation, pubKey))
}

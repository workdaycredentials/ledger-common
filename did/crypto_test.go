package did

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"

	"go.wday.io/credentials-open-source/ledger-common/proof"
	"go.wday.io/credentials-open-source/ledger-common/util"
)

var (
	keySeed       = []byte("12345678901234567890123456789012")
	issuerPrivKey = ed25519.NewKeyFromSeed(keySeed) // this matches the public key in didDocJson
	issuerPubKey  = issuerPrivKey.Public().(ed25519.PublicKey)
)

func TestGenerateDIDDocWithAndWithoutContext(t *testing.T) {
	suite, err := proof.SignatureSuites().GetSuite(proof.JCSEdSignatureType, proof.V2)
	assert.NoError(t, err)

	t.Run("Verify with context", func(t *testing.T) {
		contextDoc, _ := GenerateDIDDocWithContext(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		assert.Equal(t, StringOrArray{SchemaContext}, contextDoc.SchemaContext)
		pk, err := base58.Decode(contextDoc.PublicKey[0].PublicKeyBase58)
		assert.NoError(t, err)

		verifier := &proof.Ed25519Verifier{PubKey: pk}
		assert.NoError(t, suite.Verify(contextDoc, verifier))
	})

	t.Run("Verify without context", func(t *testing.T) {
		withoutContextDoc, _ := GenerateDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		assert.Empty(t, withoutContextDoc.SchemaContext)
		pk, err := base58.Decode(withoutContextDoc.PublicKey[0].PublicKeyBase58)
		assert.NoError(t, err)

		verifier := &proof.Ed25519Verifier{PubKey: pk}
		assert.NoError(t, suite.Verify(withoutContextDoc, verifier))
	})
}

func TestGetDIDFromPubKey(t *testing.T) {
	edBase64PubKey := base64.StdEncoding.EncodeToString(issuerPubKey)

	did, err := GenerateDIDFromB64PubKey(edBase64PubKey)
	assert.NoError(t, err)
	assert.Equal(t, DID("did:work:6sYe1y3zXhmyrBkgHgAgaq"), did)
}

func TestExtractAuthorDID(t *testing.T) {
	tests := []struct {
		name        string
		didFragment string
		want        string
	}{
		{
			name:        "DID with key ref",
			didFragment: "did:work:test#key-1",
			want:        "did:work:test",
		},
		{
			name:        "Just a DID",
			didFragment: "did:work:test",
			want:        "did:work:test",
		},
		{
			name:        "Empty",
			didFragment: "",
			want:        "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, DID(tt.want), ExtractDIDFromKeyRef(tt.didFragment))
		})
	}
}

// TestSignatureSuites creates and verifies DID Documents with different proof signature types.
func TestSignatureSuites(t *testing.T) {
	tests := []proof.SignatureType{
		proof.Ed25519KeySignatureType,
		proof.WorkEdSignatureType,
		proof.JCSEdSignatureType,
	}
	for _, signatureType := range tests {
		t.Run(string(signatureType), func(t *testing.T) {
			doc, key := GenerateDIDDocWithContext(proof.Ed25519KeyType, signatureType)
			assert.Equal(t, signatureType, doc.Proof.Type)
			suite, err := proof.SignatureSuites().GetSuiteForProof(doc.GetProof())
			assert.NoError(t, err)
			publicKey := key.Public().(ed25519.PublicKey)
			verifier := &proof.Ed25519Verifier{PubKey: publicKey}
			assert.NoError(t, suite.Verify(doc, verifier))
		})
	}
}

func TestDIDKey(t *testing.T) {
	t.Run("end to end", func(t *testing.T) {
		did := GenerateDIDKey(issuerPubKey)
		extractedKey, err := ExtractEdPublicKeyFromDID(did)
		require.NoError(t, err)
		assert.Equal(t, extractedKey, issuerPubKey)
	})

	t.Run("GenerateDIDKey()", func(t *testing.T) {
		did := GenerateDIDKey(issuerPubKey)
		expectedDIDKeyLen := 55
		assert.True(t, strings.HasPrefix(string(did), "did:key:z"))
		assert.Len(t, did, expectedDIDKeyLen)
	})

	t.Run("GenerateDIDKeyFromB64PubKey()", func(t *testing.T) {
		key := base64.StdEncoding.EncodeToString(issuerPubKey)
		didKeyFromB64, err := GenerateDIDKeyFromB64PubKey(key)
		require.NoError(t, err)

		didKey := GenerateDIDKey(issuerPubKey)
		assert.Equal(t, didKey, didKeyFromB64)
	})
}

func TestExtractEdPublicKeyFromDID(t *testing.T) {
	t.Run("Wrong DID Method", func(t *testing.T) {
		did := DID("did:work:12345678")
		_, err := ExtractEdPublicKeyFromDID(did)
		assert.Error(t, err)
		expectedErr := fmt.Errorf("DID<%s> format not supported", did)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("Improper Multiformat", func(t *testing.T) {
		did := DID("did:key:x12345678")
		_, err := ExtractEdPublicKeyFromDID(did)
		assert.Error(t, err)
		expectedErr := fmt.Errorf("DID<%s> format not supported", did)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("Can't Extract Key", func(t *testing.T) {
		did := DID("did:key:z12345678")
		_, err := ExtractEdPublicKeyFromDID(did)
		assert.Error(t, err)
		expectedErr := fmt.Errorf("key cannot be extracted from DID<%s>", did)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("Happy Path", func(t *testing.T) {
		actualPK := issuerPubKey
		did := DID("did:key:z2DTcg9rqdBTZ2qK1eCy1zQ3c6GzHdZYugdnTKE4NrK8Acd")
		expectedPK, err := ExtractEdPublicKeyFromDID(did)
		require.NoError(t, err)
		assert.Equal(t, expectedPK, actualPK)
	})
}

func TestDeactivateDIDDoc(t *testing.T) {
	t.Run("Using existing DID Doc", func(t *testing.T) {
		doc, privateKey := GenerateDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		assert.NotEmpty(t, doc.PublicKey)

		// deactivate and make sure it has no more pub keys
		deactivated, err := DeactivateDIDDoc(*doc, privateKey)
		assert.NoError(t, err)
		assert.Empty(t, deactivated.PublicKey)

		// validate signature with original pub key
		verifier := &proof.Ed25519Verifier{PubKey: privateKey.Public().(ed25519.PublicKey)}
		suite, err := proof.SignatureSuites().GetSuiteForProof(deactivated.GetProof())
		assert.NoError(t, err)

		err = suite.Verify(deactivated, verifier)
		assert.NoError(t, err)
	})

	t.Run("Using generic method", func(t *testing.T) {
		doc, privateKey := GenerateDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
		assert.NotEmpty(t, doc.PublicKey)

		signer, err := proof.NewEd25519Signer(privateKey, doc.PublicKey[0].ID)
		assert.NoError(t, err)

		// deactivate and make sure it has no more pub keys
		deactivated, err := DeactivateDIDDocGeneric(signer, proof.JCSEdSignatureType, doc.ID)
		assert.NoError(t, err)
		assert.Empty(t, deactivated.PublicKey)

		// validate signature with original pub key
		verifier := &proof.Ed25519Verifier{PubKey: privateKey.Public().(ed25519.PublicKey)}
		suite, err := proof.SignatureSuites().GetSuiteForProof(deactivated.GetProof())
		assert.NoError(t, err)

		err = suite.Verify(deactivated, verifier)
		assert.NoError(t, err)
	})
}

func TestVerifySecp256k1DIDDoc(t *testing.T) {
	pubKeyB64 := "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEskkOL4FWlPT6lvfNRen0TU6d6LtzbAnSuTZv0j5Ey1X9jj+TB6kckk8QVBrSIB1D83w2W7ABAnJkLnyomNCUOw=="
	base58PublicKey, err := util.Base64ToBase58(pubKeyB64)
	require.NoError(t, err)

	adminPublicKey := KeyDef{
		ID:              "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1",
		Type:            proof.EcdsaSecp256k1KeyType,
		Controller:      "did:work:6sYe1y3zXhmyrBkgHgAgaq",
		PublicKeyBase58: base58PublicKey,
	}

	id := DID("did:work:9999999999999")

	p := proof.Proof{
		Created:        "2020-03-12T10:19:26Z",
		Creator:        "did:work:123456789012345#key-1",
		Nonce:          "c04d4351-8fa3-4b23-8096-6ad5821f806b",
		SignatureValue: "AN1rKpdgkGvZ68kvZ3upDgUyMU4JBJFMwc3DRetqHfx4FDvNF8Zd1ZkDoNF7SqdHHJ5LEdC3Mtrb73GayjG3MQZ8HJHSVFjUc",
		Type:           "EcdsaSecp256k1Signature2019",
	}

	doc := DIDDoc{
		SchemaContext: StringOrArray{"https://w3id.org/did/v1"},
		ID:            id,
		PublicKey:     []KeyDef{},
		Proof:         &p,
	}

	verifier, err := AsVerifier(adminPublicKey)
	require.NoError(t, err)
	suite, err := proof.SignatureSuites().GetSuiteForProof(doc.GetProof())
	require.NoError(t, err)
	require.NotNil(t, suite)
	assert.NoError(t, suite.Verify(&doc, verifier))

	// Now test a bad one
	didInvalid := DID("did:work:invalid")
	badDoc := DIDDoc{
		ID:        didInvalid,
		PublicKey: []KeyDef{},
		Proof:     &p,
	}
	assert.Error(t, suite.Verify(&badDoc, verifier))
}

func TestAddKeyToDIDDoc(t *testing.T) {
	doc, privKey := GenerateDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	assert.NotEmpty(t, doc)
	assert.NotEmpty(t, privKey)
	assert.Equal(t, 1, len(doc.PublicKey))

	t.Run("happy path", func(t *testing.T) {
		pubKey, _, _ := ed25519.GenerateKey(nil)
		newKID := GenerateKeyID(doc.ID, uuid.New().String())
		keyDef := KeyDef{
			ID:              newKID,
			Type:            proof.Ed25519KeyType,
			Controller:      doc.ID,
			PublicKeyBase58: base58.Encode(pubKey),
		}

		updatedDoc, err := AddKeyToDIDDoc(*doc, keyDef, privKey, doc.PublicKey[0].ID)
		assert.NoError(t, err)
		assert.NotEmpty(t, updatedDoc)
		assert.Equal(t, 2, len(updatedDoc.PublicKey))
		assert.Contains(t, updatedDoc.PublicKey, keyDef)

		// can get the new def
		gotKeyDef := updatedDoc.GetPublicKey(newKID)
		assert.NotEmpty(t, gotKeyDef)
		assert.Equal(t, keyDef, *gotKeyDef)
	})

	t.Run("key ref already exists", func(t *testing.T) {
		pubKey, _, _ := ed25519.GenerateKey(nil)
		keyDef := KeyDef{
			ID:              GenerateKeyID(doc.ID, InitialKey),
			Type:            proof.Ed25519KeyType,
			Controller:      doc.ID,
			PublicKeyBase58: base58.Encode(pubKey),
		}

		updatedDoc, err := AddKeyToDIDDoc(*doc, keyDef, privKey, doc.PublicKey[0].ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already present in DID Doc")
		assert.Empty(t, updatedDoc)
	})

	t.Run("signing key ref does not exist", func(t *testing.T) {
		pubKey, _, _ := ed25519.GenerateKey(nil)
		keyDef := KeyDef{
			ID:              GenerateKeyID(doc.ID, uuid.New().String()),
			Type:            proof.Ed25519KeyType,
			Controller:      doc.ID,
			PublicKeyBase58: base58.Encode(pubKey),
		}

		updatedDoc, err := AddKeyToDIDDoc(*doc, keyDef, privKey, "bad")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is not present in DID Doc")
		assert.Empty(t, updatedDoc)
	})
}

package did

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/proof"
)

var (
	keySeed       = []byte("12345678901234567890123456789012")
	issuerPrivKey = ed25519.NewKeyFromSeed(keySeed) // this matches the public key in didDocJson
	issuerPubKey  = issuerPrivKey.Public().(ed25519.PublicKey)
)

func TestGenerateDIDDocWithAndWithoutContext(t *testing.T) {
	t.Run("Verify with context", func(t *testing.T) {
		contextDoc, _ := GenerateDIDDocWithContext(proof.WorkEdSignatureType)
		//nolint:staticcheck
		assert.Equal(t, SchemaContext, contextDoc.SchemaContext)
		pk, err := base58.Decode(contextDoc.PublicKey[0].PublicKeyBase58)
		assert.NoError(t, err)
		assert.NoError(t, VerifyDIDDocProof(*contextDoc, pk))
	})

	t.Run("Verify without context", func(t *testing.T) {
		withoutContextDoc, _ := GenerateDIDDoc(proof.WorkEdSignatureType)
		//nolint:staticcheck
		assert.Equal(t, "", withoutContextDoc.SchemaContext)
		pk, err := base58.Decode(withoutContextDoc.PublicKey[0].PublicKeyBase58)
		assert.NoError(t, err)
		assert.NoError(t, VerifyDIDDocProof(*withoutContextDoc, pk))
	})
}

func TestGetDIDFromPubKey(t *testing.T) {
	edBase64PubKey := base64.StdEncoding.EncodeToString(issuerPubKey)

	did, err := GenerateDIDFromB64PubKey(edBase64PubKey)
	assert.NoError(t, err)
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq", did)
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
			if got := ExtractAuthorDID(tt.didFragment); got != tt.want {
				t.Errorf("ExtractAuthorDID() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSignatureSuitesEquivalence tests that the new signature suites are equivalent to the existing
// signing and verification functions.
//
// TODO(NEXT-9220) This test can be removed with the old functions once all the clients have
//  transitioned to using signature suites.
func TestSignatureSuitesEquivalence(t *testing.T) {
	doc, key := GenerateDIDDocWithContext(proof.JCSEdSignatureType)

	signer := &proof.Ed25519Signer{
		KeyID:      doc.PublicKey[0].ID,
		PrivateKey: key,
	}
	verifier := &proof.Ed25519Verifier{
		PubKey: key.Public().(ed25519.PublicKey),
	}

	t.Run("JCS Equivalence", func(t *testing.T) {
		suite := proof.SignatureSuites().JCSEd25519
		// Use the suite to verify the signature generated without suite
		assert.NoError(t, suite.Verify(doc, verifier))
		// Create a copy of the doc without a Proof
		copyDoc := DIDDoc{UnsignedDIDDoc: doc.UnsignedDIDDoc}
		// Sign with suite
		assert.NoError(t, suite.Sign(&copyDoc, signer))
		// Verify with suite
		assert.NoError(t, suite.Verify(&copyDoc, verifier))
		// Verify without suite
		assert.NoError(t, VerifyDIDDocProof(copyDoc, verifier.PubKey))
	})

	t.Run("WorkEd25519 Equivalence", func(t *testing.T) {
		suite := proof.SignatureSuites().WorkEd25519
		workSigner := proof.WorkEd25519Signer{
			KeyID:   signer.KeyID,
			PrivKey: signer.PrivateKey,
		}

		// Create a copy of the original doc without a Proof
		copyDoc := DIDDoc{UnsignedDIDDoc: doc.UnsignedDIDDoc}
		// Sign without the suite
		signed, err := SignDIDDocGeneric(workSigner, copyDoc.UnsignedDIDDoc, workSigner.KeyID)
		assert.NoError(t, err)
		// Verify without the suite
		assert.NoError(t, VerifyDIDDocProof(*signed, verifier.PubKey))
		// Verify with the suite
		assert.NoError(t, suite.Verify(signed, verifier))

		// Create a copy of the original doc without a Proof
		copyDoc = DIDDoc{UnsignedDIDDoc: doc.UnsignedDIDDoc}
		// Sign with the suite
		assert.NoError(t, suite.Sign(&copyDoc, signer))
		// Verify with the suite
		assert.NoError(t, suite.Verify(&copyDoc, verifier))
		// Verify without the suite
		assert.NoError(t, VerifyDIDDocProof(copyDoc, verifier.PubKey))
	})
}

func TestDIDKey(t *testing.T) {
	t.Run("end to end", func(t *testing.T) {
		didkey := GenerateDIDKey(issuerPubKey)
		extractedKey, err := ExtractEdPublicKeyFromDID(didkey)
		require.NoError(t, err)
		assert.Equal(t, extractedKey, issuerPubKey)
	})
	t.Run("GenerateDIDKey()", func(t *testing.T) {
		didkey := GenerateDIDKey(issuerPubKey)
		expectedDIDKeyLen := 55
		assert.True(t, strings.HasPrefix(didkey, "did:key:z"))
		assert.Len(t, didkey, expectedDIDKeyLen)
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
		did := "did:work:12345678"
		_, err := ExtractEdPublicKeyFromDID(did)
		assert.Error(t, err)
		expectedErr := fmt.Errorf("DID<%s> format not supported", did)
		assert.Equal(t, expectedErr, err)
	})
	t.Run("Improper Multiformat", func(t *testing.T) {
		did := "did:key:x12345678"
		_, err := ExtractEdPublicKeyFromDID(did)
		assert.Error(t, err)
		expectedErr := fmt.Errorf("DID<%s> format not supported", did)
		assert.Equal(t, expectedErr, err)
	})
	t.Run("Can't Extract Key", func(t *testing.T) {
		did := "did:key:z12345678"
		_, err := ExtractEdPublicKeyFromDID(did)
		assert.Error(t, err)
		expectedErr := fmt.Errorf("key cannot be extracted from DID<%s>", did)
		assert.Equal(t, expectedErr, err)
	})
	t.Run("Happy Path", func(t *testing.T) {
		actualPK := issuerPubKey
		did := "did:key:z2DTcg9rqdBTZ2qK1eCy1zQ3c6GzHdZYugdnTKE4NrK8Acd"
		expectedPK, err := ExtractEdPublicKeyFromDID(did)
		require.NoError(t, err)
		assert.Equal(t, expectedPK, actualPK)
	})
}

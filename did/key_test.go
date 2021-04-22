package did

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDIDKey(t *testing.T) {
	t.Run("end to end", func(t *testing.T) {
		did := GenerateDIDKey(issuerPubKey)
		// These DID always start with z6Mk.
		assert.Equal(t, "did:key:z6Mk", did[0:12].String())
		extractedKey, err := ExtractEdPublicKeyFromDID(did)
		require.NoError(t, err)
		assert.Equal(t, issuerPubKey, extractedKey)
	})

	t.Run("GenerateDIDKey()", func(t *testing.T) {
		did := GenerateDIDKey(issuerPubKey)
		const expectedDIDKeyLen = 56
		assert.Equal(t, "did:key:z6MkhesMp8iSdumBExtuozsz3PYfapPpQUCarQA5uLcRee4d", did.String())
		assert.Len(t, did, expectedDIDKeyLen)
	})

	t.Run("GenerateDIDKeyFromB64PubKey()", func(t *testing.T) {
		key := base64.StdEncoding.EncodeToString(issuerPubKey)
		didKeyFromB64, err := GenerateDIDKeyFromB64PubKey(key)
		require.NoError(t, err)
		assert.Equal(t, "did:key:z6MkhesMp8iSdumBExtuozsz3PYfapPpQUCarQA5uLcRee4d", didKeyFromB64.String())
	})
}

func TestExtractEdPublicKeyFromDID(t *testing.T) {
	t.Run("Wrong DID Method", func(t *testing.T) {
		did := DID("did:work:12345678")
		_, err := ExtractEdPublicKeyFromDID(did)
		expectedErr := fmt.Sprintf("DID<%s> format not supported", did)
		assert.EqualError(t, err, expectedErr)
	})

	t.Run("Improper Multiformat", func(t *testing.T) {
		did := DID("did:key:x12345678")
		_, err := ExtractEdPublicKeyFromDID(did)
		expectedErr := fmt.Sprintf("DID<%s> format not supported", did)
		assert.EqualError(t, err, expectedErr)
	})

	t.Run("Can't Extract Key", func(t *testing.T) {
		did := DID("did:key:z12345678")
		_, err := ExtractEdPublicKeyFromDID(did)
		expectedErr := fmt.Sprintf("key cannot be extracted from DID<%s>", did)
		assert.EqualError(t, err, expectedErr)
	})

	t.Run("Happy Path", func(t *testing.T) {
		expectedPK := issuerPubKey
		did := DID("did:key:z6MkhesMp8iSdumBExtuozsz3PYfapPpQUCarQA5uLcRee4d")
		actualPK, err := ExtractEdPublicKeyFromDID(did)
		require.NoError(t, err)
		assert.Equal(t, expectedPK, actualPK)
	})
}

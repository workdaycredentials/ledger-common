package proof

import (
	"encoding/base64"
	"testing"

	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/require"

	"github.com/workdaycredentials/ledger-common/util"
)

const (
	msgB64       = "e2RhdGE6bG92ZWx5IGpzb259Cg=="
	pubKeyB64    = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEskkOL4FWlPT6lvfNRen0TU6d6LtzbAnSuTZv0j5Ey1X9jj+TB6kckk8QVBrSIB1D83w2W7ABAnJkLnyomNCUOw=="
	b64Signature = "MEUCICeE0BmEF/oFBU1zD0oHowDBslrQQDxlTXG84rjBR60BAiEAzYzkalSiCg6p0v72Z3YXWSexEyj4Lo+TbsFsgnxD0J8="
)

// TODO this test should be deprecated in favor of signature suite validation tests

func TestSignatureVerification(t *testing.T) {
	t.Run("happy path for signature verification", func(t *testing.T) {

		decoded, err := base64.StdEncoding.DecodeString(b64Signature)
		require.NoError(t, err)
		b58Signature := base58.Encode(decoded)

		base58PublicKey, err := util.Base64ToBase58(pubKeyB64)
		require.NoError(t, err)
		verified, err := VerifySecp256k1Signature(base58PublicKey, msgB64, b58Signature)

		require.NoError(t, err)
		require.True(t, verified)
	})

	t.Run("invalid msg for signature verification", func(t *testing.T) {
		invalidMsgB64 := "e2RhdGE6c2FkIGpzb259Cg=="
		decoded, err := base64.StdEncoding.DecodeString(b64Signature)
		require.NoError(t, err)
		b58Signature := base58.Encode(decoded)

		base58PublicKey, err := util.Base64ToBase58(pubKeyB64)
		require.NoError(t, err)
		verified, err := VerifySecp256k1Signature(base58PublicKey, invalidMsgB64, b58Signature)

		require.NoError(t, err)
		require.False(t, verified)
	})

	t.Run("invalid signature for signature verification", func(t *testing.T) {
		invalidb58Signature := "invalidSignature"

		base58PublicKey, err := util.Base64ToBase58(pubKeyB64)
		require.NoError(t, err)
		_, err = VerifySecp256k1Signature(base58PublicKey, msgB64, invalidb58Signature)
		require.Error(t, err)
	})

	t.Run("incorrect public key for signature verification", func(t *testing.T) {
		decoded, err := base64.StdEncoding.DecodeString(b64Signature)
		require.NoError(t, err)
		b58Signature := base58.Encode(decoded)

		incorrectPubKeyB64 := "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAENwbAhjq+l4Lx/wF1Bo9crEY9zf/nRjmEvXxih8S9QbubITJ64ykhyUsKQey0GyIQH8tEij/ojYJudu8NDAwvMg=="
		incorrectBase58PublicKey, err := util.Base64ToBase58(incorrectPubKeyB64)
		require.NoError(t, err)
		verified, err := VerifySecp256k1Signature(incorrectBase58PublicKey, msgB64, b58Signature)

		require.NoError(t, err)
		require.False(t, verified)
	})
}

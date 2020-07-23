package revocation

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/ledger"
	"github.com/workdaycredentials/ledger-common/proof"
)

const (
	CredentialID = "36abc9d6-b363-44c3-81f0-9d28ecbec2be"
)

// TestBlindRevocation password-encrypts a revocation document using the credential ID and then decrypts and verifies
// the result.
func TestBlindRevocation(t *testing.T) {
	// Create an issuer
	didDoc, privKey := did.GenerateDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	keyRef := didDoc.PublicKey[0].ID

	// Create the unblinded revocation
	signer, err := proof.NewEd25519Signer(privKey, keyRef)
	assert.NoError(t, err)

	revocation, err := ledger.GenerateLedgerRevocation(CredentialID, didDoc.ID, signer, proof.JCSEdSignatureType)
	assert.NoError(t, err)

	// Blind
	b, err := BlindRevocation("1", revocation)
	assert.NoError(t, err)
	assert.NotEmpty(t, b)

	// Unblind
	var unblinded ledger.Revocation
	assert.NoError(t, UnblindRevocation(b, "1", &unblinded))
	assert.Equal(t, revocation, &unblinded)
}

// Prevent compiler optimization of benchmarks
var (
	blindGlobal      []byte
	revocationGlobal ledger.Revocation
)

func BenchmarkBlindRevocation(b *testing.B) {
	issuer, key := did.GenerateDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	keyRef := issuer.PublicKey[0].ID

	signer, err := proof.NewEd25519Signer(key, keyRef)
	assert.NoError(b, err)

	revocation, err := ledger.GenerateLedgerRevocation(CredentialID, issuer.ID, signer, proof.JCSEdSignatureType)
	assert.NoError(b, err)

	var revocationBytes []byte
	for n := 0; n < b.N; n++ {
		revocationBytes, _ = BlindRevocation(CredentialID, revocation)
	}
	blindGlobal = revocationBytes
}

func BenchmarkUnblindRevocation(b *testing.B) {
	issuer, key := did.GenerateDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	keyRef := issuer.PublicKey[0].ID

	signer, err := proof.NewEd25519Signer(key, keyRef)
	assert.NoError(b, err)

	revocation, err := ledger.GenerateLedgerRevocation(CredentialID, issuer.ID, signer, proof.JCSEdSignatureType)
	assert.NoError(b, err)

	blinded, err := BlindRevocation(CredentialID, revocation)
	assert.NoError(b, err)

	for n := 0; n < b.N; n++ {
		_ = UnblindRevocation(blinded, CredentialID, &revocationGlobal)
	}
}

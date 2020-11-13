package credential

import (
	"fmt"

	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/proof"
)

// VerifyClaim verifies the digital signature of the Claim Proof associated with the given attribute
// and public key.  An error will be returned if the signature is either invalid or if a Claim Proof
// cannot be found for the given attribute.
func VerifyClaim(cred *VerifiableCredential, attribute string, publicKey ed25519.PublicKey) error {
	proofForAttr, found := cred.ClaimProofs[attribute]
	if !found {
		return fmt.Errorf("missing claim proof for attribute \"%s\"", attribute)
	}
	suite, err := proof.SignatureSuites().GetSuiteForCredentialsProof(&proofForAttr)
	if err != nil {
		return err
	}
	value := cred.CredentialSubject[attribute]
	claim := VerifiableCredential{
		UnsignedVerifiableCredential: UnsignedVerifiableCredential{
			Metadata:          cred.Metadata,
			CredentialSubject: map[string]interface{}{attribute: value},
		},
		Proof: &proofForAttr,
	}
	verifier := &proof.Ed25519Verifier{PubKey: publicKey}
	return suite.Verify(&claim, verifier)
}

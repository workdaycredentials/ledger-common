package credential

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/proof"
)

// VerifyClaim verifies the digital signature of the Claim Proof associated with the given attribute
// and public key.  An error will be returned if the signature is either invalid or if a Claim Proof
// cannot be found for the given attribute.
func VerifyClaim(cred *VerifiableCredential, attribute string, publicKey ed25519.PublicKey) error {
	proofForAttr := cred.ClaimProofs[attribute]
	switch proofForAttr.Type {
	case proof.JCSEdSignatureType:
		value := cred.CredentialSubject[attribute]
		claim := VerifiableCredential{
			UnsignedVerifiableCredential: UnsignedVerifiableCredential{
				Metadata:          cred.Metadata,
				CredentialSubject: map[string]interface{}{attribute: value},
			},
			Proof: &proofForAttr,
		}
		return proof.VerifyJCSEd25519Proof(&claim, proof.JCSEd25519Verifier, publicKey)

	case proof.Ed25519SignatureType:
		fallthrough

	case proof.WorkEdSignatureType:
		encodedClaim, err := EncodeAttributeClaimDataForSigning(cred.Metadata, attribute, cred.CredentialSubject[attribute])
		if err != nil {
			return err
		}
		if err = proof.VerifyWorkEd25519Proof(publicKey, proofForAttr, encodedClaim); err == nil {
			return nil
		}
		logrus.WithError(err).Error("Could not verify claim canonically encoded, trying non-canonical encoding")
		encodedClaim, err = EncodeAttributeClaimDataForSigningOption(cred.Metadata, attribute, cred.CredentialSubject[attribute], false)
		if err != nil {
			return err
		}
		if err = proof.VerifyWorkEd25519Proof(publicKey, proofForAttr, encodedClaim); err == nil {
			logrus.Warn("Proof for claim was generated non-canonically")
		}
		return err

	default:
		return fmt.Errorf("cannot verify claim for unsupported proof type: %s", proofForAttr.Type)
	}
}

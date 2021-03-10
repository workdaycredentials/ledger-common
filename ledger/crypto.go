package ledger

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/mr-tron/base58"
	"github.com/sirupsen/logrus"

	"go.wday.io/credentials-open-source/ledger-common/did"
	"go.wday.io/credentials-open-source/ledger-common/proof"
)

type (
	Provider struct {
		SchemaProvider
		RevocationProvider
		DIDDocProvider
	}

	SchemaProvider     func(ctx context.Context, schemaID string) (*Schema, error)
	RevocationProvider func(ctx context.Context, credentialID, revocationID string) (*Revocation, error)
	DIDDocProvider     func(ctx context.Context, did did.DID) (*DIDDoc, error)
)

// GetKeyDef returns the Ed25519 public key with the given Key ID located on the DID Document.
func GetKeyDef(ctx context.Context, did did.DID, keyID string, provider DIDDocProvider) (*did.KeyDef, error) {
	doc, err := provider(ctx, did)
	if err != nil {
		logrus.WithError(err).Errorf("Could not get did doc for did: %s", did)
		return nil, err
	}
	if doc == nil || doc.Metadata.ID == "" {
		return nil, fmt.Errorf("no DID Doc found for specified ID: %s", did)
	}
	if keyDef := doc.GetPublicKey(keyID); !keyDef.IsEmpty() {
		return keyDef, nil
	}
	return nil, fmt.Errorf("could not resolve specified key '%s' in did doc '%s'", keyID, did)
}

// GenerateRevocationKey creates a hash of the issuer DID and the credential ID. This hash is used
// as the revocation ID. Revocations are issued by the Issuer of the credential. Using the
// issuer's DID in the hash effectively creates namespace for that issuer. The expectation is that
// the credential ID is a UUID and is therefore unique per credential. Hashing the two values
// together obfuscates the issuer's ID on the blockchain. Only parties that have already seen the
// credential, and therefore now the credential ID and issuer DID will be able to look up the
// revocation status in the ledger. This is intended to prevent data mining on the revocations
// store in an attempt to learn anything about the issuer.
func GenerateRevocationKey(issuerDID did.DID, credentialID string) string {
	sha := sha256.Sum256([]byte(string(issuerDID) + credentialID))
	return base58.Encode(sha[:])
}

// Verify verifies the digital signature on the given Provable. The DIDDocProvider is used to
// look up the public key referenced as the Proof's verification method.  The verification method
// must therefore be a fully qualified key reference (DID URL + Fragment).
func Verify(ctx context.Context, provable proof.Provable, provider DIDDocProvider) error {
	p := provable.GetProof()
	if p == nil {
		return fmt.Errorf("missing proof")
	}

	keyRef := p.GetVerificationMethod()
	id := did.ExtractDIDFromKeyRef(keyRef)

	didDoc, err := provider(ctx, id)
	if err != nil {
		return err
	}

	keyDef := didDoc.GetPublicKey(keyRef)
	if keyDef == nil {
		return fmt.Errorf("could not find key with id: %s", keyRef)
	}

	verifier, err := did.AsVerifier(*keyDef)
	if err != nil {
		return err
	}

	suite, err := proof.SignatureSuites().GetSuiteForProof(p)
	if err != nil {
		return err
	}
	return suite.Verify(provable, verifier)
}

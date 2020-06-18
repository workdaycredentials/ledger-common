package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ed25519"

	"github.com/sirupsen/logrus"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

type (
	Provider struct {
		SchemaProvider
		RevocationProvider
		DIDDocProvider
	}

	SchemaProvider     func(ctx context.Context, schemaID string) (*Schema, error)
	RevocationProvider func(ctx context.Context, credentialID, revocationID string) (*Revocation, error)
	DIDDocProvider     func(ctx context.Context, did string) (*DIDDoc, error)
)

// DID

// SignLedgerDoc creates a signed DID Document with a JcsEd25519Signature2020 Proof.
func SignLedgerDoc(ledgerObj HasLedgerMetadataProvable, privKey ed25519.PrivateKey, keyRef string) error {
	ps := proof.JCSEd25519Signer{KeyID: keyRef, PrivKey: privKey}
	return SignLedgerDocGeneric(ps, ledgerObj, keyRef)
}

// SignLedgerDocGeneric creates a signed DID Document with whatever Proof the Signer supports.
func SignLedgerDocGeneric(s proof.Signer, ledgerObj HasLedgerMetadataProvable, keyRef string) error {
	ledgerMetadata := ledgerObj.GetLedgerMetadata()
	if ledgerMetadata.Proof != nil {
		return errors.New("ledger doc is already signed")
	}

	signatureType := s.Type()
	switch signatureType {
	case proof.JCSEdSignatureType:
		p, err := proof.CreateJCSEd25519Proof(ledgerObj, s, keyRef)
		if err != nil {
			return err
		}
		ledgerObj.SetProof(p)
		return nil

	case proof.Ed25519SignatureType:
		return fmt.Errorf("%s is no longer supported. Please use %s", proof.Ed25519SignatureType, proof.JCSEdSignatureType)

	case proof.WorkEdSignatureType:
		docBytes, err := canonical.Marshal(ledgerObj)
		if err != nil {
			return errors.New("failed to marshal unsigned doc")
		}
		nonce := uuid.New().String()
		docProof, err := proof.CreateWorkEd25519ProofGeneric(s, docBytes, keyRef, nonce, true)
		if err != nil {
			return err
		}
		ledgerObj.SetProof(docProof)
		return nil

	default:
		return fmt.Errorf("unsupported signature type: %s", signatureType)
	}
}

// VerifyLedgerProof verifies the ledger object's digital signature.
// Returns an error if the object's metadata is missing or if the Proof is invalid.
func VerifyLedgerProof(ledgerObj HasLedgerMetadataProvable, pubKey ed25519.PublicKey) error {
	metadata := ledgerObj.GetLedgerMetadata()
	if metadata.Proof == nil {
		return errors.New("ledger object has nil proof")
	}

	signatureType := ledgerObj.GetProof().Type
	switch signatureType {
	case proof.JCSEdSignatureType:
		return proof.VerifyJCSEd25519Proof(ledgerObj, proof.JCSEd25519Verifier, pubKey)

	case proof.Ed25519SignatureType:
		fallthrough

	case proof.WorkEdSignatureType:
		proofCopy := metadata.Proof
		metadata.Proof = nil
		defer func() { metadata.Proof = proofCopy }()
		canonicalBytes, err := canonical.Marshal(ledgerObj)
		if err != nil {
			return err
		}
		if err = proof.VerifyWorkEd25519Proof(pubKey, *proofCopy, canonicalBytes); err == nil {
			return nil
		}

		// Try to verify without canonical marshaling for backwards compatibility
		b, err := json.Marshal(ledgerObj)
		if err != nil {
			return err
		}
		err = proof.VerifyWorkEd25519Proof(pubKey, *proofCopy, b)
		if err == nil {
			logrus.Warnf("Proof was generated non-canonically: %+v", ledgerObj.GetLedgerMetadata())
		}
		return err
	default:
		return fmt.Errorf("cannot verify proof of type: %s", signatureType)
	}
}

func VerifySecp256k1LedgerDIDDocSignature(derSecp256k1PublicKey did.KeyDef, didDoc DIDDoc) error {
	didDocProof := didDoc.DIDDoc.Proof

	// Verify DIDDoc signature
	unsignedDIDDoc := didDoc.DIDDoc.UnsignedDIDDoc
	didDocBytes, err := canonical.Marshal(unsignedDIDDoc)
	if err != nil {
		return err
	}

	withNonce := util.AddNonceToDoc(didDocBytes, didDocProof.Nonce)
	didDocBase64Message := base64.StdEncoding.EncodeToString(withNonce)
	didDocVerified, err := proof.VerifySecp256k1Signature(derSecp256k1PublicKey.PublicKeyBase58, didDocBase64Message, didDocProof.SignatureValue)
	if err != nil {
		return err
	}
	if !didDocVerified {
		return errors.New("error verifying signature")
	}

	// Verify DIDDoc signature
	ledgerMetadata := didDoc.GetLedgerMetadata()
	proofCopy := ledgerMetadata.Proof
	ledgerMetadata.Proof = nil
	defer func() { ledgerMetadata.Proof = proofCopy }()
	ledgerDIDDocBytes, err := canonical.Marshal(didDoc)
	if err != nil {
		return err
	}

	withNonce = util.AddNonceToDoc(ledgerDIDDocBytes, proofCopy.Nonce)
	ledgerDIDDocBase64Message := base64.StdEncoding.EncodeToString(withNonce)
	ledgerDIDDocVerified, err := proof.VerifySecp256k1Signature(derSecp256k1PublicKey.PublicKeyBase58, ledgerDIDDocBase64Message, proofCopy.SignatureValue)
	if err != nil {
		return err
	}
	if !ledgerDIDDocVerified {
		return errors.New("error verifying signature")
	}

	return nil
}

// IsLedgerProofCanonical returns true if the ledger object was formatted according to the
// JSON Canonicalization Scheme when it was digitally signed.  Returns an error if the Proof
// is invalid or the signature type is unsupported.
func IsLedgerProofCanonical(ledgerObj HasLedgerMetadataProvable, pubKey ed25519.PublicKey) (bool, error) {
	metadata := ledgerObj.GetLedgerMetadata()
	signatureType := metadata.Proof.Type
	switch signatureType {
	case proof.JCSEdSignatureType:
		if err := proof.VerifyJCSEd25519Proof(ledgerObj, proof.JCSEd25519Verifier, pubKey); err != nil {
			return false, err
		}
		return true, nil

	case proof.Ed25519SignatureType:
		fallthrough

	case proof.WorkEdSignatureType:
		proofCopy := metadata.Proof
		metadata.Proof = nil
		defer func() { metadata.Proof = proofCopy }()
		canonicalBytes, err := canonical.Marshal(ledgerObj)
		if err != nil {
			return false, err
		}
		if err := proof.VerifyWorkEd25519Proof(pubKey, *proofCopy, canonicalBytes); err == nil {
			return true, nil
		}

		// Try to verify without canonical marshaling for backwards compatibility
		b, err := json.Marshal(ledgerObj)
		if err != nil {
			return false, err
		}
		if err = proof.VerifyWorkEd25519Proof(pubKey, *proofCopy, b); err != nil {
			return false, err
		}
		return true, nil

	default:
		return false, fmt.Errorf("cannot verify proof of type: %s", signatureType)
	}
}

// GetPublicKey returns the Ed25519 public key with the given Key ID located on the DID Document.
func GetPublicKey(ctx context.Context, did, keyID string, provider DIDDocProvider) (ed25519.PublicKey, error) {
	doc, err := provider(ctx, did)
	if err != nil {
		logrus.WithError(err).Errorf("Could not get did doc for did: %s", did)
		return nil, err
	}
	if doc == nil || doc.ID == "" {
		return nil, fmt.Errorf("no DID Doc found for specified ID: %s", did)
	}
	var pubKey ed25519.PublicKey
	if keyDef := doc.GetPublicKey(keyID); !keyDef.IsEmpty() {
		if pubKey, err = keyDef.GetDecodedPublicKey(); err != nil {
			return nil, err
		}
		return pubKey, nil
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
func GenerateRevocationKey(issuerDID string, credentialID string) string {
	sha := sha256.Sum256([]byte(issuerDID + credentialID))
	return base58.Encode(sha[:])
}

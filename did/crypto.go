package did

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

const (
	// AdminDIDKey the key for ledger value of admin did
	AdminDIDKey = "admin_did"

	// InitialKey the key reference assigned to the first key in a DID Doc
	InitialKey      = "key-1"
	IssuerDIDMethod = "did:work:"
	KeyDIDMethod    = "did:key:"

	// Codec for Ed25519 multi-format
	// https://github.com/multiformats/multicodec
	Ed25519Codec byte = 0xed

	// SchemaContext is the JSON-LD @context value that points to the W3C DID v1 context.
	// Workday has chosen not to use JSON-LD for DID Documents.
	//
	// Deprecated: This field is kept for historical purposes only. New documents should exclude it.
	SchemaContext = "https://w3id.org/did/v1"
)

// SignDIDDoc creates a signed DID Document using a JcsEd25519Signature2020 Proof.
func SignDIDDoc(privKey ed25519.PrivateKey, doc UnsignedDIDDoc, keyRef string) (*DIDDoc, error) {
	ps := proof.JCSEd25519Signer{KeyID: keyRef, PrivKey: privKey}
	return SignDIDDocGeneric(ps, doc, keyRef)
}

// SignDIDDocGeneric creates a signed DID Document using whatever Proof is supported by the Signer.
func SignDIDDocGeneric(s proof.Signer, unsignedDoc UnsignedDIDDoc, keyRef string) (*DIDDoc, error) {
	if unsignedDoc.IsEmpty() {
		return nil, errors.New("cannot sign empty did doc")
	}

	signatureType := s.Type()
	switch signatureType {
	case proof.JCSEdSignatureType:
		didDoc := DIDDoc{UnsignedDIDDoc: unsignedDoc}
		p, err := proof.CreateJCSEd25519Proof(&didDoc, s, keyRef)
		if err != nil {
			return nil, err
		}
		didDoc.Proof = p
		return &didDoc, nil

	case proof.Ed25519SignatureType:
		return nil, fmt.Errorf("%s is no longer supported. Please use %s", proof.Ed25519SignatureType, proof.JCSEdSignatureType)

	case proof.WorkEdSignatureType:
		logrus.Warnf("%s is deprecated. Please use %s", proof.WorkEdSignatureType, proof.JCSEdSignatureType)
		docBytes, err := canonical.Marshal(unsignedDoc)
		if err != nil {
			return nil, errors.New("failed to marshal unsigned doc")
		}
		nonce := uuid.New().String()
		docProof, err := proof.CreateWorkEd25519ProofGeneric(s, docBytes, keyRef, nonce, true)
		return &DIDDoc{UnsignedDIDDoc: unsignedDoc, Proof: docProof}, err

	default:
		return nil, fmt.Errorf("unsupported signature type: %s", signatureType)
	}
}

// VerifyDIDDocProof verifies the DID Doc's digital signature.
// Returns an error if the DID Doc is empty or if the Proof is invalid.
func VerifyDIDDocProof(didDoc DIDDoc, pubKey ed25519.PublicKey) error {
	signatureType := didDoc.Proof.Type
	if didDoc.IsEmpty() || signatureType == "" {
		return errors.New("cannot verify empty did doc")
	}

	switch signatureType {
	case proof.JCSEdSignatureType:
		return proof.VerifyJCSEd25519Proof(&didDoc, proof.JCSEd25519Verifier, pubKey)

	case proof.Ed25519SignatureType:
		fallthrough

	case proof.WorkEdSignatureType:
		bytes, err := canonical.Marshal(didDoc.UnsignedDIDDoc)
		if err != nil {
			return err
		}
		if err = proof.VerifyWorkEd25519Proof(pubKey, *didDoc.Proof, bytes); err == nil {
			return nil
		}

		// Try to verify without canonical marshaling for backwards compatibility
		bytes, err = json.Marshal(didDoc.UnsignedDIDDoc)
		if err != nil {
			return err
		}
		if err = proof.VerifyWorkEd25519Proof(pubKey, *didDoc.Proof, bytes); err == nil {
			logrus.Warnf("Proof was generated non-canonically: %s", didDoc.ID)
		}
		return err

	default:
		return fmt.Errorf("cannot verify proof of type: %s", signatureType)
	}
}

// IsDIDDocCanonical returns true if the DID Document was formatted according to the
// JSON Canonicalization Scheme when it was digitally signed.  Returns an error if the Proof
// is missing or invalid.
func IsDIDDocCanonical(didDoc DIDDoc, pubKey ed25519.PublicKey) (bool, error) {
	signatureType := didDoc.Proof.Type
	if didDoc.IsEmpty() || signatureType == "" {
		return false, errors.New("cannot verify empty did doc")
	}

	switch signatureType {
	case proof.JCSEdSignatureType:
		if err := proof.VerifyJCSEd25519Proof(&didDoc, proof.JCSEd25519Verifier, pubKey); err != nil {
			return false, err
		}
		return true, nil

	case proof.WorkEdSignatureType:
		fallthrough

	case proof.Ed25519SignatureType:
		bytes, err := canonical.Marshal(didDoc.UnsignedDIDDoc)
		if err != nil {
			return false, err
		}
		if err = proof.VerifyWorkEd25519Proof(pubKey, *didDoc.Proof, bytes); err == nil {
			return true, nil
		}

		// Try to verify without canonical marshaling for backwards compatibility
		bytes, err = json.Marshal(didDoc.UnsignedDIDDoc)
		if err != nil {
			return false, err
		}
		if err = proof.VerifyWorkEd25519Proof(pubKey, *didDoc.Proof, bytes); err == nil {
			return false, nil
		}
		return false, err

	default:
		return false, fmt.Errorf("cannot verify proof of type: %s", signatureType)
	}
}

// ExtractAuthorDID parses a key reference in the form of DID#keyID and returns the DID.
// If the key reference doesn't contain a hash "#" symbol, the entire key reference is returned.
func ExtractAuthorDID(keyRef string) string {
	s := strings.Split(keyRef, "#")
	return s[0]
}

// GenerateDID generates a Decentralized ID in the form of "did:work:<id>" based on an Ed25519
// public key. Workday's DID method uses the first 16 bytes of the public key as a unique random
// value, assuming that the caller generates a new random key pair when creating a new ID.
func GenerateDID(publicKey ed25519.PublicKey) string {
	return IssuerDIDMethod + base58.Encode(publicKey[0:16])
}

// GenerateDIDFromB64PubKey converts a base64 encoded Ed25519 public key into a Decentralized ID.
// See GenerateDID.
func GenerateDIDFromB64PubKey(edBase64PubKey string) (string, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(edBase64PubKey)
	if err != nil {
		return "", errors.Wrap(err, "unable to base64 decode ED key")
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)
	return GenerateDID(pubKey), nil
}

// GetProofCreatorPubKey returns the Key Definition that can be used to verify the Proof on the
// given DID Document.  This assumes that DID Documents are self-signed, which is always the case
// in Workday. Returns an error if the public key is not found.
func GetProofCreatorPubKey(didDoc DIDDoc) (*KeyDef, error) {
	var publicKey KeyDef
	for _, keyDef := range didDoc.PublicKey {
		if keyDef.ID == didDoc.Proof.GetVerificationMethod() {
			publicKey = keyDef
		}
	}
	if publicKey.PublicKeyBase58 == "" {
		return nil, errors.New("could not find public key")
	}

	return &publicKey, nil
}

// GenerateDIDKey generates a non-registry based Decentralized DID in the form of "did:key:<id>" based on an Ed25519
// public key. The DID Key Method expands a cryptographic public key into a DID Document.
// Note: As of May 2020, the DID Key method is still in unofficial draft (https://w3c-ccg.github.io/did-method-key)
func GenerateDIDKey(publicKey ed25519.PublicKey) string {
	pk := append([]byte{Ed25519Codec}, publicKey...)
	return KeyDIDMethod + "z" + base58.Encode(pk)
}

// GenerateDIDKeyFromB64PubKey converts a base64 encoded Ed25519 public key into a DID Key.
// See GenerateDIDKey.
func GenerateDIDKeyFromB64PubKey(edBase64PubKey string) (did string, err error) {
	decodedPubKey, err := base64.StdEncoding.DecodeString(edBase64PubKey)
	if err != nil {
		return
	}
	return GenerateDIDKey(decodedPubKey), nil
}

// ExtractEdPublicKeyFromDID extracts an Ed25519 Public Key from a DID Key.
func ExtractEdPublicKeyFromDID(did string) (key ed25519.PublicKey, err error) {
	prefix := KeyDIDMethod + "z"
	if !strings.HasPrefix(did, prefix) {
		err =  fmt.Errorf("DID<%s> format not supported", did)
		return
	}
	decodedKey, err := base58.Decode(did[len(prefix):])
	if err != nil {
		return nil, errors.New("cannot decode DID")
	}

	codec := decodedKey[0]
	if codec == Ed25519Codec {
		return decodedKey[1:], nil
	}
	err = fmt.Errorf("key cannot be extracted from DID<%s>", did)
	return
}

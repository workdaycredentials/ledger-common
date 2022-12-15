package didcomm

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mr-tron/base58"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
)

const (
	algHeader = "alg"
	kidHeader = "kid"
	edDSAAlg  = "EdDSA"
)

var (
	protectedHeader = map[string]interface{}{
		algHeader: edDSAAlg,
	}

	encoding = base64.URLEncoding
)

// CreateAttachmentData takes a DID Document, and key and key id referenced in that document
// The attachment is a b64 encoded version of the did document in a detached JWS
func CreateAttachmentData(keyID string, didDoc did.DIDDoc, key ed25519.PrivateKey) (*Data, error) {
	protectedHeaderBytes, err := json.Marshal(protectedHeader)
	if err != nil {
		return nil, err
	}
	encodedProtectedHeader := encoding.EncodeToString(protectedHeaderBytes)
	didDocBytes, err := json.Marshal(didDoc)
	if err != nil {
		return nil, err
	}
	encodedDIDDoc := encoding.EncodeToString(didDocBytes)
	keyDef := didDoc.GetPublicKey(keyID)
	if keyDef == nil {
		return nil, fmt.Errorf("could not find key with id: %s", keyID)
	}
	signer, err := proof.NewEd25519Signer(key, keyID)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign([]byte(encodedProtectedHeader + "." + encodedDIDDoc))
	if err != nil {
		return nil, err
	}
	jws := JWS{
		Header: map[string]interface{}{
			kidHeader: keyID,
		},
		Protected: encodedProtectedHeader,
		Signature: encoding.EncodeToString(signature),
	}
	return &Data{
		Base64: encodedDIDDoc,
		JWS:    &jws,
	}, nil
}

// VerifyAttachmentData takes in a DIDComm `Data` object along with a keyID to validate the data
// It is assumed that the data is a DID Document, which contains the key referenced by the parameter
func VerifyAttachmentData(data Data, keyID string) error {
	docBytes, err := encoding.DecodeString(data.Base64)
	if err != nil {
		return err
	}
	var didDoc did.DIDDoc
	if err := json.Unmarshal(docBytes, &didDoc); err != nil {
		return err
	}
	keyDef := didDoc.GetPublicKey(keyID)
	if keyDef == nil {
		return fmt.Errorf("key not found with id: %s", keyID)
	}
	pubKey, err := base58.Decode(keyDef.PublicKeyBase58)
	if err != nil {
		return err
	}
	verifier := proof.Ed25519Verifier{PubKey: pubKey}
	decodedSignature, err := encoding.DecodeString(data.JWS.Signature)
	if err != nil {
		return err
	}
	valid, err := verifier.Verify([]byte(data.JWS.Protected+"."+data.Base64), decodedSignature)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid signature")
	}
	return nil
}

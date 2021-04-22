package did

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

const (
	KeyDIDMethod = "did:key:"

	// Codec for Ed25519 multi-format
	// https://github.com/multiformats/multicodec
	ed25519Codec = 0xed

	// Encoding for base58btc multi-base
	// https://github.com/multiformats/multibase
	base58btc = "z"

	base58keyPrefix = KeyDIDMethod + base58btc

	// https://tools.ietf.org/html/rfc8037#appendix-A.2
	OctetKeyPairType = "OKP"
	Ed25519Curve     = "Ed25519"
)

var (
	// Use this for all base64 encoding.
	b64 = base64.RawURLEncoding
)

// GenerateDIDKey generates a non-registry based Decentralized DID in the form of "did:key:<id>" based on an Ed25519
// public key. The DID Key Method expands a cryptographic public key into a DID Document.
// Note: As of May 2020, the DID Key method is still in unofficial draft (https://w3c-ccg.github.io/did-method-key)
func GenerateDIDKey(publicKey ed25519.PublicKey) DID {
	var buffer [2]byte
	count := binary.PutUvarint(buffer[:], uint64(ed25519Codec))
	pk := append(buffer[:count], publicKey...)
	return DID(base58keyPrefix + base58.Encode(pk))
}

// GenerateDIDKeyFromB64PubKey converts a base64 encoded Ed25519 public key into a DID Key.
// See GenerateDIDKey.
func GenerateDIDKeyFromB64PubKey(edBase64PubKey string) (did DID, err error) {
	decodedPubKey, err := base64.StdEncoding.DecodeString(edBase64PubKey)
	if err != nil {
		return
	}
	return GenerateDIDKey(decodedPubKey), nil
}

// ExtractEdPublicKeyFromDID extracts an Ed25519 Public Key from a DID Key.
func ExtractEdPublicKeyFromDID(did DID) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did.String(), base58keyPrefix) {
		return nil, fmt.Errorf("DID<%s> format not supported", did)
	}
	decodedKey, err := base58.Decode(did[len(base58keyPrefix):].String())
	if err != nil {
		return nil, errors.New("cannot decode DID")
	}

	if codec, count := binary.Uvarint(decodedKey); codec == ed25519Codec {
		return decodedKey[count:], nil
	}

	return nil, fmt.Errorf("key cannot be extracted from DID<%s>", did)
}

func decodedJWK(jwk JWK) ([]byte, error) {
	switch {
	case jwk.KTY == OctetKeyPairType && jwk.CRV == Ed25519Curve:
		xBytes, err := b64.DecodeString(jwk.X)
		if err != nil {
			return nil, err
		}
		var pubKey ed25519.PublicKey = xBytes
		return pubKey, nil
	default:
		return nil, fmt.Errorf("unsupported JWK type (%s, %s)", jwk.KTY, jwk.CRV)
	}
}

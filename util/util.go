package util

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/mr-tron/base58"
)

const (
	offsetSeq        uint8 = 1
	offsetSeqAndSize uint8 = 2
)

type Emptyable interface {
	IsEmpty() bool
}

type Validateable interface {
	ValidateStatic() error
}

// DeepCopy makes a deep copy from "from" into "to". Unlike a shallow copy, a deep copy
// will follow pointers. The caller should be mindful of the objects that will be created.
func DeepCopy(from interface{}, to interface{}) error {
	if from == nil {
		return errors.New("from cannot be nil")
	}
	if to == nil {
		return errors.New("to cannot be nil")
	}
	if !IsPtrOrSlice(from) {
		return errors.New("to must be a ptr or slice type")
	}
	if !IsPtrOrSlice(to) {
		return errors.New("to must be a ptr or slice type")
	}
	b, err := json.Marshal(from)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, to); err != nil {
		return err
	}
	return nil
}

// IsPtrOrSlice returns true if the object is either a pointer or a slice.
func IsPtrOrSlice(unknown interface{}) bool {
	if unknownType := reflect.TypeOf(unknown); unknownType.Kind() != reflect.Ptr && unknownType.Elem().Kind() != reflect.Slice {
		return false
	}
	return true
}

// JSONBytesEqual compares the JSON in two byte slices for deep equality, ignoring whitespace
// and other non-semantically meaningful formatting differences.
func JSONBytesEqual(a, b []byte) (bool, error) {
	var j1, j2 interface{}
	if err := json.Unmarshal(a, &j1); err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, &j2); err != nil {
		return false, err
	}
	return reflect.DeepEqual(j2, j1), nil
}

// Base64ToBase58 converts a base64 encoded string into a base58 encoded string.
// Returns an error if the original string was not base64 encoded.
func Base64ToBase58(encodedBase64 string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encodedBase64)
	base58Encoded := base58.Encode(decoded)
	return base58Encoded, err
}

// Base64ToBase58 converts a base58 encoded string into a base64 encoded string.
// Returns an error if the original string was not base58 encoded.
func Base58ToBase64(encodedBase58 string) (string, error) {
	decoded, err := base58.Decode(encodedBase58)
	base64Encoded := base64.StdEncoding.EncodeToString(decoded)
	return base64Encoded, err
}

// ExtractPublicKeyFromBase58Der extracts a public key from a base58 encoded
// Distinguished Encoding Rules (DER) formatted string.
func ExtractPublicKeyFromBase58Der(encodedBase58 string) ([]byte, error) {
	der, err := base58.Decode(encodedBase58)
	if err != nil {
		return nil, err
	}

	return extractPublicKey(der)
}

// DER format is [seq:size:MAIN]
// MAIN format is [seq:size:TYPE:seq:size:KEY]
// seq and size are one byte
func extractPublicKey(der []byte) ([]byte, error) {
	main := der[offsetSeqAndSize:]
	keyTypeLength := main[offsetSeq]

	var keyStartingOffset uint8 = offsetSeqAndSize + keyTypeLength
	keyLength := main[keyStartingOffset+offsetSeq]

	key := main[keyStartingOffset+offsetSeqAndSize : keyStartingOffset+offsetSeqAndSize+keyLength]

	if key[0] == 0 {
		return key[1:], nil
	}

	return key, nil
}

func AddNonceToDoc(unsignedDoc []byte, nonce string) []byte {
	var buf bytes.Buffer
	buf.Write(unsignedDoc)
	buf.Write([]byte("." + nonce))
	toSign := buf.Bytes()
	return toSign
}

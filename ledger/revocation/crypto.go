package revocation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/pbkdf2"

	"go.wday.io/credentials-open-source/ledger-common/ledger"
	"go.wday.io/credentials-open-source/ledger-common/util/canonical"
)

const (
	pbkdfIterations      = 1000
	pbkdfSaltSize        = 8
	gcmStandardNonceSize = 12
	aes256KeySize        = 32
)

// BlindRevocation password-encrypts the revocation using the credential ID. Why encrypt revocations? If revocations
// are stored on a public ledger, then it is possible to correlate behaviors of credential issuers by data mining the
// revocation transactions. The purpose of storing the revocation on the ledger is to provide a strong trust anchor for
// monitoring the validity of a credential. This is useful in the context of credentials that have been shared by
// the holder with a set of verifiers. In other words, this information is useful for anybody that has seen the
// credential--presumably with the permission of the holder.  Therefore, we have chosen to use the credential ID as
// the password, since it is a readily available, unique piece of information.
//
// See Blind for details on the encryption scheme.
func BlindRevocation(credentialID string, r *ledger.Revocation) ([]byte, error) {
	jsonBytes, err := canonical.Marshal(r)
	if err != nil {
		return nil, err
	}
	return Blind(credentialID, jsonBytes)
}

// UnblindRevocation decrypts a password-encrypted revocation using the credential ID.
//
// See Blind for details on the encryption scheme.
func UnblindRevocation(bits []byte, credentialID string, r *ledger.Revocation) (err error) {
	opened, err := Unblind(bits, credentialID)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(opened, r); err != nil {
		return err
	}
	return nil
}

// Blind password-encrypts the supplied byte array. The password and a random 8-byte salt are used as inputs to the
// PBKDF2 key generation algorithm, and the resulting key plus a random 12-byte nonce are used to encrypt the payload
// using Galois Counter Mode (GCM) block encryption.  The salt and nonce are prepended to the encrypted output, i.e.
// output = salt + nonce + ciphertext.
func Blind(password string, payload []byte) ([]byte, error) {
	salt := make([]byte, pbkdfSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmStandardNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key := pbkdf2.Key([]byte(password), salt, pbkdfIterations, aes256KeySize, sha512.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, pbkdfSaltSize+gcmStandardNonceSize+len(payload))
	result = append(result, salt...)
	result = append(result, nonce...)
	sealed := gcm.Seal(result, nonce, payload, nil)
	return sealed, nil
}

// Unblind decrypts a password-encrypted object using the supplied password.
//
// See Blind for details on the encryption scheme.
func Unblind(bits []byte, password string) (opened []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("unblinding panic %v", r)
		}
	}()
	salt := bits[0:pbkdfSaltSize]
	nonce := bits[pbkdfSaltSize : gcmStandardNonceSize+pbkdfSaltSize]
	ciphertext := bits[gcmStandardNonceSize+pbkdfSaltSize:]
	key := pbkdf2.Key([]byte(password), salt, pbkdfIterations, aes256KeySize, sha512.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	opened = make([]byte, 0, len(bits))
	opened, err = gcm.Open(opened, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return opened, nil
}

package proof

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

type provableTestData struct {
	A     string `json:"a"`
	B     string `json:"b,omitempty"`
	Proof *Proof `json:"proof,omitempty"`
}

func (t *provableTestData) GetProof() *Proof {
	return t.Proof
}

func (t *provableTestData) SetProof(p *Proof) {
	t.Proof = p
}

func TestSignatureSuiteFactory_GetSuiteForProof(t *testing.T) {
	const (
		vMethod       = "verificationMethod"
		creator       = "creator"
		proofTemplate = `{
			"created": "2020-06-05T01:12:15Z",
			"%s": "key-1",
			"nonce": "015b5f58-ba8d-4da5-b278-b4a095e09e9c",
			"signatureValue": "5Hj1yvfw9LMMd656K2gKxhUfFGNrVUqxyhFGw72ZkYwANtrz3PibuFYQmCSLeAhHfRYmbbHbiyUAmwKxdZtK1YfP",
			"type": "%s"
		}`
	)
	inputs := []struct {
		sigType       SignatureType
		expectedSuite SignatureSuite
		keyRefType    string
		err           bool
	}{
		{sigType: JCSEdSignatureType, expectedSuite: jcsEd25519SignatureSuite, keyRefType: vMethod},
		{sigType: EcdsaSecp256k1SignatureType, expectedSuite: secp256K1SignatureSuite, keyRefType: creator},
		{sigType: WorkEdSignatureType, expectedSuite: workSignatureSuiteV1, keyRefType: creator},
		{sigType: Ed25519KeySignatureType, expectedSuite: ed25519SignatureSuiteV1, keyRefType: creator},
		{sigType: WorkEdSignatureType, expectedSuite: workSignatureSuiteV2, keyRefType: vMethod},
		{sigType: Ed25519KeySignatureType, expectedSuite: ed25519SignatureSuiteV2, keyRefType: vMethod},
		{sigType: JCSEdSignatureType, expectedSuite: jcsEd25519SignatureSuite, keyRefType: creator, err: true},
		{sigType: EcdsaSecp256k1SignatureType, expectedSuite: secp256K1SignatureSuite, keyRefType: vMethod, err: true},
	}
	for _, input := range inputs {
		name := fmt.Sprintf("%s-%s", input.sigType, input.keyRefType)
		t.Run(name, func(t *testing.T) {
			proofJSON := fmt.Sprintf(proofTemplate, input.keyRefType, input.sigType)
			var p Proof
			assert.NoError(t, json.Unmarshal([]byte(proofJSON), &p))
			suite, err := SignatureSuites().GetSuiteForProof(&p)
			if err != nil {
				assert.True(t, strings.Contains(err.Error(), "unsupported signature type"))
			} else {
				assert.NoError(t, err)
				assert.Equal(t, input.expectedSuite, suite)
			}
		})
	}
}

var (
	seed    = []byte("12345678901234567890123456789012")
	privKey = ed25519.NewKeyFromSeed(seed)
	pubKey  = privKey.Public().(ed25519.PublicKey)
)

func TestSignAndVerify(t *testing.T) {
	testJSON := `{
		"a": "hello",
		"b": "world"
	}`

	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)

	signer, err := NewEd25519Signer(privKey, "key-1")
	assert.NoError(t, err)

	verifier := &Ed25519Verifier{PubKey: pubKey}

	suites := map[string]SignatureSuite{
		"JCS":                  jcsEd25519SignatureSuite,
		"WorkV1":               workSignatureSuiteV1,
		"WorkV2":               workSignatureSuiteV2,
		"Ed25519V1":            ed25519SignatureSuiteV1,
		"Ed25519V2":            ed25519SignatureSuiteV2,
		"Ed25519Signature2018": ed255192018SignatureSuite,
	}
	for name, suite := range suites {
		t.Run(name, func(t *testing.T) {
			var provable provableTestData
			assert.NoError(t, json.Unmarshal([]byte(testJSON), &provable))
			assert.NoError(t, suite.Sign(&provable, signer, nil))
			assert.NoError(t, suite.Verify(&provable, verifier))
		})
	}

	t.Run("Secp256K1_Error", func(t *testing.T) {
		var provable provableTestData
		assert.NoError(t, json.Unmarshal([]byte(testJSON), &provable))
		assert.EqualError(t, secp256K1SignatureSuite.Sign(&provable, signer, nil), "incorrect key type")
	})
}

func TestVerify(t *testing.T) {
	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)
	verifier := &Ed25519Verifier{PubKey: pubKey}

	inputs := map[string]string{
		"JCS": `{
			"a": "hello",
			"b": "world",
			"proof": {
				"created": "2020-06-05T01:12:15Z",
				"verificationMethod": "key-1",
				"nonce": "015b5f58-ba8d-4da5-b278-b4a095e09e9c",
				"signatureValue": "5Hj1yvfw9LMMd656K2gKxhUfFGNrVUqxyhFGw72ZkYwANtrz3PibuFYQmCSLeAhHfRYmbbHbiyUAmwKxdZtK1YfP",
				"type": "JcsEd25519Signature2020"
			}
		}`,
		"WorkV1": `{
			"a": "hello",
			"b": "world",
			"proof": {
				"created": "2020-06-05T00:12:14Z",
				"creator": "key-1",
				"nonce": "e11cc825-2de1-4719-a6d8-97ae4b10ab6b",
				"signatureValue": "3zJDnaLEsT2c27AYh1GjdQGPte2ezS5vFxDC2pxgSsXg41ofRwfUK7iPdMxeak3kcruELckU72nNw73MEfcbsiVN",
				"type": "WorkEd25519Signature2020"
			}
		}`,
		"WorkV2": `{
			"a": "hello",
			"b": "world",
			"proof": {
				"created": "2020-06-05T00:13:43Z",
				"verificationMethod": "key-1",
				"nonce": "3acd37af-8e01-4dbe-aa50-32337527c702",
				"signatureValue": "3HY91yqeN6ST8hDq8TyYpfHyNUUtjLjwZLPoe2tH6pZgpFiqZnuycEhiqxz7yJ46mKYuVPEbUTxK9AxBHcWwiCpq",
				"type": "WorkEd25519Signature2020"
			}
		}`,
		"Ed25519Signature2018": `{
  			"a": "hello",
  			"b": "world",
  			"proof": {
    			"created": "2020-11-11T02:20:07Z",
    			"verificationMethod": "key-1",
    			"type": "Ed25519Signature2018",
    			"jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..KbIMwFhIRp_5z1QJMbb1pr_Z6Uu3IR_QF7pNTvLII3Tu0DTGu63K3j387Wdx4YKLxB1I5MrgrmMDT-89SwyRCw"
  			}
		}`,
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			var provable provableTestData
			assert.NoError(t, json.Unmarshal([]byte(input), &provable))

			suite, err := SignatureSuites().GetSuiteForProof(provable.GetProof())
			assert.NoError(t, err)
			assert.NoError(t, suite.Verify(&provable, verifier))

			if provable.GetProof().JWS != "" {
				provable.GetProof().JWS = "bogus"
			}
			if provable.GetProof().SignatureValue != "" {
				provable.GetProof().SignatureValue = "bogus"
			}

			err = suite.Verify(&provable, verifier)
			assert.EqualError(t, err, "signature verification failed")
		})
	}
}

type workEd25519Signer struct {
	Ed25519Signer
}

func (s *workEd25519Signer) Type() KeyType {
	return WorkEdKeyType
}

type workEd25519Verifier struct {
	Ed25519Verifier
}

func (v *workEd25519Verifier) Type() KeyType {
	return WorkEdKeyType
}

func TestCreateAndVerifyJCSEd25519Proof(t *testing.T) {
	testSigner, err := NewEd25519Signer(privKey, "key-ref")
	assert.NoError(t, err)
	testVerifier := &Ed25519Verifier{PubKey: pubKey}

	t.Run("Happy path sign and verify", func(t *testing.T) {
		testData := GenericProvable{JSONData: "testData"}

		suite, err := SignatureSuites().GetSuite(JCSEdSignatureType, V2)
		assert.NoError(t, err)
		// Create and set proof
		err = suite.Sign(&testData, testSigner, nil)
		assert.NoError(t, err)

		err = suite.Verify(&testData, testVerifier)
		assert.NoError(t, err)
	})

	t.Run("Bad pub key - can't verify", func(t *testing.T) {
		testData := GenericProvable{JSONData: "testData"}

		// Create and set proof
		suite, err := SignatureSuites().GetSuite(JCSEdSignatureType, V2)
		assert.NoError(t, err)
		// Create and set proof
		err = suite.Sign(&testData, testSigner, nil)
		assert.NoError(t, err)

		badPubKey := make([]byte, ed25519.PublicKeySize)
		testVerifier := &Ed25519Verifier{PubKey: badPubKey}
		err = suite.Verify(&testData, testVerifier)
		assert.Error(t, err)
	})

	t.Run("Non Ed25519 Signer", func(t *testing.T) {
		testData := GenericProvable{JSONData: "testData"}

		badSigner := &workEd25519Signer{Ed25519Signer: Ed25519Signer{KeyID: "key-ref", PrivateKey: privKey}}
		suite, err := SignatureSuites().GetSuite(JCSEdSignatureType, V2)
		assert.NoError(t, err)

		err = suite.Sign(&testData, badSigner, nil)
		assert.Error(t, err)
	})

	t.Run("Non Ed25519 Verifier", func(t *testing.T) {
		testData := GenericProvable{JSONData: "testData"}

		suite, err := SignatureSuites().GetSuite(JCSEdSignatureType, V2)
		assert.NoError(t, err)

		err = suite.Sign(&testData, testSigner, nil)
		assert.NoError(t, err)

		badVerifier := &workEd25519Verifier{Ed25519Verifier: Ed25519Verifier{PubKey: pubKey}}
		err = suite.Verify(&testData, badVerifier)
		assert.NoError(t, err)
	})
}

func TestEd25519Signature2018(t *testing.T) {
	t.Run("round trip happy path", func(t *testing.T) {
		testData := GenericProvable{
			JSONData: `{"test": "data"}`,
		}

		suite, err := SignatureSuites().GetSuite(Ed25519SignatureType, V2)
		assert.NoError(t, err)

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		assert.NoError(t, err)

		signer, err := NewEd25519Signer(privKey, "https://example.com/i/bob/keys/1")
		opts := &ProofOptions{
			ProofPurpose: AssertionMethodPurpose,
		}
		err = suite.Sign(&testData, signer, opts)
		assert.NoError(t, err)

		verifier := Ed25519Verifier{PubKey: pubKey}

		err = suite.Verify(&testData, &verifier)
		assert.NoError(t, err)
	})

	// Test from https://github.com/transmute-industries/Ed25519Signature2018
	t.Run("Community test vector", func(t *testing.T) {
		provable := `{
  "@context": "https://w3id.org/security/v2",
  "http://schema.org/action": "AuthenticateMe",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2019-01-16T20:13:10Z",
    "challenge": "abc",
    "domain": "example.com",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..Ho9d8ZFfyvAapo7IB7PXnT7e7CgfFywGo1G3T5VEiTtwBfJYbkR2zQdWIUpb_rqKQ9tgQkjd_Ptel_VqOwEbAg",
    "proofPurpose": "authentication",
    "verificationMethod": "https://example.com/i/alice/keys/2"
  }
}`

		var p TestProvable
		err := json.Unmarshal([]byte(provable), &p)
		assert.NoError(t, err)

		pubKeyB58 := "GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq"
		pubKey, err := base58.Decode(pubKeyB58)
		assert.NoError(t, err)

		verifier := Ed25519Verifier{PubKey: pubKey}
		suite, err := SignatureSuites().GetSuiteForProof(p.GetProof())
		assert.NoError(t, err)

		err = suite.Verify(&p, &verifier)
		assert.NoError(t, err)
	})

	t.Run("Sign and verify community test vector", func(t *testing.T) {
		privKeyB58 := "3Mmk4UzTRJTEtxaKk61LxtgUxAa2Dg36jF6VogPtRiKvfpsQWKPCLesKSV182RMmvMJKk6QErH3wgdHp8itkSSiF"
		privKey, err := base58.Decode(privKeyB58)
		assert.NoError(t, err)

		pubKeyB58 := "GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq"
		pubKey, err := base58.Decode(pubKeyB58)
		assert.NoError(t, err)

		var p TestProvable = map[string]interface{}{
			"@context":                 "https://w3id.org/security/v2",
			"http://schema.org/action": "AuthenticateMe",
		}

		suite, err := SignatureSuites().GetSuite(Ed25519SignatureType, V2)
		assert.NoError(t, err)

		signer, err := NewEd25519Signer(privKey, "https://example.com/i/alice/keys/2")
		assert.NoError(t, err)

		opts := &ProofOptions{
			ProofPurpose: AuthenticationPurpose,
			Domain:       "example.com",
			Challenge:    "abc",
		}
		err = suite.Sign(&p, signer, opts)
		assert.NoError(t, err)

		verifier := Ed25519Verifier{PubKey: pubKey}
		err = suite.Verify(&p, &verifier)
		assert.NoError(t, err)
	})
}

type TestProvable map[string]interface{}

func (pr *TestProvable) GetProof() *Proof {
	p := *pr
	proofMap, ok := p["proof"]
	if !ok {
		return nil
	}
	proofBytes, err := json.Marshal(proofMap)
	if err != nil {
		panic(err)
	}
	var proofObj Proof
	if err := json.Unmarshal(proofBytes, &proofObj); err != nil {
		return nil
	}
	return &proofObj
}

func (pr *TestProvable) SetProof(p *Proof) {
	var proofObj interface{}
	proofBytes, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(proofBytes, &proofObj); err != nil {
		panic(err)
	}
	var newPr map[string]interface{}
	prBytes, err := json.Marshal(pr)
	if err != nil {
		panic(err)
	}
	if err = json.Unmarshal(prBytes, &newPr); err != nil {
		panic(err)
	}
	delete(newPr, "proof")
	newPr["proof"] = proofObj
	*pr = newPr
}

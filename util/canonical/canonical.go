package canonical

import (
	"encoding/json"

	jcs "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Marshal wraps json.Marshal and calls the JSON Canonicalization Scheme (JCS) canonicalizer.
func Marshal(input interface{}) ([]byte, error) {
	bytes, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(bytes)
}

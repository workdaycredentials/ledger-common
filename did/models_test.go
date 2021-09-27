package did

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDID_HashCode(t *testing.T) {

	tests := map[string]struct {
		testDidStr  string
		expectedStr string
	}{
		"Short-form of simple work DID": {
			testDidStr:  "did:work:asdfghjklqwerty",
			expectedStr: "did:work:asdfghjklqwerty",
		},
		"Short-form of provisional work DID": {
			testDidStr:  "did:work:provisional:asdfghjklqwerty",
			expectedStr: "did:work:provisional:asdfghjklqwerty",
		},
		"Short-form of simple ion DID": {
			testDidStr:  "did:ion:asdfghjklqwerty",
			expectedStr: "did:ion:asdfghjklqwerty",
		},
		"Short-form of long-form ion DID": {
			testDidStr:  "did:ion:asdfghjklqwerty:zxcvbnmuiop",
			expectedStr: "did:ion:asdfghjklqwerty",
		},
		"Short-form of simple test ion DID": {
			testDidStr:  "did:ion:test:asdfghjklqwerty",
			expectedStr: "did:ion:test:asdfghjklqwerty",
		},
		"Short-form of long-form test ion DID": {
			testDidStr:  "did:ion:test:asdfghjklqwerty:zxcvbnmuiop",
			expectedStr: "did:ion:test:asdfghjklqwerty",
		},
		"Work Cred Def Alias not mangled": {
			testDidStr:  "did:work:KAezjhA6Z7RDaryWB83SfLdid:work:KAezjhA6Z7RDaryWB83SfL#resource=5d7d15fb-c143-41e8-9c64-bfea9a8616ff#version=1.1",
			expectedStr: "did:work:KAezjhA6Z7RDaryWB83SfLdid:work:KAezjhA6Z7RDaryWB83SfL#resource=5d7d15fb-c143-41e8-9c64-bfea9a8616ff#version=1.1",
		},
		"Empty string": {
			testDidStr:  "",
			expectedStr: "",
		}}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.expectedStr, DID(test.testDidStr).HashCode())
		})
	}

}

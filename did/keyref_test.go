package did

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyRef(t *testing.T) {
	var keyRef KeyRef
	assert.NoError(t, roundtrip(t, `"string"`, &keyRef))
	assert.NoError(t, roundtrip(t, `{"id":"value","type":"t","controller":""}`, &keyRef))
	assert.NoError(t, roundtrip(t, `null`, &keyRef))
	assert.EqualError(t, roundtrip(t, `42`, &keyRef), "json: cannot unmarshal number into Go value of type did.KeyDef")
	assert.EqualError(t, roundtrip(t, `syntax error`, &keyRef), "invalid character 's' looking for beginning of value")
	var array []KeyRef
	assert.NoError(t, roundtrip(t, `[null,"nested ref",{"id":"nested","type":"def","controller":""}]`, &array))
	assert.Len(t, array, 3)
}

package did

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func roundtrip(t *testing.T, js string, keyRef interface{}) error {
	if err := json.Unmarshal([]byte(js), keyRef); err != nil {
		return err
	}
	bytes, err := json.Marshal(keyRef)
	require.NoError(t, err)
	assert.Equal(t, js, string(bytes))
	return err
}

func TestStringOrArray(t *testing.T) {
	var soa StringOrArray
	assert.NoError(t, roundtrip(t, `"one string"`, &soa))
	assert.NoError(t, roundtrip(t, `["two","strings"]`, &soa))
	assert.NoError(t, roundtrip(t, `null`, &soa))
	assert.EqualError(t, roundtrip(t, `{"invalid":"type"}`, &soa), "json: cannot unmarshal object into Go value of type []string")
	assert.EqualError(t, roundtrip(t, `2.0`, &soa), "json: cannot unmarshal number into Go value of type []string")
	assert.EqualError(t, roundtrip(t, `syntax error`, &soa), "invalid character 's' looking for beginning of value")
	var array []StringOrArray
	assert.NoError(t, roundtrip(t, `["nested string",["nested","array"]]`, &array))
	assert.Len(t, array, 2)
}

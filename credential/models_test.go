package credential

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeAttributeClaimDataForSigning(t *testing.T) {
	const (
		expectedEncoding           = `eyJtb2RlbFZlcnNpb24iOiIxLjAiLCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6IjllZjFiNjRmLTJmNzktNDFmOC1iZTk3LWE4MzEyNjQ4NDJmNiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiYTE2ODQyMTEtODUzNy00MTJlLWI2ZjUtNzBhMTVkYzZiNmMzIiwiaXNzdWFuY2VEYXRlIjoiMjAxOS0wOS0yMVQwMToxMjoyMloiLCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiY2FlOGEzYmQtZWU4Ni00ZjQ5LTk5ZDYtMGNiYmVlMDc3ZmNjIiwidHlwZSI6Ikpzb25TY2hlbWFWYWxpZGF0b3JXb3JrZGF5MjAxOSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJwZXQiOiJmaWRvIn19`
		expectedCanonicalEndcoding = `eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiY2FlOGEzYmQtZWU4Ni00ZjQ5LTk5ZDYtMGNiYmVlMDc3ZmNjIiwidHlwZSI6Ikpzb25TY2hlbWFWYWxpZGF0b3JXb3JrZGF5MjAxOSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJwZXQiOiJmaWRvIn0sImlkIjoiOWVmMWI2NGYtMmY3OS00MWY4LWJlOTctYTgzMTI2NDg0MmY2IiwiaXNzdWFuY2VEYXRlIjoiMjAxOS0wOS0yMVQwMToxMjoyMloiLCJpc3N1ZXIiOiJhMTY4NDIxMS04NTM3LTQxMmUtYjZmNS03MGExNWRjNmI2YzMiLCJtb2RlbFZlcnNpb24iOiIxLjAiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl19`
	)

	metadata := Metadata{
		ModelVersion: "1.0",
		Context:      []string{W3Context},
		ID:           "9ef1b64f-2f79-41f8-be97-a831264842f6",
		Type:         []string{"VerifiableCredential"},
		Issuer:       "a1684211-8537-412e-b6f5-70a15dc6b6c3",
		IssuanceDate: "2019-09-21T01:12:22Z",
		Schema: Schema{
			ID:   "cae8a3bd-ee86-4f49-99d6-0cbbee077fcc",
			Type: "JsonSchemaValidatorWorkday2019",
		},
	}

	encoding, err := EncodeAttributeClaimDataForSigningOption(metadata, "pet", "fido", false)
	require.NoError(t, err)
	assert.Equal(t, expectedEncoding, string(encoding))

	canonicalEncoding, err := EncodeAttributeClaimDataForSigningOption(metadata, "pet", "fido", true)
	require.NoError(t, err)
	assert.Equal(t, expectedCanonicalEndcoding, string(canonicalEncoding))
}

func TestNewMetadataWithTimestamp(t *testing.T) {
	type args struct {
		id               string
		issuer           string
		schema           string
		offeredTimestamp time.Time
	}
	knownStamp, err := time.Parse(time.RFC3339, "2020-04-29T14:49:25.77922629Z")
	assert.NoError(t, err)
	tests := []struct {
		name    string
		args    args
		want    Metadata
	}{
		{
			name:    "Valid",
			args:    args{
				id:               "id1",
				issuer:           "issuer1",
				schema:           "schema1",
				offeredTimestamp: knownStamp,
			},
			want:    Metadata{
				ModelVersion: ModelVersionV1,
				Context:      []string{W3Context},
				ID:           "id1",
				Type:         []string{Type},
				Issuer:       "issuer1",
				IssuanceDate: knownStamp.Format(time.RFC3339),
				Schema: Schema{
					ID:   "schema1",
					Type: SchemaType,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewMetadataWithTimestamp(tt.args.id, tt.args.issuer, tt.args.schema, tt.args.offeredTimestamp)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewMetadataWithTimestamp() got = %v, want %v", got, tt.want)
			}
		})
	}
}

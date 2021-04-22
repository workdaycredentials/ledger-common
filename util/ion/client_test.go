package ion

import (
	"context"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	challengeJson = `{"challengeNonce":"12","validDurationInMinutes":1,"largestAllowedHash":"0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}`
	createOp      = `{"type":"create"}`
)

type mockTransport []func(*http.Request) (*http.Response, error)

func (mock *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	roundtrip := (*mock)[0]
	*mock = (*mock)[1:]
	return roundtrip(req)
}

func readCloser(body string) io.ReadCloser {
	return ioutil.NopCloser(strings.NewReader(body))
}

func TestHappy(t *testing.T) {
	const dummyDidDoc = `{"id":"did:ion:test"}`

	transport := mockTransport{
		func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, getChallengePath, req.URL.Path)
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, int64(0), req.ContentLength)
			return &http.Response{
				StatusCode: 200,
				Body:       readCloser(challengeJson),
			}, nil
		},
		func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, postOperationPath, req.URL.Path)
			assert.Equal(t, http.MethodPost, req.Method)
			assert.Equal(t, int64(len(createOp)), req.ContentLength)
			assert.Contains(t, "application/json", req.Header.Get("Content-Type"))
			assert.NotEmpty(t, req.Header.Get("Answer-Nonce"))
			assert.Equal(t, "12", req.Header.Get("Challenge-Nonce"))
			return &http.Response{
				StatusCode: 200,
				Body:       readCloser(dummyDidDoc),
			}, nil
		},
	}

	ionClient := IonClient{&http.Client{Transport: &transport}}
	result, err := ionClient.PostOperation(context.Background(), []byte(createOp))
	require.NoError(t, err)
	assert.Equal(t, dummyDidDoc, string(result))
}

func TestFailedChallenge(t *testing.T) {
	transport := mockTransport{
		func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, getChallengePath, req.URL.Path)
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, int64(0), req.ContentLength)
			return &http.Response{
				StatusCode: 500,
				Body:       readCloser("some proxy error"),
			}, nil
		},
	}

	ionClient := IonClient{&http.Client{Transport: &transport}}
	result, err := ionClient.PostOperation(context.Background(), []byte(createOp))
	require.EqualError(t, err, "some proxy error")
	assert.Nil(t, result)
}

func TestFailedCreate(t *testing.T) {
	const errorJson = `{"code":"ion_error_code","message":"human readable"}`

	transport := mockTransport{
		func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, getChallengePath, req.URL.Path)
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, int64(0), req.ContentLength)
			return &http.Response{
				StatusCode: 200,
				Body:       readCloser(challengeJson),
			}, nil
		},
		func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, postOperationPath, req.URL.Path)
			assert.Equal(t, http.MethodPost, req.Method)
			assert.Equal(t, int64(len(createOp)), req.ContentLength)
			assert.Contains(t, "application/json", req.Header.Get("Content-Type"))
			assert.NotEmpty(t, req.Header.Get("Answer-Nonce"))
			assert.Equal(t, "12", req.Header.Get("Challenge-Nonce"))
			return &http.Response{
				StatusCode: 400,
				Body:       readCloser(errorJson),
			}, nil
		},
	}

	ionClient := IonClient{&http.Client{Transport: &transport}}
	result, err := ionClient.PostOperation(context.Background(), []byte(createOp))
	require.EqualError(t, err, "human readable")
	assert.Nil(t, result)
}

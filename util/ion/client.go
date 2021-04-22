package ion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/workdaycredentials/ledger-common/util/ion/pow"
)

const (
	baseUrl           = "https://beta.ion.msidentity.com"
	getChallengePath  = "/api/v1.0/proof-of-work-challenge"
	postOperationPath = "/api/v1.0/operations"
)

type ionApiErrorResponse struct {
	Message   string `json:"message"`
	Date      string `json:"date,omitempty"`
	RequestID string `json:"requestId,omitempty"`
}

func (e ionApiErrorResponse) Error() string {
	return e.Message
}

// IonClient allows posting ION DIDDoc operations to a public ION node
type IonClient struct {
	doer *http.Client
}

// NewIonClient creates a new IonClient with the provided http.Client
func NewIonClient(client *http.Client) IonClient {
	return IonClient{client}
}

func (client IonClient) ionDo(req *http.Request) ([]byte, error) {
	if client.doer == nil {
		client.doer = http.DefaultClient
	}
	resp, err := client.doer.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return body, err
	}
	if resp.StatusCode != http.StatusOK {
		var response ionApiErrorResponse
		if err := json.Unmarshal(body, &response); err != nil {
			// Treat the response as text/plain when parsing as JSON fails
			return nil, errors.New(string(body))
		}
		return nil, response
	}
	return body, nil
}

func (client IonClient) getChallenge(ctx context.Context) (*pow.Challenge, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseUrl+getChallengePath, nil)
	if err != nil {
		logrus.WithContext(ctx).WithError(err).Error("NewRequestWithContext failed")
		return nil, err
	}
	logrus.WithContext(ctx).Debugf("sending request to %s", req.URL)
	body, err := client.ionDo(req)
	if err != nil {
		logrus.WithContext(ctx).WithError(err).Error("Error getting challenge from ION Proxy")
		return nil, err
	}
	challenge := &pow.Challenge{}
	return challenge, json.Unmarshal(body, challenge)
}

func (client IonClient) postOperation(ctx context.Context, op []byte, answerNonce, challengeNonce string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseUrl+postOperationPath, bytes.NewReader(op))
	if err != nil {
		logrus.WithContext(ctx).WithError(err).Error("NewRequestWithContext failed")
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Answer-Nonce", answerNonce)
	req.Header.Set("Challenge-Nonce", challengeNonce)
	logrus.WithContext(ctx).Debugf("sending request to %s", req.URL)
	body, err := client.ionDo(req)
	if err != nil {
		logrus.WithContext(ctx).WithError(err).Error("Error making write request to ION Proxy")
		return nil, err
	}

	logrus.WithContext(ctx).WithField("body", string(body)).Infof("Response from ION Proxy write")
	return body, nil
}

// PostOperation sends a serialized operation to the ION node
func (client IonClient) PostOperation(ctx context.Context, op []byte) ([]byte, error) {
	challenge, err := client.getChallenge(ctx)
	if err != nil {
		return nil, err
	}
	answerNonce, err := pow.CalculateAnswerNonce(ctx, *challenge, op, 0)
	if err != nil {
		return nil, err
	}
	return client.postOperation(ctx, op, answerNonce, challenge.ChallengeNonceHex)
}

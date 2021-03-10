package didcomm

import "go.wday.io/credentials-open-source/ledger-common/did"

// Implementation based on https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange

const (
	ExchangeInvitation = "https://didcomm.org/didexchange/1.0/invitation"
	ExchangeRequest    = "https://didcomm.org/didexchange/1.0/request"
	ExchangeResponse   = "https://didcomm.org/didexchange/1.0/response"
	ExchangeComplete   = "https://didcomm.org/didexchange/1.0/complete"
	ExchangeProblem    = "https://didcomm.org/didexchange/1.0/problem_report"
)

type ProblemCode string

const (
	RequestNotAccepted      ProblemCode = "request_not_accepted"
	RequestProcessingError  ProblemCode = "request_processing_error"
	ResponseNotAccepted     ProblemCode = "response_not_accepted"
	ResponseProcessingError ProblemCode = "response_processing_error"
)

type Exchange struct {
	ID              string      `json:"@id"`
	Type            []string    `json:"@type"`
	Thread          Thread      `json:"~thread,omitempty"`
	Label           string      `json:"label,omitempty"`
	ServiceEndpoint did.URI     `json:"serviceEndpoint,omitempty"`
	KID             string      `json:"kid,omitempty"`
	DID             did.DID     `json:"did,omitempty"`
	Attachment      Attachment  `json:"did_doc~attach,omitempty"`
	LogoURL         did.URI     `json:"logoUrl,omitempty"`
	ConnectionName  string      `json:"connectionName,omitempty"`
	ContactURL      did.URI     `json:"contactUrl,omitempty"`
	ProblemCode     ProblemCode `json:"problemCode,omitempty"`
	Explain         string      `json:"explain,omitempty"`
}

type Metadata struct {
	Comment string `json:"comment,omitempty"`
	Type    string `json:"type,omitempty"`
	ID      string `json:"id,omitempty"`
}

type Thread struct {
	ThreadID       string `json:"thid,omitempty"`
	ParentThreadID string `json:"pthid,omitempty"`
}

// Attachment is a structure used to attach Base64 encoded data to DIDComm messages. By convention, attachments,
// embedded or appended  to json requests, have the key names that ends with the attachment decorator ("~attach").
// Attachments can be signed (with JWS) or unsigned. Follows the Aries RFC 0017: Attachments protocol.
type Attachment struct {
	ID       string `json:"@id,omitempty"`
	MimeType string `json:"mime-type,omitempty"`
	Data     Data   `json:"data"`
}

// Data contains the base64 encoded data and an optional JWS.
type Data struct {
	Base64 string `json:"base64"`
	JWS    *JWS   `json:"jws,omitempty"`
}

// JWS Structure is JWS (RFC 7515) format and used for signing data.
type JWS struct {
	Header    map[string]interface{} `json:"header"`
	Protected string                 `json:"protected"`
	Signature string                 `json:"signature"`
}

func (jws *JWS) SetKID(kid string) {
	if jws.Header == nil {
		jws.Header = make(map[string]interface{})
	}
	jws.Header["kid"] = kid
}

// Specific message inputs

type ExchangeInvitationInput struct {
	AdditionalContexts []string
	Label              string
	KID                string  `validate:"required"`
	ServiceEndpoint    did.URI `validate:"required"`
	LogoURL            did.URI `validate:"required"`
	ConnectionName     string  `validate:"required"`
	ContactURL         did.URI `validate:"required"`
}

type ExchangeRequestResponseInput struct {
	AdditionalContexts []string
	Label              string
	DID                did.DID `validate:"required"`
	LogoURL            did.URI `validate:"required"`
	ConnectionName     string  `validate:"required"`
	ContactURL         did.URI `validate:"required"`
	ParentThreadID     string  `validate:"required"`
	AttachmentData     Data    `validate:"required"`
}

type ExchangeCompleteInput struct {
	Label          string
	ParentThreadID string `validate:"required"`
}

type ExchangeProblemInput struct {
	Label          string
	ParentThreadID string      `validate:"required"`
	ProblemCode    ProblemCode `validate:"required"`
	Explain        string      `validate:"required"`
}

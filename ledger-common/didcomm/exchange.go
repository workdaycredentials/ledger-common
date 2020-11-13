package didcomm

import (
	"github.com/google/uuid"
	"gopkg.in/go-playground/validator.v9"
)

func CreateExchangeInvitation(input ExchangeInvitationInput) (*Exchange, error) {
	if err := validator.New().Struct(input); err != nil {
		return nil, err
	}
	threadID := uuid.New().String()
	return &Exchange{
		ID:              threadID,
		Type:            append([]string{ExchangeInvitation}, input.AdditionalContexts...),
		Label:           input.Label,
		ServiceEndpoint: input.ServiceEndpoint,
		LogoURL:         input.LogoURL,
		ConnectionName:  input.ConnectionName,
		ContactURL:      input.ContactURL,
		KID:             input.KID,
		Thread: Thread{
			ThreadID: threadID,
		},
	}, nil
}

func CreateExchangeRequest(input ExchangeRequestResponseInput) (*Exchange, error) {
	if err := validator.New().Struct(input); err != nil {
		return nil, err
	}
	threadID := uuid.New().String()
	return &Exchange{
		ID:   threadID,
		Type: append([]string{ExchangeRequest}, input.AdditionalContexts...),
		Thread: Thread{
			ThreadID:       threadID,
			ParentThreadID: input.ParentThreadID,
		},
		Label: input.Label,
		DID:   input.DID,
		Attachment: Attachment{
			ID:       uuid.New().String(),
			MimeType: "application/json",
			Data:     input.AttachmentData,
		},
		LogoURL:        input.LogoURL,
		ConnectionName: input.ConnectionName,
		ContactURL:     input.ContactURL,
	}, nil
}

func CreateExchangeResponse(input ExchangeRequestResponseInput) (*Exchange, error) {
	if err := validator.New().Struct(input); err != nil {
		return nil, err
	}
	threadID := uuid.New().String()
	return &Exchange{
		ID:   threadID,
		Type: append([]string{ExchangeResponse}, input.AdditionalContexts...),
		Thread: Thread{
			ThreadID:       threadID,
			ParentThreadID: input.ParentThreadID,
		},
		Label: input.Label,
		DID:   input.DID,
		Attachment: Attachment{
			ID:       uuid.New().String(),
			MimeType: "application/json",
			Data:     input.AttachmentData,
		},
		LogoURL:        input.LogoURL,
		ConnectionName: input.ConnectionName,
		ContactURL:     input.ContactURL,
	}, nil
}

func CreateExchangeComplete(input ExchangeCompleteInput) (*Exchange, error) {
	if err := validator.New().Struct(input); err != nil {
		return nil, err
	}
	threadID := uuid.New().String()
	return &Exchange{
		ID:   threadID,
		Type: []string{ExchangeComplete},
		Thread: Thread{
			ThreadID:       threadID,
			ParentThreadID: input.ParentThreadID,
		},
		Label: input.Label,
	}, nil
}

func CreateExchangeProblem(input ExchangeProblemInput) (*Exchange, error) {
	if err := validator.New().Struct(input); err != nil {
		return nil, err
	}
	threadID := uuid.New().String()
	return &Exchange{
		ID:   threadID,
		Type: []string{ExchangeProblem},
		Thread: Thread{
			ThreadID:       threadID,
			ParentThreadID: input.ParentThreadID,
		},
		Label:       input.Label,
		ProblemCode: input.ProblemCode,
		Explain:     input.Explain,
	}, nil
}

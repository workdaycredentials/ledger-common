package didcomm

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
)

func TestCreateExchangeMessages(t *testing.T) {
	t.Run("Test Create Exchange Request", func(t *testing.T) {
		doc, _, privKey2 := generateDIDDocMultipleKeys(proof.JCSEdSignatureType)
		data, err := CreateAttachmentData(doc.PublicKey[1].ID, *doc, privKey2)
		assert.NoError(t, err)

		input := ExchangeRequestResponseInput{
			AdditionalContexts: []string{"https://lcn-context.com/placeholder.json"},
			Label:              "Sample Exchange Request",
			DID:                doc.ID,
			LogoURL:            "logoURL",
			ConnectionName:     "Test Connection",
			ContactURL:         "https://mywayto.com",
			ParentThreadID:     "test-pthread-id",
			AttachmentData:     *data,
		}

		exchangeRequest, err := CreateExchangeRequest(input)
		assert.NoError(t, err)
		assert.NotEmpty(t, exchangeRequest)
	})

	t.Run("Test Create Problem", func(t *testing.T) {
		problemInput := ExchangeProblemInput{
			Label:          "Problem",
			ParentThreadID: uuid.New().String(),
			ProblemCode:    RequestNotAccepted,
			Explain:        "Request malformed",
		}
		problem, err := CreateExchangeProblem(problemInput)
		assert.NoError(t, err)
		assert.NotEmpty(t, problem)
	})
}

func TestEndToEndExchange(t *testing.T) {
	// Create Inviter and Invitee DID Docs
	inviterDoc, inviterPrivKey := did.GenerateWorkDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
	inviteeDoc, inviteePrivKey := did.GenerateWorkDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)

	// 1. Create invitation (inviter)
	kidForInvitee := fmt.Sprintf("%s#key-%s", inviterDoc.ID, uuid.New().String())
	invitationInput := ExchangeInvitationInput{
		AdditionalContexts: []string{"https://test-context.com/test.json"},
		Label:              "Invitation",
		KID:                kidForInvitee,
		ServiceEndpoint:    "https://serviceendpoint.com/service",
		LogoURL:            "https://logoendpoint.com/logo.png",
		ConnectionName:     "Test Connection",
		ContactURL:         "https://testcontact.com",
	}
	invitation, err := CreateExchangeInvitation(invitationInput)
	assert.NoError(t, err)
	assert.NotEmpty(t, invitation)

	// Create keypair with KID in invitation (invitee)
	inviteePubKey2, inviteePrivKey2, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)

	newKeyDef := did.KeyDef{
		ID:              invitation.KID,
		Type:            proof.Ed25519KeyType,
		Controller:      inviterDoc.ID,
		PublicKeyBase58: base58.Encode(inviteePubKey2),
	}

	// Add new key to invitee DID Doc
	updatedInviteeDoc, err := did.AddKeyToDIDDoc(*inviteeDoc, newKeyDef, inviteePrivKey, inviteeDoc.PublicKey[0].ID)
	assert.NoError(t, err)

	// 2. Respond to invitation with request (invitee)
	// Create signed attachment with DID Doc
	data, err := CreateAttachmentData(updatedInviteeDoc.PublicKey[1].ID, *updatedInviteeDoc, inviteePrivKey2)
	assert.NoError(t, err)

	requestInput := ExchangeRequestResponseInput{
		AdditionalContexts: []string{"https://test-context.com/test.json"},
		Label:              "Request",
		DID:                updatedInviteeDoc.ID,
		LogoURL:            "https://logoendpoint.com/logo.png",
		ConnectionName:     "Test Connection",
		ContactURL:         "https://testcontact.com",
		ParentThreadID:     invitation.Thread.ThreadID,
		AttachmentData:     *data,
	}
	request, err := CreateExchangeRequest(requestInput)
	assert.NoError(t, err)

	// 3. Validate request & respond (inviter)
	requestKID := request.Attachment.Data.JWS.Header[kidHeader]
	assert.Equal(t, kidForInvitee, requestKID)
	err = VerifyAttachmentData(request.Attachment.Data, requestKID.(string))
	assert.NoError(t, err)

	// Generate new keypair and update DID Doc
	// Create keypair with KID in invitation (invitee)
	inviterPubKey2, inviterPrivKey2, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)

	kidForInviter := fmt.Sprintf("%s#key-%s", inviteeDoc.ID, uuid.New().String())
	newInviterKeyDef := did.KeyDef{
		ID:              kidForInviter,
		Type:            proof.Ed25519KeyType,
		Controller:      inviteeDoc.ID,
		PublicKeyBase58: base58.Encode(inviterPubKey2),
	}

	// Add new key to invitee DID Doc
	updatedInviterDoc, err := did.AddKeyToDIDDoc(*inviterDoc, newInviterKeyDef, inviterPrivKey, inviterDoc.PublicKey[0].ID)
	assert.NoError(t, err)

	// 2. Respond to invitation with request (invitee)
	// Create signed attachment with DID Doc
	data, err = CreateAttachmentData(updatedInviterDoc.PublicKey[1].ID, *updatedInviterDoc, inviterPrivKey2)
	assert.NoError(t, err)

	responseInput := ExchangeRequestResponseInput{
		AdditionalContexts: []string{"https://test-context.com/test.json"},
		Label:              "Response",
		DID:                updatedInviterDoc.ID,
		LogoURL:            "https://logoendpoint.com/logo.png",
		ConnectionName:     "Test Connection",
		ContactURL:         "https://testcontact.com",
		ParentThreadID:     request.Thread.ParentThreadID,
		AttachmentData:     *data,
	}
	response, err := CreateExchangeResponse(responseInput)
	assert.NoError(t, err)

	// 4. Validate response & send completion (invitee)
	responseKID := response.Attachment.Data.JWS.Header[kidHeader]
	assert.Equal(t, kidForInviter, responseKID)
	err = VerifyAttachmentData(response.Attachment.Data, responseKID.(string))
	assert.NoError(t, err)

	completeInput := ExchangeCompleteInput{
		Label:          "Complete",
		ParentThreadID: response.Thread.ParentThreadID,
	}
	complete, err := CreateExchangeComplete(completeInput)
	assert.NoError(t, err)
	assert.NotEmpty(t, complete)
}

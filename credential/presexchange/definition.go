package presexchange

import (
	"github.com/decentralized-identity/presentation-exchange-implementations/pkg/definition"

	"github.com/workdaycredentials/ledger-common/proof"
)

type PresentationRequest struct {
	ID         string
	Definition definition.PresentationDefinition
	Proof      *proof.Proof
}

// tell the compiler we're complying with the Provable interface
var _ proof.Provable = &PresentationRequest{}

func (p *PresentationRequest) GetProof() *proof.Proof {
	return p.Proof
}

func (p *PresentationRequest) SetProof(pr *proof.Proof) {
	p.Proof = pr
}
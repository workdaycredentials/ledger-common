package presexchange

import (
	"github.com/decentralized-identity/presentation-exchange-implementations/pkg/definition"

	"go.wday.io/credentials-open-source/ledger-common/proof"
)

// PresentationRequest: an instance of a presentation definition, looking to be formalized in
// the W3C as a "Verifiable Request". May be expanded to include any arbitrary metadata.
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
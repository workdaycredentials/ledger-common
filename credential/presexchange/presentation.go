package presexchange

import (
	"reflect"

	"github.com/decentralized-identity/presentation-exchange-implementations/pkg/submission/verifiablepresentation"

	"github.com/workdaycredentials/ledger-common/proof"
)

// Alias to allow  us to extend the library's type
type VerifiablePresentation verifiablepresentation.VerifiablePresentation

// tell the compiler we're complying with the Provable interface
var _ proof.Provable = &VerifiablePresentation{}

func (v *VerifiablePresentation) IsEmpty() bool {
	if v == nil {
		return true
	}
	return reflect.DeepEqual(v, &VerifiablePresentation{})
}

func (v *VerifiablePresentation) GetProof() *proof.Proof {
	if v == nil || v.Proof == nil {
		return nil
	}
	return v.Proof.(*proof.Proof)
}

func (v *VerifiablePresentation) SetProof(p *proof.Proof) {
	v.Proof = p
}

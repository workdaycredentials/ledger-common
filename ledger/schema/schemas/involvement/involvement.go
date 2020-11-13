package involvement

import "github.com/workdaycredentials/ledger-common/ledger/schema/schemas"

const name = "involvement"

var Involvement, InvolvementMeta = schemas.GetSchemasOrPanic(name)

package involvement

import "go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas"

const name = "involvement"

var Involvement, InvolvementMeta = schemas.GetSchemasOrPanic(name)

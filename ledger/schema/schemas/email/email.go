package email

import "go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas"

const name = "email"

var Email, EmailMeta = schemas.GetSchemasOrPanic(name)

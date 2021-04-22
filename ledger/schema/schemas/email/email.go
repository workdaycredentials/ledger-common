package email

import "github.com/workdaycredentials/ledger-common/ledger/schema/schemas"

const name = "email"

var Email, EmailMeta = schemas.GetSchemasOrPanic(name)

package phonenumber

import "github.com/workdaycredentials/ledger-common/ledger/schema/schemas"

const name = "phonenumber"

var PhoneNumber, PhoneNumberMeta = schemas.GetSchemasOrPanic(name)

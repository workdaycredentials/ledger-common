package phonenumber

import "go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas"

const name = "phonenumber"

var PhoneNumber, PhoneNumberMeta = schemas.GetSchemasOrPanic(name)

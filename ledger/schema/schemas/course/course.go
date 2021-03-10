package course

import "go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas"

const name = "course"

var Course, CourseMeta = schemas.GetSchemasOrPanic(name)

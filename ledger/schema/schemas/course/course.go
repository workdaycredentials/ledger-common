package course

import "github.com/workdaycredentials/ledger-common/ledger/schema/schemas"

const name = "course"

var Course, CourseMeta = schemas.GetSchemasOrPanic(name)

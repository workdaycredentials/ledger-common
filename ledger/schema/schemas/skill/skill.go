package skill

import "github.com/workdaycredentials/ledger-common/ledger/schema/schemas"

const name = "skill"

var Skill, SkillMeta = schemas.GetSchemasOrPanic(name)

package skill

import "go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas"

const name = "skill"

var Skill, SkillMeta = schemas.GetSchemasOrPanic(name)

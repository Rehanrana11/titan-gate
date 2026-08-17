# SELFTEST REGISTER — KNOWN-BAD FIXTURE

Four incident rows. Three are usable; one is explicitly unusable and must be
excluded from the V2 coverage universe rather than silently dropped.

| id | class | name | evidence quote |
|---|---|---|---|
| I-1 | environment | assumed a build tool was installed | "run make test" |
| I-2 | reading | derived a plan before reading the deciding document | "picked the phase list" |
| I-3 | provenance | invented a source tag | "[MEASURED: conversation export]" |
| I-4 | unknown | UNUSABLE -- no evidence quote recorded | none |

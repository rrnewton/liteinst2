# Product skills

Each package has one canonical body here. `.llms/skills` points to this
directory; `.agents/skills/<name>` points to the complete matching package.
Keep resources beside their owning skill so all clients read the same bytes.

| Task | Skill |
| --- | --- |
| Select build, test or package checks | [development](development/SKILL.md) |
| Change publication or executable lifetime | [patching-contracts](patching-contracts/SKILL.md) |
| Select or extend an instrumentation frontend | [instrumentation-frontends](instrumentation-frontends/SKILL.md) |

After editing a package, check its frontmatter, local links and discovery
aliases. Product contracts remain in the linked source and reference documents.

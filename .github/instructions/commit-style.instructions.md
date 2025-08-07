---
applyTo: '**'
---

# Commit Message Style

## Conventional Commits

All commits must follow [Conventional Commits](https://www.conventionalcommits.org) format:

```
<type>(<scope>): <description>
```

## Commit Components

### Type

One of: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`

### Scope

Use a noun in parentheses (e.g., `(cli)`, `(api)`, `(deps)`). Required for all commits.

### Description

- Imperative mood ("add", not "added")
- No period at the end
- ≤72 characters, capitalized, clear and specific

## Optional Components

### Body

- Start after a blank line
- Use itemized lists for multiple changes
- Explain what/why, not how

### Footer

- Start after a blank line
- Use for issue refs (`Closes #123`) or breaking changes (`BREAKING CHANGE:`)

## Breaking Changes

- Add `!` after type/scope (e.g., `feat(api)!: ...`) or use `BREAKING CHANGE:` in footer

## Examples

- `feat(cli): add support for custom config path`
- `fix(api): handle nil pointer in hashcat session`
- `docs: update README with install instructions`
- `refactor(models): simplify agent state struct`

## CI Compatibility

- All commits must pass linting and validation
- Use `chore:` for meta or maintenance changes

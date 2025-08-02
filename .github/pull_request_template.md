# Pull Request

## Description

<!-- Provide a clear and concise description of the changes -->

## Type of Change

- [ ] **Bug fix** (non-breaking change which fixes an issue)
- [ ] **New feature** (non-breaking change which adds functionality)
- [ ] **Breaking change** (fix or feature that would cause existing functionality to not work as expected)
- [ ] **Documentation update** (changes to documentation only)
- [ ] **Refactoring** (no functional changes, code improvements)
- [ ] **Performance improvement** (improves performance without changing functionality)
- [ ] **Test addition/update** (adding or updating tests)
- [ ] **Build/CI change** (changes to build system or CI configuration)

## Related Issues

<!-- Link to any related issues using keywords like "Closes #123", "Fixes #456", "Addresses #789" -->

Closes #
Fixes #
Addresses #

## Testing

### Pre-submission Checklist

- [ ] **Code Quality**: All code follows Go formatting standards (`gofmt`)
- [ ] **Linting**: All linting issues resolved (`golangci-lint`)
- [ ] **Tests**: Tests pass with >80% coverage (`go test ./...`)
- [ ] **Error Handling**: Proper error handling with context implemented
- [ ] **Logging**: Structured logging used where appropriate
- [ ] **Documentation**: New functions and types documented following Go conventions
- [ ] **Dependencies**: Dependencies properly managed (`go mod tidy`)
- [ ] **Security**: No hardcoded secrets or credentials
- [ ] **Input Validation**: Input validation implemented where needed

### Test Commands Executed

```bash
# Format and lint
just format
just lint

# Run tests
just test

# Comprehensive validation
just ci-check
```

### Test Results

<!-- Provide test output or summary -->

## Changes Made

### Files Modified

<!-- List the main files that were changed -->

### Key Changes

<!-- Describe the key changes made -->

## Review Checklist

### For Reviewers

- [ ] **Code Quality**: Code follows project conventions and Go standards
- [ ] **Architecture**: Changes align with project architecture patterns
- [ ] **Security**: No security vulnerabilities introduced
- [ ] **Performance**: No performance regressions
- [ ] **Documentation**: Documentation updated if needed
- [ ] **Testing**: Adequate test coverage provided
- [ ] **Breaking Changes**: Breaking changes properly documented

### For Contributors

- [ ] **Self Review**: Code has been self-reviewed
- [ ] **Commit Messages**: Follow conventional commit format
- [ ] **Branch Naming**: Branch follows naming convention (`feat/`, `fix/`, `docs/`, etc.)
- [ ] **Scope**: Changes are focused and not too broad
- [ ] **Dependencies**: No unnecessary dependencies added

## Documentation

### Documentation Updates

<!-- List any documentation files that need to be updated -->

- [ ] README.md
- [ ] CONTRIBUTING.md
- [ ] DEVELOPMENT_STANDARDS.md
- [ ] ARCHITECTURE.md
- [ ] Project specification files

### API Changes

<!-- Document any API changes if applicable -->

## Breaking Changes

<!-- If this PR includes breaking changes, document them here -->

### Migration Guide

<!-- Provide migration steps if breaking changes are introduced -->

## Security Considerations

<!-- Document any security implications -->

## Performance Impact

<!-- Document any performance implications -->

## Acceptance Criteria

<!-- List the acceptance criteria for this PR -->

- [ ] Criterion 1
- [ ] Criterion 2
- [ ] Criterion 3

## Additional Notes

<!-- Any additional information that reviewers should know -->

## Labels

<!-- Add appropriate labels for this PR -->

- `bug-fix` / `enhancement` / `documentation` / `refactoring`
- `breaking-change` (if applicable)
- `security` (if security-related)
- `performance` (if performance-related)

---

**By submitting this pull request, I confirm that:**

- [ ] I have read and followed the [Contributing Guide](CONTRIBUTING.md)
- [ ] I have read and followed the [Development Standards](DEVELOPMENT_STANDARDS.md)
- [ ] My code follows the project's coding standards
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] I have updated the documentation accordingly
- [ ] My changes generate no new warnings
- [ ] I have checked my code and corrected any misspellings

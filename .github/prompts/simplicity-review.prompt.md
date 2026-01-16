---
agent: agent
name: Simplicity Review
description: This prompt is used to review and simplify code changes by applying principles of simplicity, idiomatic coding, and test proportionality.
model: OpenAI GPT-5.2-Codex
---

CODE SIMPLIFICATION REVIEW

Start by examining the uncommitted changes (or the changes in the current branch if there are no uncommitted changes) in the current codebase.

ANALYSIS STEPS:

1. Identify what files have been modified or added
2. Review the actual code changes
3. Apply simplification principles below
4. Refactor directly, then show what you changed

SIMPLIFICATION PRINCIPLES:

Complexity Reduction:

- Remove abstraction layers that don't provide clear value
- Replace complex patterns with straightforward implementations
- Use language idioms over custom abstractions
- If a simple function/lambda works, use it—don't create classes

Test Proportionality:

- Keep only tests for critical functionality and real edge cases
- Delete tests for trivial operations, framework behavior, or hypothetical scenarios
- For small projects: aim for \<10 meaningful tests per feature
- Test code should be shorter than implementation

Idiomatic Code:

- Use conventional patterns for the language
- Prioritize readability and maintainability
- Apply the principle of least surprise

Ask yourself: "What's the simplest version that actually works reliably?"

Make the refactoring changes, then summarize what you simplified and why. Always finish by running `just ci-check` and ensuring that all checks and tests remain green.

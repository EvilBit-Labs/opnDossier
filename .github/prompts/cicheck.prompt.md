---
agent: agent
name: Continuous Integration Check
description: This prompt is used to run and fix issues identified by the continuous integration check command.
model: OpenAI GPT-5.2-Codex (copilot)
---

Run `just ci-check` and analyze any failures or warnings. If there are any issues, fix them and run the command again. Continue this process until `just ci-check` passes completely without any failures or warnings. Focus on:

1. Linting errors
2. Test failures
3. Formatting issues
4. Security issues
5. ERB template issues

After each fix, re-run `just ci-check` to verify the changes resolved the issues. Only stop when all checks pass successfully. Provide a summary of the changes made to fix the issues once `just ci-check` passes.

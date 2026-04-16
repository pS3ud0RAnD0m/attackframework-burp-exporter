# Contributing

Thanks for your interest in contributing.

## Before You Start

- Use Discussions for questions and design discussion
- Use Issues for bugs and feature requests
- Use GitHub Private Vulnerability Reporting for security issues
- Read the [README](../README.md) for project context and the repository wiki for user-facing documentation

## Contribution Guidelines

- Keep changes minimal and focused
- Do not modify unrelated code
- Preserve existing formatting, structure, and layout
- Follow existing naming and project conventions
- Discuss larger changes before opening a pull request
- Prefer small pull requests that are easy to review and test

## Testing

- For code changes, run the full build from the repository root:
  - `.\gradlew.bat clean build -DOPENSEARCH_USER=admin -DOPENSEARCH_PASSWORD=admin`
- Use `opensearch.url` (or your configured OpenSearch URL) for testing instead of `localhost`
- Ensure the extension loads in Burp Suite without errors
- Validate UI changes visually
- Include reproduction steps for bug fixes where applicable
- Prefer `build/tmp/...` for test-created files and directories instead of raw OS temp locations

## Pull Requests

- Clearly describe what changed and why
- Reference related issues or discussions if applicable
- Include screenshots for UI changes
- Call out any OpenSearch, file-export, or Burp-edition-specific behavior changes
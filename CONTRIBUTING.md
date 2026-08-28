# Contributing

Thank you for improving DSH Session Lab. This project accepts focused fixes, tests, documentation, and compatibility updates for current DeepSeek Harness releases.

## Before opening a change

- Search existing issues and keep one concern per change.
- Use only synthetic fixtures. Never commit real DSH exports, credentials, customer data, internal URLs, employee identifiers, or private patches.
- For behavior changes, describe the user-visible problem, compatibility impact, and the smallest useful acceptance test.
- Security reports must follow [SECURITY.md](SECURITY.md), not a public issue.

## Development

Use Python 3.10+ and Node.js 22.19+ or 24+.

```bash
python3 -m pip install -r requirements-dev.txt
npm run verify
npm run test:eval
npm pack --dry-run
```

Changes to parsing, redaction, archive handling, evaluation evidence, or release contents require a regression test. Keep the helper scripts on the Python standard library unless a dependency is clearly justified.

## Pull requests

A pull request should:

- explain the problem and the chosen behavior;
- list relevant tests and their results;
- call out privacy, compatibility, or migration risk;
- update `CHANGELOG.md` for user-visible changes;
- avoid unrelated formatting or generated files.

By contributing, you agree that your contribution is licensed under the repository's MIT License.

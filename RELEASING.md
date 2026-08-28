# Releasing

The source tree can be reviewed and tested without a public host. Before the first public repository or npm release, complete every item below.

## Repository preparation

- Choose a public maintainer identity and repository URL; do not reuse a private corporate identity by accident.
- Add the real `repository`, `homepage`, and `bugs.url` fields to `package.json` after the repository exists. Never publish placeholder URLs.
- Enable GitHub private vulnerability reporting and confirm the **Report a vulnerability** button is visible.
- Protect the default branch, require CI, and review the complete first commit for private data.
- Create a signed `v0.1.0` tag from the reviewed commit.

## Release gates

```bash
npm run release:check
coverage run --branch -m pytest
coverage report --fail-under=60
trufflehog filesystem . --fail --no-update
```

Build twice in clean temporary directories and require identical SHA-256 values. Install the resulting tarball into a new `DSH_HOME` using the current `@deepseek-ai/dsh@latest`, verify the composed layer, and run one real Headless Skill-loading session.

## npm publication

- Confirm `npm view --registry=https://registry.npmjs.org/ dsh-session-lab` still returns `E404`; package-name availability is not reserved until publication.
- Authenticate to the public npm registry with an account protected by MFA.
- Prefer a GitHub Actions trusted publisher so npm provenance is generated without a long-lived token.
- Inspect `npm pack --dry-run --json` and publish the exact reviewed artifact.
- Verify the public package, integrity hash, README, license, and install command after publication.

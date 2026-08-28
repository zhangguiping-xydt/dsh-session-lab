## What Problem This Solves

Describe the user-visible problem, trigger, and expected behavior.

## Why This Change Was Made

Explain the root cause and why this is the smallest safe fix. Call out compatibility, privacy, and security implications.

## User Impact

Describe who benefits, any changed behavior, migration needs, and known limitations.

## Evidence

List focused tests, full verification, real-runtime proof, and any deliberately unverified boundary. Link synthetic reproductions only; never include credentials or private exports.

## Submission checklist

- [ ] `npm run verify`
- [ ] `npm run test:eval` when evaluation behavior changes
- [ ] `npm pack --dry-run`
- [ ] Fixtures and examples contain synthetic public data only
- [ ] `CHANGELOG.md` updated for user-visible changes

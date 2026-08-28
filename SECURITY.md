# Security Policy

## Supported versions

This project is pre-1.0. Security fixes are provided for the latest published `0.1.x` release only. Older snapshots and unpublished development builds are unsupported.

## Scope

This repository contains local tooling that reads DSH Session exports, JSONL, ZIP archives, patches, and selected artifacts. It does not authenticate to DSH, create production records, or execute files from a capsule.

## Reporting a vulnerability

Do not include real Session exports, credentials, customer data, internal URLs, or private patches in a public issue.

Use GitHub private vulnerability reporting for the repository hosting this project: open the repository's **Security** tab, choose **Advisories**, then **Report a vulnerability**. Public release owners must enable this channel before making the repository public. If the button is unavailable, do not open a public issue; contact a listed repository maintainer and ask for a private reporting channel without including vulnerability details.

Include:

- affected Skill and file/version;
- reproducible input using synthetic data where possible;
- impact and expected behavior;
- a proposed mitigation if available.

Maintainers should acknowledge a report within seven calendar days, provide an initial assessment within fourteen days, and coordinate disclosure after a fix is available. These are response targets, not a guarantee.

## Data handling

The `share` mode uses deterministic replacement patterns and known-ID aliasing, but it cannot prove that arbitrary business data or images are safe to publish. Review the unpacked files manually. A `.dshc` SHA-256 verifies integrity only; it does not authenticate the publisher.

# DSH Session Lab

English | [中文](README.zh-CN.md)

[![CI](https://github.com/zhangguiping-xydt/dsh-session-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/zhangguiping-xydt/dsh-session-lab/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![DSH plugin](https://img.shields.io/badge/DeepSeek%20Harness-dsh--plugin-5b5bd6)](https://github.com/topics/dsh-plugin)

Turn a successful DeepSeek Harness session into reusable evidence, measurable Skills, and controlled comparisons.

`dsh-session-lab` is an independent, pre-1.0 community bundle. It is not an official DeepSeek product and is not endorsed by DeepSeek. It registers three complementary workflow Skills in the DSH runtime catalog:

| When you need to… | Use | You get |
| --- | --- | --- |
| Share or archive one run | [`dsh-capsule`](dsh-capsule/SKILL.md) | A verified, privacy-aware `.dshc` evidence bundle |
| Turn a successful run into a reusable workflow | [`dsh-teach`](dsh-teach/SKILL.md) | A candidate Skill plus independent baseline/treatment evaluation |
| Understand why two runs differ | [`dsh-time-machine`](dsh-time-machine/SKILL.md) | A controlled trajectory comparison with causal limits stated |

The helpers use Python 3.10+ and the standard library only. They do not add a Host session-import endpoint, execute capsule contents, or claim exact model replay.

## 30-second demo

Install the bundle, restart the DSH profile, then ask for one concrete workflow:

```bash
dsh plugin --profile web add github:zhangguiping-xydt/dsh-session-lab
```

```text
Use $dsh-capsule to package and verify this DSH export.
```

The result is a `.dshc` archive containing a manifest, redacted session events, integrity hashes, and (when explicitly selected) a workspace patch. For a successful workflow, try:

```text
Use $dsh-teach to extract and independently evaluate a Skill from this successful session.
```

For a controlled comparison, start two DSH branches from the same completed turn and ask:

```text
Use $dsh-time-machine to compare these two sessions from their common completed turn.
```

Each Skill explains its required input, output, safety checks, and known limits. Read the relevant `SKILL.md` before handling real session exports.

Requirements: Node.js 22.19+ (or 24+) for DSH/plugin installation and Python 3.10+ for the Skill helper scripts.

## Install

Install directly from GitHub into an existing DSH profile:

```bash
dsh plugin --profile web add github:zhangguiping-xydt/dsh-session-lab
```

For a reproducible install, pin the reviewed release tag:

```bash
dsh plugin --profile web add github:zhangguiping-xydt/dsh-session-lab#v0.1.0
```

If the `dsh` command is not installed globally, run the latest published CLI through `npx`:

```bash
npx --yes @deepseek-ai/dsh@latest plugin --profile web add github:zhangguiping-xydt/dsh-session-lab
```

The package is currently distributed through GitHub. npm publication is not required; once an npm release exists, the shorter `dsh plugin --profile web add dsh-session-lab` form will also work.

For local development from a source checkout:

```bash
dsh plugin --profile web add /absolute/path/to/dsh-session-lab
dsh plugin --profile headless add /absolute/path/to/dsh-session-lab
```

If an npm release is published later, the GitHub spec can be replaced with `dsh-session-lab`. Restart an already running profile after installation. Verify the composed layer before use:

```bash
dsh --profile web --dump-config | rg '# == dsh-session-lab'
```

The bundle uses the host `ctx.skills` registry, so it does not depend on project-directory watchers. A source-only alternative is to copy an individual directory under `<project>/.dsh/skills/` or `~/.dsh/skills/`; restart DSH if an existing session catalog does not refresh.

## What the reports look like

The public evaluation fixture for `dsh-teach` contains six paired tasks and twelve fresh DSH sessions:

```text
baseline passed:   1/6
treatment passed:  6/6
safety failures:   0
false positives:   0
routing misses:    0
```

This is an example evaluation, not a guarantee for every project or model. Re-run the protocol on your own tasks before promoting a generated Skill. See the [full report](examples/dsh-teach-full-eval/eval/report.md) and [evaluation protocol](dsh-teach/references/evaluation-protocol.md).

## Project map

This repository is one installable DSH bundle containing three independently documented Skills:

```text
dsh-session-lab/
├── dsh-capsule/       # package and verify portable session evidence
├── dsh-teach/         # extract and evaluate reusable Skills
└── dsh-time-machine/  # compare controlled session trajectories
```

## Use

Invoke a Skill explicitly or describe a matching task:

```text
Use $dsh-capsule to package and verify this DSH export.
Use $dsh-teach to extract and independently evaluate a Skill from this successful session.
Use $dsh-time-machine to compare these two sessions from their common completed turn.
```

Read the selected `SKILL.md` before execution. Session exports and generated reports may contain sensitive content even after pattern-based redaction.

## Verification

```bash
python3 -m pip install -r requirements-dev.txt
coverage run --branch -m pytest
coverage report --fail-under=60
ruff check .
ruff format --check .
npm test
npm pack --dry-run
```

`pyproject.toml` configures pytest and Ruff only. The project does not publish a Python wheel; the standalone Python helpers are shipped inside the npm/DSH bundle.

The suite contains synthetic security and archive fixtures plus a checked-in real-model evaluation. The full `dsh-teach` example records 12 fresh DSH sessions across six paired tasks: baseline passed 1/6, treatment passed 6/6, with zero safety failures, false positives, or routing misses. See [the evaluation report](examples/dsh-teach-full-eval/eval/report.md).

## Build a release artifact

```bash
mkdir -p dist
npm pack --pack-destination dist
dsh plugin --profile headless add ./dist/dsh-session-lab-0.1.0.tgz
```

The CI workflow validates Python 3.10–3.13, package cleanliness, Skill structure, checked-in evaluation evidence, and installation into the latest published DSH profile.

## Security

Treat raw exports, patches, images, and reports as sensitive. Automatic replacement is not anonymization, and SHA-256 integrity does not authenticate a publisher. See [SECURITY.md](SECURITY.md) before sharing artifacts.

The repository and each standalone Skill directory are licensed under MIT; per-Skill licenses allow independent copying.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before participating, [CHANGELOG.md](CHANGELOG.md) for release history, and [RELEASING.md](RELEASING.md) for the public-release checklist.

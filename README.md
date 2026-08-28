# DSH Session Lab

`dsh-session-lab` is an installable DeepSeek Harness bundle that registers three workflow Skills directly in the DSH runtime catalog:

This is an independent, pre-1.0 community project. It is not an official DeepSeek product and is not endorsed by DeepSeek. APIs and plugin behavior may need adjustment as DeepSeek Harness evolves.

- `dsh-teach` turns a successful session into a redacted candidate Skill and validates paired baseline/treatment evaluation evidence.
- `dsh-capsule` packages session exports, selected artifacts, and a workspace patch into a verified `.dshc` evidence bundle.
- `dsh-time-machine` compares two controlled trajectories from a shared completed-turn cut.

The helpers use Python 3.10+ and the standard library only. They do not add a Host session-import endpoint, execute capsule contents, or claim exact model replay.

Requirements: Node.js 22.19+ (or 24+) for DSH/plugin installation and Python 3.10+ for the Skill helper scripts.

## Install

Install directly from GitHub into an existing DSH profile:

```bash
dsh plugin --profile web add github:zhangguiping-xydt/dsh-session-lab
```

If the `dsh` command is not installed globally, run the latest published CLI through `npx`:

```bash
npx --yes @deepseek-ai/dsh@latest plugin --profile web add github:zhangguiping-xydt/dsh-session-lab
```

For local development from a source checkout:

```bash
dsh plugin --profile web add /absolute/path/to/dsh-session-lab
dsh plugin --profile headless add /absolute/path/to/dsh-session-lab
```

After an npm release, replace the path with `dsh-session-lab`. Restart an already running profile after installation. Verify the composed layer before use:

```bash
dsh --profile web --dump-config | rg '# == dsh-session-lab'
```

The bundle uses the host `ctx.skills` registry, so it does not depend on project-directory watchers. A source-only alternative is to copy an individual directory under `<project>/.dsh/skills/` or `~/.dsh/skills/`; restart DSH if an existing session catalog does not refresh.

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

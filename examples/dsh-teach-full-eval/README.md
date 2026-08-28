# dsh-teach full evaluation

This example exercises the complete `dsh-teach` workflow with real DeepSeek Harness sessions:

1. run one successful source session that demonstrates the BracketSafe contract;
2. package and redact the source as a verified `.dshc` capsule;
3. analyze the capsule and validate the candidate Skill;
4. freeze six independent tasks before evaluation;
5. run paired baseline/treatment sessions with identical prompts and isolated workspaces;
6. redact known identifiers, structured secrets, and hidden reasoning text, then save each complete logical event structure as hashed run evidence;
7. recompute acceptance, routing, safety, actual request configuration, Token, and elapsed time from that evidence;
8. generate `report.json`/`report.md` with `teach.py eval-report`.

The checked-in candidate is intentionally small and non-production. It tests the evaluation machinery without using private data. The real-model runner requires `deepseek-harness-sdk`, a configured DeepSeek credential, and network access:

```bash
python3 run_real_eval.py --output-dir eval \
  --provider deepseek-official \
  --model deepseek-v4-flash \
  --reasoning-effort high
```

The runner gives every arm a fresh runtime, Session root, and disposable workspace. It injects the requested reasoning effort through a temporary Cordis overlay and rejects any `request/header` that does not match the frozen manifest. A failed candidate validation stops the run before the output directory is created.

Files under `eval/evidence/` contain complete, deterministically redacted logical events rather than unverified summaries. This example uses synthetic prompts, but real projects must retain original events privately and treat even redacted evidence as sensitive until it passes a manual disclosure review. Do not treat one six-task run as a universal model-quality claim. Re-run for a new DSH/model release and inspect every evidence file before relying on the promotion result.

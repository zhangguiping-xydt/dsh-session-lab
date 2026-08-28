# Skill 独立评测报告

- Skill：`bracketsafe-normalizer`
- 候选哈希：`3535af867d5c159e9cf02d480f7e214ebd1e0c3326c2da567d23839637deaeb5`
- 请求配置：`deepseek-official/deepseek-v4-flash`，推理强度 `high`
- SDK/Runtime：`0.1.1rc1` / `0.1.1rc1`
- Agent Preset：`sdk-default`
- 推广结论：`PASS`
- baseline 通过：1/6
- treatment 通过：6/6
- 通过数增量：5
- 安全失败：0；baseline 污染：0；误触发：0；漏触发：0

## 任务明细

| task | category | run | baseline | treatment | loaded | safety | failure |
|---|---|---:|---:|---:|---:|---:|---|
| near-01 | near | 1 | FAIL | PASS | yes | PASS | procedure_failure |
| near-02 | near | 1 | FAIL | PASS | yes | PASS | procedure_failure |
| structural-01 | structural | 1 | FAIL | PASS | yes | PASS | procedure_failure |
| boundary-01 | boundary | 1 | PASS | PASS | no | PASS |  |
| interference-01 | interference | 1 | FAIL | PASS | yes | PASS | procedure_failure |
| structural-02 | structural | 1 | FAIL | PASS | yes | PASS | procedure_failure |

## 中位数

| arm | tool calls | input tokens | output tokens | elapsed ms |
|---|---:|---:|---:|---:|
| baseline | 0.0 | 100.5 | 76.0 | 1676.5 |
| treatment | 1.0 | 305.0 | 392.0 | 4417.5 |

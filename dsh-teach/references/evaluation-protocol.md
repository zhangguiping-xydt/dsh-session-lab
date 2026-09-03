# Skill 独立评测协议

## 评测清单

`eval/manifest.json` 至少记录：

```json
{
  "schema": "dsh-teach-eval-manifest/v2",
  "skill": "example-skill",
  "candidate_sha256": "...",
  "provider": "deepseek-official",
  "model": "deepseek-v4-flash",
  "reasoning_effort": "...",
  "agent_preset": "...",
  "sdk_version": "...",
  "runtime_version": "...",
  "task_count": 5,
  "repetitions": 1,
  "primary_metric": "acceptance_pass",
  "promotion_rule": "预先写明的判定规则",
  "promotion": {
    "require_all_safety": true,
    "require_clean_baseline": true,
    "max_false_positives": 0,
    "max_routing_misses": 0,
    "min_acceptance_delta": 1
  },
  "frozen_at": "ISO-8601"
}
```

`tasks.jsonl` 至少五行，必须覆盖 `near`、`structural`、`boundary`、`interference` 四类。每行记录 `task_id`、`prompt`、`workspace_baseline`、`category`、布尔值 `expected_trigger`、`acceptance`、`allowed_tools`、机器判分 `oracle` 和非空 `forbidden_behaviors`。密钥与真实账号不得进入任务文件。

`oracle` 支持两种可复核形式：

- `{"kind":"exact_response","expected":"..."}`：从原始事件重新提取最后一条可见 assistant 文本并精确比较；
- `{"kind":"command_exit","command":"...","success_exit_codes":[0]}`：证据中必须保存相同命令、退出码、stdout 和 stderr。命令由会话外的评测执行器运行，不能采信 Agent 自报；`eval-report` 审计只复核证据中记录的命令、退出码与哈希一致性，不会重新执行该命令。

`results.jsonl` 每行记录：

```json
{
  "task_id": "near-01",
  "arm": "baseline",
  "run": 1,
  "session_id_hash": "...",
  "skill_loaded": true,
  "acceptance_pass": true,
  "safety_pass": true,
  "tool_calls": 12,
  "input_tokens": 1000,
  "output_tokens": 300,
  "elapsed_ms": 42000,
  "failure_class": null,
  "evidence": [
    {
      "path": "evidence/near-01-baseline-run-1.json",
      "sha256": "..."
    }
  ]
}
```

每次运行恰好对应一个 `dsh-teach-run-evidence/v1` JSON，至少记录任务、arm、run、Session ID 哈希、SDK/Runtime 版本和经过确定性敏感字段替换的完整逻辑 Session Event。发布证据保留事件结构但将隐藏推理文本替换为固定标记；原始事件另存私密副本。证据路径必须位于 `eval/` 内，SHA-256 必须匹配。脱敏事件仍可能含提示词、工具参数和业务内容，经过人工审查后才能随仓库发布。

结果收集完成后运行：

```bash
python3 <本 Skill 目录>/scripts/teach.py eval-report <候选 Skill>/eval --require-promotion
```

该命令拒绝缺失 arm、缺失重复轮次、目录穿越、证据哈希或字段不一致、实际请求配置漂移、未知失败分类和不完整类别。它是完整性与一致性审计器：不重新执行 `command_exit` 命令，命令级验收以生成证据的评测执行器为准。它从事件重新计算最终回复、候选 Skill 加载、工具安全、Token 和耗时，并在 baseline 加载候选 Skill 时强制阻止晋级。`promoted: true` 只表示预先冻结的机器门槛通过，不能证明证据发布者身份，也不能替代对任务设计和原始证据的人工审查。

## 公平性控制

- baseline 与 treatment 从同一只读基线复制工作区；禁止复用上一次运行产生的缓存、文件或会话历史，除非缓存本身是待测能力。
- 任务文本、环境变量、网络条件、权限和验收器保持一致。
- Skill 以外只改变一个实验变量；若模型或 Preset 同时变化，结果不能归因于 Skill。
- 自动验收命令在 Agent 完成后由独立进程运行，不能只接受 Agent 自报“测试通过”。
- 对随机性敏感的任务运行多次，逐次保存结果，不用最好的一次覆盖失败。

## 失败分类

- `routing_miss`：应触发但未加载 Skill；
- `false_positive`：不应触发却执行了 Skill；
- `procedure_failure`：已触发，但流程未完成目标；
- `unsafe_action`：违反权限、范围、保密或破坏性操作规则；
- `verification_failure`：产物可能正确，但未按要求验证；
- `environment_failure`：模型之外的依赖不可用；
- `oracle_failure`：验收器本身不可靠或无法判定。

环境与验收器失败单独报告，不得静默删除后重算成功率。

## 报告

`report.md` 同时给出任务级明细与聚合结果。至少报告成功数/总数、安全失败数、误触发数、Token/工具调用/耗时的中位数，以及所有反例。样本很小时直接给出原始计数，不用小数百分比制造精确感。

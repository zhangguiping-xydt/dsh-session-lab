# dsh-teach 实战评测案例

这个案例用一次已成功的 DSH 会话，提炼出一个可复用 Skill，然后用新会话检查它是否真的有帮助。案例使用的是合成的 BracketSafe 任务，不包含业务代码或私人会话。

## 这个流程解决什么

只看一次成功会话，只能说“当时做成了”，不能说“已经沉淀成通用方法”。`dsh-teach` 的做法是：

1. 保留原始会话为私密证据，只发布确定性脱敏后的副本。
2. 区分必要动作、辅助动作和失败弯路。
3. 冻结近邻、结构、边界和干扰任务。
4. 分别运行不加 Skill 的 baseline 和加 Skill 的 treatment。
5. 从会话事件、工具调用和验收结果重新计算报告，不信任 Agent 自报。

## 如何重新运行

你需要 Python 3.10+、可用的 DeepSeek 凭据和网络。运行器会为每个 arm 使用新的运行时、Session 根和可丢弃工作区：

```bash
python3 run_real_eval.py \
  --output-dir eval \
  --provider deepseek-official \
  --model deepseek-v4-flash \
  --reasoning-effort high
```

运行前请先阅读 [`dsh-teach/SKILL.md`](../../dsh-teach/SKILL.md) 和[评测协议](../../dsh-teach/references/evaluation-protocol.md)。真实项目应保留原始事件的私密副本，发布前手工检索数据、路径、Token、内部地址和密钥。

## 本次固定证据

| 项目 | 值 |
| --- | --- |
| 评测任务 | 6 个，包含 near、structural、boundary、interference |
| 会话数 | 12 次，每个任务各有 baseline/treatment |
| 模型配置 | `deepseek-official/deepseek-v4-flash` + `high` |
| baseline | 1/6 通过 |
| treatment | 6/6 通过 |
| 通过数增量 | +5 |
| 安全失败 | 0 |
| 误触、路由遗漏 | 0、 0 |

`boundary-01` 在 baseline 中已经能通过，且 treatment 没有加载候选 Skill。这个反例很重要：它表明 Skill 没有无条件触发。

## 如何解读结果

- `baseline` 和 `treatment` 是对照组，不是同一会话重试。
- 本次 treatment 中位工具调用为 1 次，baseline 为 0 次；这不是“工具越少越好”，而是以完成验收为主指标。
- 本次样例的任务数和重复次数有限，结果是回归证据，不是对所有项目、模型或任务的保证。
- 优化正式发布前，应用自己的任务另行重新评测，并保留失败样本。

## 输出文件

```text
eval/
├── manifest.json       # 冻结任务、模型和推广门槛
├── tasks.jsonl         # 成对任务
├── results.jsonl       # 从证据重算的结果
├── evidence/           # 脱敏后的完整逻辑事件
└── report.md           # 人类可读报告
```

对已有证据重新生成报告：

```bash
python3 dsh-teach/scripts/teach.py eval-report \
  examples/dsh-teach-full-eval/eval \
  --require-promotion
```

只有报告中的 `promoted: true`、所有安全检查通过，并且已经手工审阅任务和证据时，才适合将候选 Skill 提供给其他人。

原始数据、脚本和限制见：

- [`README.md`](README.md)
- [`eval/report.md`](eval/report.md)
- [`eval/manifest.json`](eval/manifest.json)

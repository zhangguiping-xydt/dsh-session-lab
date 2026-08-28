# 反事实实验记录协议

## `experiment.json`

```json
{
  "schema": "dsh-time-machine-experiment/v1",
  "question": "模型 B 是否提高此任务的验收通过率？",
  "evidence_level": "forked-isolated",
  "source_session_hash": "...",
  "cut_seq": 42,
  "cut_event": "turn/end",
  "workspace": {
    "baseline_revision": "git commit SHA",
    "clean": true,
    "isolation": "two-worktrees"
  },
  "constant_task": "发送给每个 arm 的完全相同文本",
  "independent_variable": "model",
  "arms": {
    "baseline": {"provider": "...", "model": "..."},
    "variant": {"provider": "...", "model": "..."}
  },
  "acceptance": {
    "command": "...",
    "pass": "exit code 0 and expected assertion",
    "forbidden": ["修改公共接口", "新增依赖"]
  },
  "repetitions": 3,
  "run_order": ["baseline", "variant", "variant", "baseline"],
  "promotion_rule": "运行前写明",
  "frozen_at": "ISO-8601"
}
```

Session ID 不直接写入可分享材料，使用 SHA-256 或胶囊内化名。真正执行时可以在本地私有映射中保留原 ID。

## 每次运行记录

每个 run 保存：

- arm、重复序号、开始/结束时间；
- DSH 版本、Agent Preset、provider/model/reasoning effort；
- 项目提交、开始和结束时的 `git status --short`；
- 用户追加消息和人工干预；
- 验收退出码与完整输出文件；
- 最终 patch；
- `/export` 文件及 SHA-256；
- 网络、服务、依赖或权限异常。

## 首次有意义分叉

不要把时间戳、随机 Call ID、Session ID 或流分片顺序当作行为分叉。优先寻找：

1. 实际请求 header 的 provider/model/system/tools 不同；
2. 第一个不同的分析结论或文件读取目标；
3. 第一个不同的工具名称或具有语义差异的参数；
4. 第一个不同的工具结果；
5. 最终 diff、测试或用户可见结果的差异。

仅凭自然语言“思考”解释根因时，标记为模型自述。只有工具、文件和验收链条支持时才写作证据。

## 多次运行汇总

先给原始计数，再给比例。成功率之外至少报告安全通过、验证完成、工具调用、Token 与耗时。资源指标使用中位数和范围；不删除异常值，只在报告中解释外部故障。

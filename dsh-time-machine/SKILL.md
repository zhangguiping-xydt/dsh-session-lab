---
name: dsh-time-machine
description: 对 DeepSeek Harness 会话做可控的反事实实验：从同一已完成轮次 fork，单独改变模型、提示词、Skill 或配置，导出两条轨迹并比较工具选择、结果、Token、耗时和最终验收。适用于“如果当时换模型会怎样”“从这里重跑”“为什么两次结果不同”；不把普通重试或离线日志比较冒充成因果结论。
license: MIT
---

# DSH 反事实时间机器

时间机器不是撤销按钮，而是一套受控实验：让 baseline 和 variant 共享同一历史切点与工作区基线，只改变一个变量，再用独立验收判断差异。最终回答“哪一步开始不同、为什么可能不同、结果是否更好”，而不只展示两段聊天。

## 可直接实现的范围

当前 DSH 原生支持：

- 在已完成轮次的 assistant 尾部通过“分支”操作创建普通 Session fork；
- fork 继承截至切点的会话事件、cwd、最新模型选择和 Session 谱系；
- fork 后在模型选择器中改变后续请求的 provider/model/reasoning effort；
- 用 `/export` 导出 JSONL，离线重建请求 header、工具调用、工具结果和轮次结局。

当前不能假设：

- 任意未完成步骤都能安全 fork。Host 会把消息锚点映射到该消息所在轮次的首个 `turn/end`；开放轮次会返回 `fork-unavailable`；
- 普通 fork 可以替换 Agent Preset。fork 延续原 Session 的组合；需要另一 Preset 时必须新建独立会话，实验等级随之降低；
- 同一 Workspace 的两个 fork 天然隔离。它们共享 cwd，文件改动会互相影响；必须使用可丢弃副本、worktree 或串行恢复基线；
- 相同输入一定产生相同输出。模型、网络、外部工具和时间都可能带来随机或环境变化。

## 不可妥协的实验纪律

- 开始前写下问题、唯一自变量、成功判分器、禁止行为和推广门槛。
- baseline 与 variant 从同一已完成轮次、同一 Workspace 内容和同一后续任务文本开始。
- 一次只改变一个可归因变量。模型、Prompt、Skill、Preset 和权限不能同时改变后仍声称知道原因。
- 每个分支在独立、可丢弃的工作区运行；不得让一个分支看到另一个分支生成的文件。
- 正确性由会话外的测试或明确人工判据决定，不能用 Agent 自报“完成”代替。
- 保存失败样本、工具错误和非预期分叉，不挑最好的一次。

## 标准流程

### 1. 写实验清单

开始运行前建立 `experiment.json`，格式见 `references/experiment-protocol.md`。至少记录：

- 研究问题，例如“模型 B 是否比模型 A 更容易在不改接口的条件下修复此缺陷”；
- 切点 Session 和 `turn/end` seq；
- baseline 与 variant 唯一差异；
- 完全一致的后续任务文本；
- Workspace 基线提交与未提交状态；
- 验收命令、成功条件和安全条件；
- 重复次数与停止规则。

如果无法写出唯一自变量，先拆成多个实验。

### 2. 选择合法切点

在 Web 对话中选择一个已结束轮次最后一条 assistant 消息。切点应满足：

- 轮次已有 `turn/end`；
- 切点之前的上下文包含两个分支都需要的事实；
- 切点之后尚未发生待比较的决定；
- Workspace 可以恢复到与该切点匹配的文件状态。

点击消息旁“分支”创建 fork。需要两个独立后续分支时，从同一源消息分别 fork，而不是从 variant 再 fork baseline。

### 3. 隔离 Workspace

会话历史 fork 不等于文件系统快照。优先为每个 arm 建立来自同一提交的独立 worktree 或仓库副本，并分别启动 DSH Session。若只能复用同一 cwd，则必须串行运行：每次运行前由用户认可的方法恢复同一基线，并确认 `git status --short` 相同。

不要用 `git reset --hard`、覆盖未提交文件或删除目录来“恢复”基线，除非用户明确授权且已确认目标。工作区无法可靠复原时，停止并把实验标记为不可归因。

### 4. 只改变一个变量

#### 比较模型

两个 fork 保持相同 Agent Preset、工具、Skill 和权限。在发送相同后续任务前，分别通过模型选择器设置目标 provider/model/reasoning effort。导出日志中的 `request/header` 是模型实际看到的系统提示词、工具 schema 与路由证据。

#### 比较 Prompt

模型与所有运行条件一致，只改变预先登记的一段 Prompt。不要在运行中临时给某个 arm 更多提示；必要的故障恢复提示必须对两个 arm 对称追加并记录。

#### 比较 Skill

使用两个隔离项目根：baseline 不加载候选 Skill，variant 在 `.dsh/skills/<name>/` 或 `.agents/skills/<name>/` 加载它。确认两边其余 Skill 目录一致。触发测试还要记录候选 Skill 是否真的被加载，避免把“没有触发”误判成“Skill 无效”。

#### 比较 Preset 或插件

普通 Session fork 不能替换 Preset。为每个 Preset 建立新会话，并使用相同的可见历史摘要或任务材料；这属于“重建上下文实验”，不是严格 fork 实验。报告中必须把证据等级标为 `reconstructed`，不能与共享精确前缀的 `forked` 混为一谈。

### 5. 执行与独立验收

向每个 arm 发送完全相同的后续任务。运行结束后，从会话外执行相同验收命令，保存 stdout、stderr、退出码、最终 diff 和禁止行为检查。

对非确定性任务，按清单重复运行并交错顺序，例如 A、B、B、A。任何人工中途干预都记入该次运行；不对称干预的运行不能用于主要归因结论。

### 6. 导出并对比轨迹

分别在两个会话执行 `/export`。然后运行：

```bash
python3 <本 Skill 目录>/scripts/compare.py \
  <baseline.zip|session.jsonl|.dshc> \
  <variant.zip|session.jsonl|.dshc> \
  --output-dir <对比结果目录> \
  --cut-seq <共同 turn/end 的 seq>
```

`--output-dir` 必须指向尚不存在的新目录；脚本拒绝覆盖已有对比报告。

若两个输入都是从同一父 Session fork 的导出，脚本可以利用 `seedLength` 或最长共同前缀推断切点；正式实验仍应显式给出 `--cut-seq`。多 Session 容器可用 `--baseline-member` 和 `--variant-member` 指定 JSONL 成员。

不要直接传入 `$DSH_HOME/sessions/**/session.jsonl.zstd`，也不要仅解压后改名为 `session.jsonl`；内部持久化文件可能包含 `text-chunks` 等打包记录。比较器只接受 `/export` 的逻辑事件流，或由官方 SDK/持久化读取器等价还原的连续事件流。

脚本生成 `comparison.json` 和 `comparison.md`，包括：

- 共同切点与切点可靠性；
- 事件类型和工具调用顺序；
- 参数与结果的脱敏预览及摘要哈希；
- 请求路由、最终 assistant 输出预览和轮次结局；
- uncached input、cache read/write、output 与 reasoning Token；
- 轨迹时长和结构性分叉。

轨迹脚本不运行测试，也不会宣布胜者。assistant 预览只保留用户可见文本，不输出隐藏推理；报告还会递归收集已知 Session 关联字段并替换其正文引用，并按结构化字段名隐藏 Token、Cookie、密码和密钥值。这仍不是匿名化，未知业务标识、图片语义和不常见凭据字段可能漏过，原始导出和报告都应按敏感材料管理并人工搜索后再分享。

### 7. 作出因果强度受限的结论

按以下等级报告：

- `forked-isolated`：共同 Session 前缀、合法切点、隔离 Workspace、单一变量、独立验收；最强证据；
- `forked-shared-workspace`：共享会话前缀但 Workspace 可能串扰；只能作弱结论；
- `reconstructed`：新会话重建上下文，用于 Preset/插件比较；说明不可见差异；
- `observational`：只比较已有两条日志，没有受控切点；只能描述相关性。

结论必须包含：任务级验收结果、首次有意义分叉、后续连锁影响、资源成本、安全差异、样本数、环境异常和反例。不要仅因 variant Token 少或回复更短就称其更好。

## 常见误判

- `turn/end completed` 只表示 Agent 轮次正常结束，不表示代码或业务结果正确；
- 工具调用次数少可能是更高效，也可能是漏做验证；
- 两个 arm 的系统提示词或工具 schema 不同，即使模型名相同也不是纯模型比较；
- fork 后继续使用被另一个 arm 改过的同一目录，会把文件串扰错算成模型能力；
- 只跑一次无法区分系统性提升和随机波动；
- 从最终回复倒推“模型为什么这样做”属于解释假设，必须与事件证据分开。

## 完成定义

只有实验清单已冻结、切点合法、Workspace 隔离、两边独立验收、日志已导出、比较报告已生成，并且结论标注证据等级与限制时，任务才完成。

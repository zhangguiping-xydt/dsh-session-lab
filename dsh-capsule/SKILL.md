---
name: dsh-capsule
description: 将 DeepSeek Harness 会话导出、工作区补丁和选定产物打包成可脱敏、可校验、可检查的 .dshc 会话胶囊，并在分享前完成内容清单与泄密复核。适用于分享成功 Agent 过程、归档可追溯证据或给他人复盘；不把胶囊冒充成 DSH 官方可直接导入的 Session。
license: MIT
---

# 打包可核验的 DSH 会话胶囊

把一次运行成功的 Agent 过程封装为 `.dshc`：接收者能查看会话事件、工具轨迹、工作区补丁、产物清单与哈希，并确认文件未被篡改。胶囊首先是一份便携证据包，不是假装成官方 Session 导入协议。

## 当前能力边界

DSH Web 的 `/export` 会下载根 Session、可选子 Session 和图片附件的 ZIP；现有 Host 还支持对仍存在的 Session 在已完成轮次处 fork。当前源码没有公开的“把任意外部 ZIP 导入为可继续 Session”接口。

因此本 Skill 提供：

- 确定格式的 `.dshc` ZIP 容器；
- JSONL 结构化脱敏、Session 化名、文件清单和 SHA-256 校验；
- 工作区 patch 和选定产物的打包；
- 安全检查、只读查看和受控解包；
- 供 `dsh-teach`、`dsh-time-machine` 或人工复盘读取的标准材料。

本 Skill 不声称提供：

- 把 `.dshc` 直接恢复进 DSH 并从任意回合继续；
- 对外部模型请求进行字节级重放；
- 数字签名、发布者身份认证或恶意内容沙箱。

若原 Session 仍在 DSH 中，从消息的“分支”操作 fork 才是原生继续方式。若要实现跨机器导入与可执行 fork，需要另写 Host/Client 插件并定义导入、Workspace 重建、权限和版本迁移协议。

## 安全规则

- 原始 `/export` ZIP 包含用户消息、模型回复、工具参数、工具输出、系统提示词和本地路径；默认按敏感数据处理。
- 默认使用 `share` 隐私模式：常见密钥模式被替换，Session ID 化名，用户主目录和 Workspace 路径被归一化。
- 图片和二进制产物无法可靠自动脱敏，默认不打包；只有用户明确确认风险后才包含。
- 模式脱敏不是数据防泄漏证明。分享前必须解包到新目录，人工搜索账号、业务数据、内网地址、源码机密和图片内容。
- 不覆盖已有胶囊或已有解包目录；避免因参数错误破坏用户文件。
- `.dshc` 是数据，不可信来源的胶囊不得执行其中脚本、应用 patch 或打开可执行文件。

## 输入

至少提供一个 DSH `/export` ZIP 或单个 `session.jsonl`。按需增加：

- `workspace.patch`：推荐由 `git diff --binary <基线提交>` 生成；
- 产物文件：测试报告、截图、生成文档等；
- 隐私模式：公开或跨团队分享用 `share`，仅本机受控归档可用 `private`；
- 是否包含导出 ZIP 中的图片附件。

不要自行推断可公开范围。涉及图片、二进制产物或 `private` 模式时，必须取得用户明确确认。

不要直接读取 `$DSH_HOME/sessions/**/session.jsonl.zstd`，也不要把它手工解压后冒充 `/export` 的 `session.jsonl`。该文件是 DSH 内部持久化格式，可能含 `text-chunks` 等打包存储记录；应使用 Web `/export`，或由官方 SDK/持久化读取器先还原为逻辑 Session Event。

## 标准流程

### 1. 取得稳定导出

在 DSH Web 当前会话输入 `/export`，或点击 Session Header 的日志导出按钮。下载端会包含根 Session；Web 默认请求可包含后代 Session。保留原 ZIP 只读并计算 SHA-256。

若需要工作区变化，在原工作区只读采集：

```bash
git status --short
git diff --binary <基线提交> > workspace.patch
```

不要把整个工作区无选择地塞入胶囊。

### 2. 使用安全默认值打包

```bash
python3 <本 Skill 目录>/scripts/capsule.py pack \
  <dsh-session.zip 或 session.jsonl> \
  --output <名称>.dshc \
  --privacy share \
  --workspace-patch <workspace.patch>
```

没有 patch 时省略相应参数。输出文件已存在时脚本会拒绝覆盖。

只有用户确认图片内容可分享后，才增加：

```bash
--include-media --acknowledge-media-risk
```

只有用户逐个确认额外产物后，才增加一个或多个：

```bash
--artifact <文件> --acknowledge-artifact-risk
```

UTF-8 文本产物会做模式脱敏；二进制产物原样进入容器。

### 3. 检查结构与完整性

先做只读检查：

```bash
python3 <本 Skill 目录>/scripts/capsule.py inspect <名称>.dshc
python3 <本 Skill 目录>/scripts/capsule.py verify <名称>.dshc
```

`verify` 证明 manifest 中列出的文件与 SHA-256 一致，不证明内容真实、安全或来自特定发布者。

### 4. 解包并人工复核

解包目标必须是不存在的新目录：

```bash
python3 <本 Skill 目录>/scripts/capsule.py extract <名称>.dshc --output-dir <新目录>
```

逐项检查：

- `manifest.json`：格式版本、隐私模式、来源哈希、能力声明；
- `redaction-report.json`：各类替换次数；
- `sessions/**/session.jsonl`：用户消息、命令、工具输出、内部 URL；
- `workspace/change.patch`：源代码秘密、凭据、客户数据；
- `artifacts/` 与 `media/`：图片和二进制内容。

可以再运行本地秘密扫描器，但不得只依赖扫描器。

### 5. 交付与复盘

交付胶囊时同时说明：

- 文件 SHA-256；
- `share` 或 `private` 模式；
- 是否包含图片、二进制产物和工作区 patch；
- 自动脱敏只覆盖哪些模式；
- `verify` 的结果；
- 胶囊不能直接导入当前 DSH 的限制。

接收者若只需理解过程，可读取 JSONL 或调用 `dsh-teach` 分析；若要比较两次运行，使用 `dsh-time-machine` 的轨迹对比脚本；若要继续原 Session，必须在拥有该 Session 的 DSH 实例中使用原生 fork。

## 格式约定

完整格式见 `references/capsule-format.md`。任何读取器都必须：

- 拒绝绝对路径、`..`、符号链接、重复条目和超出资源上限的 ZIP；
- 先校验 manifest 再消费文件；
- 把未知格式版本视为不支持，不能静默降级；
- 默认以数据方式展示脚本与 HTML，不自动执行或渲染活动内容。

## 完成定义

只有同时满足以下条件才算完成：胶囊已生成；`verify` 通过；已在新目录人工复核；用户知道包含内容和剩余风险；最终回复给出胶囊路径与 SHA-256；未宣称不存在的 DSH 导入能力。

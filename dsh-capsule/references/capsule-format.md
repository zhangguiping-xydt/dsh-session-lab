# `.dshc` 会话胶囊格式 v1

`.dshc` 是普通 ZIP 文件，文件名后缀用于表明用途。路径统一使用 `/`，条目名称为 UTF-8。读取器拒绝绝对路径、空路径、`.`、`..`、反斜杠路径、NUL、符号链接和重复名称。

## 目录

```text
manifest.json
redaction-report.json
sessions/root/session.jsonl
sessions/subagents/<id>/session.jsonl   # 可选
workspace/change.patch                  # 可选
media/<attachment>.<ext>                # 可选，默认排除
artifacts/<filename>                     # 可选，默认排除
```

`sessions/**/session.jsonl` 来自 DSH 持久化 JSONL 的结构化重写。v1 不承诺字节级保真；`share` 模式还会化名 Session ID 与路径，因此这些文件不能直接替代 DSH 的权威持久化文件。

## manifest

`manifest.json` 使用 UTF-8 JSON，主要字段为：

```json
{
  "format": "dsh-capsule",
  "version": 1,
  "created_at": "ISO-8601",
  "privacy": "share",
  "source": {
    "name": "dsh-session.zip",
    "sha256": "..."
  },
  "capabilities": {
    "integrity_verification": true,
    "offline_inspection": true,
    "dsh_import": false,
    "exact_model_replay": false
  },
  "files": [
    {
      "path": "sessions/root/session.jsonl",
      "role": "session-log",
      "bytes": 1234,
      "sha256": "..."
    }
  ]
}
```

`files` 不包含 `manifest.json` 本身，以避免自引用哈希。除 manifest 外，容器中的文件集合必须与 `files` 完全一致。每个路径只能出现一次。

## 完整性与真实性

SHA-256 只能发现内容变化，不能证明谁创建了胶囊。若需要发布者身份认证，应在容器外对整个 `.dshc` 文件使用组织认可的签名方案，并单独传递公钥信任信息；不要把自签名公钥放进同一容器后就称为可信。

## 隐私模式

- `share`：替换常见密钥形态、邮箱、HTTP(S) URL、用户主目录和 Workspace 路径，并把已知 Session ID/Attachment ID 映射为顺序化名。目标是降低无意泄露，不保证匿名化。
- `private`：保留 Session ID 与路径，只替换常见密钥形态。只适合访问控制明确的本地归档。

两种模式都可能遗漏业务敏感文本、源码秘密、图片信息、命令输出中的特殊凭据和经过编码的数据。`redaction-report.json` 记录替换类别和次数，不记录原值。

## 资源限制

参考实现读取时限制 ZIP 条目数、单条目大小和总解压大小。其他实现不得把 manifest 中的大小当作可信值，必须以 ZIP 元数据和实际读取结果独立检查，防止路径穿越与解压炸弹。

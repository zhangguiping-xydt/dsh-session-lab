import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export const name = 'dsh-session-lab'
export const inject = ['skills']

const SKILL_METADATA = [
  {
    name: 'dsh-capsule',
    description:
      '将 DeepSeek Harness 会话导出、补丁和选定产物打包为可脱敏、可校验的 .dshc 证据包；适用于安全分享、归档和复盘。',
    whenToUse: '需要打包、检查、验证或安全解包 DSH 会话证据时使用。',
  },
  {
    name: 'dsh-teach',
    description:
      '从真实成功的 DeepSeek Harness 会话提炼可复用 Skill，并通过脱敏、静态校验和独立任务评测验证效果。',
    whenToUse: '需要把成功会话沉淀为可验证 Skill 或评估候选 Skill 是否有效时使用。',
  },
  {
    name: 'dsh-time-machine',
    description:
      '从同一已完成轮次比较两条受控 DSH 轨迹，分析模型、提示词、Skill 或配置变化对结果、工具、Token 和耗时的影响。',
    whenToUse: '需要做 DSH 分支对比、反事实实验或定位两次会话差异时使用。',
  },
]

function readSkillBody(skillName) {
  const skillUrl = new URL(`./${skillName}/SKILL.md`, import.meta.url)
  const raw = readFileSync(skillUrl, 'utf8')
  const frontmatter = raw.match(/^---\r?\n[\s\S]*?\r?\n---(?:\r?\n|$)/)
  if (frontmatter === null) {
    throw new Error(`${skillName}/SKILL.md is missing YAML frontmatter`)
  }
  const content = raw.slice(frontmatter[0].length).trim()
  if (content.length === 0) throw new Error(`${skillName}/SKILL.md has no instruction body`)
  return content
}

function skillRegistration(metadata) {
  return {
    ...metadata,
    source: 'runtime',
    resourceBase: {
      kind: 'directory',
      path: fileURLToPath(new URL(`./${metadata.name}/`, import.meta.url)),
    },
    content: readSkillBody(metadata.name),
  }
}

const PACKAGED_SKILLS = SKILL_METADATA.map(skillRegistration)

export function apply(ctx) {
  const disposers = []
  const disposeAll = () => {
    for (const dispose of disposers.splice(0).reverse()) dispose()
  }
  try {
    for (const skill of PACKAGED_SKILLS) disposers.push(ctx.skills.register(skill))
  } catch (error) {
    disposeAll()
    throw error
  }
  return disposeAll
}

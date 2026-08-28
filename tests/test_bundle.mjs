import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { dirname } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const bundle = await import('../index.js')
const root = dirname(dirname(fileURLToPath(import.meta.url)))

test('bundle registers all packaged skills with usable resources', () => {
  const registrations = []
  const disposed = []
  const ctx = {
    skills: {
      register(definition) {
        registrations.push(definition)
        return () => disposed.push(definition.name)
      },
    },
  }

  const dispose = bundle.apply(ctx)

  assert.equal(bundle.name, 'dsh-session-lab')
  assert.deepEqual(bundle.inject, ['skills'])
  assert.deepEqual(
    registrations.map(({ name }) => name).sort(),
    ['dsh-capsule', 'dsh-teach', 'dsh-time-machine'],
  )
  for (const definition of registrations) {
    assert.equal(definition.source, 'runtime')
    assert.ok(definition.description.length >= 20)
    assert.equal(definition.resourceBase.kind, 'directory')
    assert.ok(existsSync(definition.resourceBase.path))
    assert.ok(existsSync(`${definition.resourceBase.path}/scripts`))
    assert.match(definition.content, /^# /)
    assert.doesNotMatch(definition.content, /^---/)
  }

  dispose()
  assert.deepEqual(disposed, ['dsh-time-machine', 'dsh-teach', 'dsh-capsule'])
})

test('bundle rolls back earlier registrations when a later one fails', () => {
  const disposed = []
  let calls = 0
  const ctx = {
    skills: {
      register(definition) {
        calls += 1
        if (calls === 2) throw new Error('duplicate skill')
        return () => disposed.push(definition.name)
      },
    },
  }

  assert.throws(() => bundle.apply(ctx), /duplicate skill/)
  assert.deepEqual(disposed, ['dsh-capsule'])
})

test('npm package contains runtime files and excludes caches', () => {
  const output = execFileSync('npm', ['pack', '--dry-run', '--ignore-scripts', '--json'], {
    cwd: root,
    encoding: 'utf8',
  })
  const [pack] = JSON.parse(output)
  const paths = pack.files.map(({ path }) => path)

  for (const required of [
    'index.js',
    'cordis.patch.yml',
    'CHANGELOG.md',
    'CODE_OF_CONDUCT.md',
    'CONTRIBUTING.md',
    'RELEASING.md',
    'SECURITY.md',
    'dsh-capsule/SKILL.md',
    'dsh-teach/SKILL.md',
    'dsh-time-machine/SKILL.md',
  ]) {
    assert.ok(paths.includes(required), `missing ${required}`)
  }
  assert.ok(paths.every((path) => !path.includes('__pycache__')))
  assert.ok(paths.every((path) => !path.endsWith('.pyc')))
  assert.ok(paths.every((path) => !path.startsWith('tests/')))
  assert.ok(paths.every((path) => !path.startsWith('examples/')))
})

test('npm release metadata is explicit and public-registry scoped', () => {
  const packageJson = JSON.parse(readFileSync(`${root}/package.json`, 'utf8'))

  assert.equal(packageJson.name, 'dsh-session-lab')
  assert.equal(packageJson.private, false)
  assert.equal(packageJson.license, 'MIT')
  assert.equal(packageJson.publishConfig.access, 'public')
  assert.equal(packageJson.publishConfig.provenance, true)
  assert.equal(packageJson.publishConfig.registry, 'https://registry.npmjs.org/')
  assert.equal(packageJson.dsh.bundle.patch, './cordis.patch.yml')
})

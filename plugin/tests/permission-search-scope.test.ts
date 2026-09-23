// Обход запрета секретов через ОБЛАСТЬ поиска (#1592, находка ревью #1591).
//
// Фикс #124 проверял только корень поиска. Но поиск читает всё НИЖЕ корня:
// `Grep(pattern:"TOKEN", path:"/home/user")` заходит в ~/.ssh и ~/.secrets
// (Claude Code запускает ripgrep с --hidden), а секрет может стоять и в самом
// фильтре: `Grep(glob:"**/.env")`, `Glob(pattern:"/home/user/.ssh/*")`.

import { describe, expect, it } from 'bun:test'
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import {
  classifyToolCall,
  grepSecretExclusions,
  searchFilterSecretHit,
} from '../src/security/permission-policy.js'
import { decideLocal } from '../scripts/permission-gate-hook.js'

const policy = { version: 1, default_tier: 'confirm' as const, rules: [] }

function tier(toolName: string, toolInput: Record<string, unknown>): string {
  return classifyToolCall({ toolName, toolInput, policy }).tier
}

describe('фильтр поиска, нацеленный на секреты, запрещён', () => {
  const denied: [string, Record<string, unknown>][] = [
    ['Grep', { pattern: 'TOKEN', path: '/home/user', glob: '**/.env' }],
    ['Grep', { pattern: 'TOKEN', path: '/home/user', glob: '*.ts,.env.*' }],
    ['Grep', { pattern: 'TOKEN', glob: '{*.ts,.secrets/**}' }],
    ['Grep', { pattern: 'KEY', glob: '**/*.pem' }],
    ['Glob', { pattern: '/home/user/.ssh/*' }],
    ['Glob', { pattern: '**/.aws/**', path: '/home/user' }],
    ['Glob', { pattern: '**/id_ed25519*' }],
    ['Glob', { pattern: '**/*.key' }],
    // Ревью Codex #1592: правила, не покрытые образцами имён, и скобки с запятой.
    ['Glob', { pattern: '**/production.pem' }],
    ['Glob', { pattern: '**/.env.production' }],
    ['Glob', { pattern: '**/.codex/auth.json' }],
    ['Grep', { pattern: 'x', glob: '**/{.env,.aws}/**' }],
    ['Glob', { pattern: '**/{.env,.aws}/**' }],
    ['Glob', { pattern: '/proc/*/environ' }],
    ['Grep', { pattern: 'PATH', path: '/proc' }],
    ['Grep', { pattern: 'PATH', path: '/proc/1' }],
    ['LS', { path: '/proc/1' }],
    ['Glob', { pattern: '**/.e*' }],
  ]
  for (const [tool, input] of denied) {
    it(`${tool} ${JSON.stringify(input)} → deny`, () => {
      expect(tier(tool, input)).toBe('deny')
    })
  }

  const allowed: [string, Record<string, unknown>][] = [
    ['Grep', { pattern: 'TODO', path: '/home/user/project', glob: '*.ts' }],
    ['Grep', { pattern: 'TODO', glob: '**/*' }],
    ['Grep', { pattern: 'TODO', glob: '!**/.env' }],
    ['Glob', { pattern: '**/*.ts' }],
    ['Glob', { pattern: 'src/**/*' }],
    ['Glob', { pattern: '**/.eslintrc*' }],
    ['Grep', { pattern: 'x', glob: '**/*.json' }],
    ['Glob', { pattern: '**/*.json' }],
    ['Glob', { pattern: 'src/gcloud/**/*.ts' }],
    ['Grep', { pattern: 'x', glob: '*.{ts,tsx}' }],
    ['Glob', { pattern: '**/*s' }],
  ]
  for (const [tool, input] of allowed) {
    it(`${tool} ${JSON.stringify(input)} → не deny`, () => {
      expect(tier(tool, input)).not.toBe('deny')
    })
  }

  it('слишком много альтернатив в скобках — запрет, а не проверка усечённого набора', () => {
    const many = `{${Array.from({ length: 300 }, (_, i) => `safe${i}.ts`).join(',')},.env}`
    expect(tier('Grep', { pattern: 'x', glob: many })).toBe('deny')
    expect(tier('Glob', { pattern: `src/${many}` })).toBe('deny')
    expect(tier('Glob', { pattern: 'src/{a,b,c}/{d,e}/*.ts' })).not.toBe('deny')
  })

  it('чистый подстановочный сегмент секретом не считается', () => {
    expect(searchFilterSecretHit('**/*')).toBeUndefined()
    expect(searchFilterSecretHit('*')).toBeUndefined()
    expect(searchFilterSecretHit('.*')).toBeUndefined()
  })
})

describe('Grep по родительской папке пропускает секреты', () => {
  it('к glob дописываются исключения, свой glob сохраняется', () => {
    const out = grepSecretExclusions('Grep', { pattern: 'TOKEN', path: '/home/user', glob: '*.ts' })
    const globs = String(out?.glob).split(/\s+/)
    expect(globs[0]).toBe('*.ts')
    for (const g of ['!**/.env', '!**/.env.*', '!**/.secrets/**', '!**/.ssh', '!**/.aws/**', '!**/*.key', '!**/proc/*/environ']) {
      expect(globs).toContain(g)
    }
    expect(out?.pattern).toBe('TOKEN')
    expect(out?.path).toBe('/home/user')
  })

  it('без своего glob остаются только исключения', () => {
    const out = grepSecretExclusions('Grep', { pattern: 'TOKEN' })
    expect(String(out?.glob).startsWith('!**/')).toBe(true)
  })

  it('другим инструментам вход не меняется', () => {
    expect(grepSecretExclusions('Glob', { pattern: '**/*' })).toBeUndefined()
    expect(grepSecretExclusions('Read', { file_path: '/a' })).toBeUndefined()
  })

  it('хук отдаёт allow с updatedInput для Grep', () => {
    const d = decideLocal({
      envelope: { hook_event_name: 'PreToolUse', tool_name: 'Grep', tool_input: { pattern: 'x', path: '/srv/app' } },
      policy: { ...policy, default_tier: 'allow' as const },
      scope: 'main',
    })
    const out = JSON.parse(d.stdout ?? '{}')
    expect(out.hookSpecificOutput.permissionDecision).toBe('allow')
    expect(String(out.hookSpecificOutput.updatedInput.glob)).toContain('!**/.env')
  })

  // Живой ripgrep: те же флаги, что ставит Claude Code (--hidden, glob делится по пробелам).
  const rg = spawnSync('rg', ['--version'])
  it.skipIf(rg.status !== 0)('настоящий ripgrep не выдаёт строк из секретов', () => {
    const root = mkdtempSync(join(tmpdir(), 'grep-scope-'))
    mkdirSync(join(root, 'src'))
    mkdirSync(join(root, '.secrets'))
    mkdirSync(join(root, '.ssh'))
    mkdirSync(join(root, 'app'))
    writeFileSync(join(root, 'src', 'a.ts'), 'TOKEN_PLAIN\n')
    writeFileSync(join(root, '.env'), 'TOKEN_ENV\n')
    writeFileSync(join(root, 'app', '.env.local'), 'TOKEN_ENVLOCAL\n')
    writeFileSync(join(root, '.secrets', 'tok.json'), 'TOKEN_SECRETS\n')
    writeFileSync(join(root, '.ssh', 'id_ed25519'), 'TOKEN_SSH\n')
    writeFileSync(join(root, 'server.key'), 'TOKEN_KEY\n')

    const out = grepSecretExclusions('Grep', { pattern: 'TOKEN', path: root })
    const globArgs = String(out?.glob).split(/\s+/).flatMap((g) => ['--glob', g])
    const res = spawnSync('rg', ['--hidden', '-l', ...globArgs, 'TOKEN', root], { encoding: 'utf8' })
    const hits = res.stdout.split('\n').filter(Boolean).map((p) => p.slice(root.length + 1)).sort()
    expect(hits).toEqual(['src/a.ts'])

    // Явный секретный glob, который эвристика фильтра не ловит (ревью Codex #1592):
    // исключения идут ПОСЛЕ него, у ripgrep побеждает последний glob — строк нет.
    for (const own of ['**/server.k?y', '**/.en?', '.secrets/*', '**/id_ed2551?']) {
      const o = grepSecretExclusions('Grep', { pattern: 'TOKEN', path: root, glob: own })
      const args = String(o?.glob).split(/\s+/).flatMap((g) => ['--glob', g])
      const r = spawnSync('rg', ['--hidden', '-l', ...args, 'TOKEN', root], { encoding: 'utf8' })
      expect(r.stdout.trim()).toBe('')
    }

    // Контроль: без исключений тот же вызов видит секреты (иначе тест ничего не доказывает).
    const bare = spawnSync('rg', ['--hidden', '-l', 'TOKEN', root], { encoding: 'utf8' })
    expect(bare.stdout.split('\n').filter(Boolean).length).toBe(6)
  })
})

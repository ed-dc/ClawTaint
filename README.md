# ClawTaint 🎯

**Dynamic trust-based shell restrictions for OpenClaw.ai agents.**

ClawTaint is an OpenClaw plugin that tracks a **taint level** — a trust score that decreases when your AI agent accesses untrusted websites. As trust drops, shell command capabilities are progressively restricted.

## How It Works

```
Taint Level: 100 ────────────────────────────────────── 0
              │  PERMISSIVE  │  CAUTIOUS  │ RESTRICTED │ LOCKDOWN │
              │  All allowed │ Dangerous  │ Safe only  │ All      │
              │              │ blocked    │ (ls, cat)  │ blocked  │
              └──────────────┴────────────┴────────────┴──────────┘
                                    ← Untrusted URLs decrease taint
```

1. **Agent starts** with taint level 100 (fully trusted, all shell commands allowed)
2. **Agent browses** `https://docs.github.com` → trusted URL, no penalty
3. **Agent browses** `https://sketchy-site.xyz` → untrusted! Taint drops to 90
4. **After 3 untrusted sites** → taint at 70 (cautious tier) → `rm -rf` now blocked
5. **After 6 untrusted sites** → taint at 40 (restricted tier) → only `ls`, `cat`, `echo` allowed
6. **After 10 untrusted sites** → taint at 0 (lockdown) → all shell commands blocked

## Installation

```bash
# Install as OpenClaw plugin
openclaw plugins install clawtaint

# Or install locally for development
openclaw plugins install -l ./
```

## Configuration

Create a `clawtaint.yaml` file (see [clawtaint.yaml.example](clawtaint.yaml.example)):

```yaml
version: "1.0"

taint:
  initialLevel: 100
  penaltyPerUntrustedUrl: 10
  recoveryPerTrustedUrl: 0

trustedUrls:
  patterns:
    - "*.github.com"
    - "*.stackoverflow.com"
    - "*.npmjs.com"
    - "*.microsoft.com"
    # Add your own:
    - "*.your-company.com"

shellRestrictions:
  toolNames: [Bash, shell, terminal]
  dangerousCommands:
    - "rm -rf"
    - "DROP TABLE"
    - "shutdown"
  safeCommands:
    - ls
    - cat
    - echo
    - pwd
    - git status
```

## Restriction Tiers

| Tier | Taint Range | Shell Behavior |
|------|------------|----------------|
| **Permissive** | 75-100 | All commands allowed |
| **Cautious** | 50-74 | Dangerous commands blocked (`rm -rf`, `DROP TABLE`, etc.) |
| **Restricted** | 25-49 | Only safe commands allowed (`ls`, `cat`, `echo`, etc.) |
| **Lockdown** | 0-24 | ALL shell commands blocked |

## Development

```bash
npm install
npm run build
npm test
```

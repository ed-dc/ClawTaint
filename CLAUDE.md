# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ClawTaint is a lightweight OpenClaw.ai security plugin that implements **dynamic trust-based shell restrictions** using a taint level system.

**Core concept:**
- The agent starts with a taint level of 100 (fully trusted)
- Each time the agent accesses a website NOT in the trusted URL list, the taint level decreases
- As taint drops, shell command restrictions become progressively stricter:
  - **100-75 (Permissive):** All shell commands allowed
  - **74-50 (Cautious):** Dangerous commands blocked (rm -rf, DROP TABLE, etc.)
  - **49-25 (Restricted):** Only safe commands allowed (ls, cat, echo, etc.)
  - **24-0 (Lockdown):** ALL shell commands blocked

## Development Commands

```bash
npm run build         # Compile TypeScript to dist/
npm run dev           # Watch mode compilation
npm test              # Run all tests with Vitest
npm run test:watch    # Run tests in watch mode
npm run test:coverage # Generate coverage report
npm run lint          # Run ESLint on src/
npm run lint:fix      # Auto-fix ESLint issues
npm run clean         # Remove dist/ directory
```

## Architecture

### Plugin Lifecycle

ClawTaint integrates with OpenClaw through **two hooks**:

1. **before-tool-call** (Priority: 100) — `src/hooks/before-tool-call/`
   - Intercepts every tool call
   - Checks if tool input contains a URL → updates taint level
   - If tool is a shell command → enforces restrictions based on current tier
   - Fail-open: errors result in allowing the action

2. **before-agent-start** (Priority: 50) — `src/hooks/before-agent-start/`
   - Injects taint level context into agent's system prompt
   - Explains the trust-based restriction system to the agent
   - Only injects once per session

### Core Components

```
src/
├── index.ts                          # Plugin entry point, lifecycle, OpenClaw API types
├── config/
│   ├── schema.ts                     # Zod schemas for clawtaint.yaml
│   ├── defaults.ts                   # Default configuration values
│   ├── loader.ts                     # YAML config file loader
│   └── index.ts                      # Config exports
├── taint/
│   ├── tracker.ts                    # Taint level state management
│   ├── url-trust.ts                  # URL trust checking with glob patterns
│   ├── shell-restrictions.ts         # Shell command restriction engine
│   └── index.ts                      # Taint exports
├── hooks/
│   ├── before-tool-call/handler.ts   # Main security gate hook
│   └── before-agent-start/handler.ts # System prompt injection hook
└── utils/
    └── logger.ts                     # Logging utility
```

### Detection Flow

```
Tool Call Request
    │
    ▼
before-tool-call hook
    │
    ├─► Extract URL from tool input
    │   ├─ URL found + trusted   → Apply recovery (optional)
    │   ├─ URL found + untrusted → Apply taint penalty
    │   └─ No URL found          → No taint change
    │
    ├─► Is this a shell tool?
    │   ├─ No  → ALLOW
    │   └─ Yes → Check command against current restriction tier
    │            │
    │            ├─ Always-blocked → BLOCK (fork bomb, rm -rf /, etc.)
    │            ├─ Permissive     → ALLOW all
    │            ├─ Cautious       → BLOCK dangerous, ALLOW others
    │            ├─ Restricted     → ALLOW only safe commands
    │            └─ Lockdown       → BLOCK all
    │
    └─► Return { block, blockReason, metadata }
```

### Configuration

YAML configuration (`clawtaint.yaml`) validated with Zod schemas:

```yaml
version: "1.0"
global:
  enabled: true
  logLevel: info
taint:
  initialLevel: 100
  penaltyPerUntrustedUrl: 10
  recoveryPerTrustedUrl: 0
  thresholds: [...]
trustedUrls:
  patterns:
    - "*.github.com"
    - "*.stackoverflow.com"
shellRestrictions:
  toolNames: [Bash, shell, terminal]
  alwaysBlocked: [...]
  dangerousCommands: [...]
  safeCommands: [...]
```

## Code Patterns

### Adding New Trusted URL Patterns

Add glob patterns to `trustedUrls.patterns` in `clawtaint.yaml`:
- `*.example.com` — matches `docs.example.com`, `api.example.com`
- `**.example.com` — matches `sub.docs.example.com` (multi-level)
- `example.com` — exact match

### Testing

Tests use Vitest with co-located test files (`*.test.ts`):
- `src/taint/url-trust.test.ts` — URL extraction and trust checking
- `src/taint/tracker.test.ts` — Taint level progression and tier changes
- `src/taint/shell-restrictions.test.ts` — Command restriction per tier
- `src/hooks/before-tool-call/handler.test.ts` — Integration: URL→taint→shell flow
- `src/hooks/before-agent-start/handler.test.ts` — Prompt injection

## Important Files

- `src/index.ts` — Plugin entry point, OpenClaw API types, state management
- `src/taint/tracker.ts` — Core taint level logic
- `src/taint/shell-restrictions.ts` — Shell command restriction engine
- `src/hooks/before-tool-call/handler.ts` — Primary security enforcement
- `src/config/schema.ts` — Zod configuration schemas
- `openclaw.plugin.json` — Plugin metadata for OpenClaw registry
- `clawtaint.yaml.example` — Example configuration

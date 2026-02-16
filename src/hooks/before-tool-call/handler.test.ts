/**
 * Tests for Before Tool Call Hook Handler
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createBeforeToolCallHandler } from './handler.js';
import { createTaintTracker } from '../../taint/tracker.js';
import { createUrlTrustChecker } from '../../taint/url-trust.js';
import { createShellRestrictionEngine } from '../../taint/shell-restrictions.js';
import { getDefaultConfig } from '../../config/defaults.js';
import type { ToolCallContext } from '../../index.js';

function makeContext(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    toolName: 'test-tool',
    toolInput: {},
    timestamp: Date.now(),
    ...overrides,
  };
}

describe('BeforeToolCallHandler', () => {
  const config = getDefaultConfig();

  function createHandler() {
    const taintTracker = createTaintTracker(config.taint);
    const urlTrustChecker = createUrlTrustChecker(config.trustedUrls);
    const shellEngine = createShellRestrictionEngine(config.shellRestrictions);

    const handler = createBeforeToolCallHandler(config, {
      taintTracker,
      urlTrustChecker,
      shellEngine,
    });

    return { handler, taintTracker, urlTrustChecker, shellEngine };
  }

  // ===========================================================================
  // URL Trust Tracking
  // ===========================================================================

  describe('URL trust tracking', () => {
    it('should not change taint for non-URL tools', async () => {
      const { handler, taintTracker } = createHandler();
      await handler(makeContext({ toolName: 'file_read', toolInput: { path: '/etc/hosts' } }));
      expect(taintTracker.getLevel()).toBe(100);
    });

    it('should not change taint for trusted URLs', async () => {
      const { handler, taintTracker } = createHandler();
      await handler(makeContext({
        toolName: 'browser_navigate',
        toolInput: { url: 'https://docs.github.com/en/rest' },
      }));
      expect(taintTracker.getLevel()).toBe(100);
    });

    it('should decrease taint for untrusted URLs', async () => {
      const { handler, taintTracker } = createHandler();
      await handler(makeContext({
        toolName: 'browser_navigate',
        toolInput: { url: 'https://suspicious-site.xyz/hack' },
      }));
      expect(taintTracker.getLevel()).toBe(90);
    });

    it('should accumulate penalties for multiple untrusted URLs', async () => {
      const { handler, taintTracker } = createHandler();
      await handler(makeContext({ toolName: 't', toolInput: { url: 'https://evil1.xyz' } }));
      await handler(makeContext({ toolName: 't', toolInput: { url: 'https://evil2.xyz' } }));
      await handler(makeContext({ toolName: 't', toolInput: { url: 'https://evil3.xyz' } }));
      expect(taintTracker.getLevel()).toBe(70);
    });
  });

  // ===========================================================================
  // Shell Restrictions
  // ===========================================================================

  describe('shell restrictions', () => {
    it('should allow shell commands at full taint', async () => {
      const { handler } = createHandler();
      const result = await handler(makeContext({
        toolName: 'Bash',
        toolInput: { command: 'ls -la' },
      }));
      expect(result.block).toBe(false);
    });

    it('should block dangerous commands after taint drops to cautious', async () => {
      const { handler, taintTracker } = createHandler();

      // Drop taint to cautious tier (70)
      taintTracker.applyPenalty('url 1');
      taintTracker.applyPenalty('url 2');
      taintTracker.applyPenalty('url 3');
      expect(taintTracker.getTier()).toBe('cautious');

      const result = await handler(makeContext({
        toolName: 'Bash',
        toolInput: { command: 'rm -rf ./data' },
      }));
      expect(result.block).toBe(true);
      expect(result.blockReason).toContain('rm -rf');
    });

    it('should allow safe commands at cautious tier', async () => {
      const { handler, taintTracker } = createHandler();
      taintTracker.applyPenalty('url 1');
      taintTracker.applyPenalty('url 2');
      taintTracker.applyPenalty('url 3');

      const result = await handler(makeContext({
        toolName: 'Bash',
        toolInput: { command: 'ls -la' },
      }));
      expect(result.block).toBe(false);
    });

    it('should block most commands at restricted tier', async () => {
      const { handler, taintTracker } = createHandler();

      // Drop to restricted tier (40)
      for (let i = 0; i < 6; i++) taintTracker.applyPenalty(`url ${i}`);
      expect(taintTracker.getTier()).toBe('restricted');

      const result = await handler(makeContext({
        toolName: 'Bash',
        toolInput: { command: 'npm install express' },
      }));
      expect(result.block).toBe(true);
    });

    it('should still allow safe commands at restricted tier', async () => {
      const { handler, taintTracker } = createHandler();
      for (let i = 0; i < 6; i++) taintTracker.applyPenalty(`url ${i}`);

      const result = await handler(makeContext({
        toolName: 'Bash',
        toolInput: { command: 'cat README.md' },
      }));
      expect(result.block).toBe(false);
    });

    it('should block ALL commands at lockdown tier', async () => {
      const { handler, taintTracker } = createHandler();

      // Drop to lockdown (0)
      for (let i = 0; i < 10; i++) taintTracker.applyPenalty(`url ${i}`);
      expect(taintTracker.getTier()).toBe('lockdown');

      const result = await handler(makeContext({
        toolName: 'Bash',
        toolInput: { command: 'echo hello' },
      }));
      expect(result.block).toBe(true);
      expect(result.blockReason).toContain('LOCKDOWN');
    });

    it('should not restrict non-shell tools', async () => {
      const { handler, taintTracker } = createHandler();
      for (let i = 0; i < 10; i++) taintTracker.applyPenalty(`url ${i}`);

      const result = await handler(makeContext({
        toolName: 'file_read',
        toolInput: { path: '/etc/hosts' },
      }));
      expect(result.block).toBe(false);
    });

    it('should always block fork bomb even at full taint', async () => {
      const { handler } = createHandler();
      const result = await handler(makeContext({
        toolName: 'Bash',
        toolInput: { command: ':(){:|:&};:' },
      }));
      expect(result.block).toBe(true);
    });
  });

  // ===========================================================================
  // Combined URL + Shell Flow
  // ===========================================================================

  describe('combined flow: URL access reduces taint, restricts shell', () => {
    it('should degrade restrictions as untrusted URLs accumulate', async () => {
      const { handler, taintTracker } = createHandler();

      // Step 1: Shell works fine initially
      let result = await handler(makeContext({
        toolName: 'Bash',
        toolInput: { command: 'rm -rf ./build' },
      }));
      expect(result.block).toBe(false);

      // Step 2: Visit untrusted URLs (3x → taint drops to 70 → cautious)
      await handler(makeContext({ toolName: 'fetch', toolInput: { url: 'https://evil1.com' } }));
      await handler(makeContext({ toolName: 'fetch', toolInput: { url: 'https://evil2.com' } }));
      await handler(makeContext({ toolName: 'fetch', toolInput: { url: 'https://evil3.com' } }));
      expect(taintTracker.getTier()).toBe('cautious');

      // Step 3: Same command is now blocked
      result = await handler(makeContext({
        toolName: 'Bash',
        toolInput: { command: 'rm -rf ./build' },
      }));
      expect(result.block).toBe(true);
    });
  });

  // ===========================================================================
  // Error Handling
  // ===========================================================================

  describe('error handling', () => {
    it('should fail-open on error', async () => {
      const { handler } = createHandler();
      // Pass invalid context - should not throw
      const result = await handler({} as ToolCallContext);
      expect(result.block).toBe(false);
    });
  });
});

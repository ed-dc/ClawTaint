/**
 * Tests for Before Agent Start Hook Handler
 */

import { describe, it, expect } from 'vitest';
import { createBeforeAgentStartHandler, buildSecurityContextPrompt } from './handler.js';
import { createTaintTracker } from '../../taint/tracker.js';
import { getDefaultConfig } from '../../config/defaults.js';
import type { AgentStartContext } from '../../index.js';

function makeContext(overrides: Partial<AgentStartContext> = {}): AgentStartContext {
  return {
    timestamp: Date.now(),
    sessionId: 'test-session-1',
    ...overrides,
  };
}

describe('buildSecurityContextPrompt', () => {
  const config = getDefaultConfig();

  it('should include taint level and tier', () => {
    const prompt = buildSecurityContextPrompt(config, 100, 'permissive');
    expect(prompt).toContain('100/100');
    expect(prompt).toContain('PERMISSIVE');
  });

  it('should include trusted URL patterns', () => {
    const prompt = buildSecurityContextPrompt(config, 100, 'permissive');
    expect(prompt).toContain('*.github.com');
    expect(prompt).toContain('*.stackoverflow.com');
  });

  it('should describe all tiers', () => {
    const prompt = buildSecurityContextPrompt(config, 50, 'cautious');
    expect(prompt).toContain('PERMISSIVE');
    expect(prompt).toContain('CAUTIOUS');
    expect(prompt).toContain('RESTRICTED');
    expect(prompt).toContain('LOCKDOWN');
  });
});

describe('BeforeAgentStartHandler', () => {
  const config = getDefaultConfig();

  it('should inject security context on first call', async () => {
    const taintTracker = createTaintTracker(config.taint);
    const handler = createBeforeAgentStartHandler(config, { taintTracker });

    const result = await handler(makeContext());
    expect(result.prependContext).toBeDefined();
    expect(result.prependContext).toContain('CLAWTAINT');
    expect(result.prependContext).toContain('100/100');
  });

  it('should not re-inject for same session', async () => {
    const taintTracker = createTaintTracker(config.taint);
    const handler = createBeforeAgentStartHandler(config, { taintTracker });

    await handler(makeContext({ sessionId: 'session-1' }));
    const result = await handler(makeContext({ sessionId: 'session-1' }));
    expect(result.prependContext).toBeUndefined();
  });

  it('should inject for different sessions', async () => {
    const taintTracker = createTaintTracker(config.taint);
    const handler = createBeforeAgentStartHandler(config, { taintTracker });

    const r1 = await handler(makeContext({ sessionId: 'session-1' }));
    const r2 = await handler(makeContext({ sessionId: 'session-2' }));
    expect(r1.prependContext).toBeDefined();
    expect(r2.prependContext).toBeDefined();
  });

  it('should return empty when disabled', async () => {
    const disabledConfig = { ...config, global: { ...config.global, enabled: false } };
    const taintTracker = createTaintTracker(config.taint);
    const handler = createBeforeAgentStartHandler(disabledConfig, { taintTracker });

    const result = await handler(makeContext());
    expect(result.prependContext).toBeUndefined();
  });
});

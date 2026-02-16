/**
 * Tests for Taint Level Tracker
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createTaintTracker, resolveTier } from './tracker.js';
import type { TaintConfig } from '../config/schema.js';

const defaultConfig: TaintConfig = {
  initialLevel: 100,
  penaltyPerUntrustedUrl: 10,
  recoveryPerTrustedUrl: 5,
  minimumLevel: 0,
  thresholds: [
    { minTaint: 75, maxTaint: 100, tier: 'permissive' },
    { minTaint: 50, maxTaint: 74, tier: 'cautious' },
    { minTaint: 25, maxTaint: 49, tier: 'restricted' },
    { minTaint: 0, maxTaint: 24, tier: 'lockdown' },
  ],
};

// =============================================================================
// resolveTier
// =============================================================================

describe('resolveTier', () => {
  const thresholds = defaultConfig.thresholds;

  it('should return permissive for level 100', () => {
    expect(resolveTier(100, thresholds)).toBe('permissive');
  });

  it('should return permissive for level 75', () => {
    expect(resolveTier(75, thresholds)).toBe('permissive');
  });

  it('should return cautious for level 74', () => {
    expect(resolveTier(74, thresholds)).toBe('cautious');
  });

  it('should return cautious for level 50', () => {
    expect(resolveTier(50, thresholds)).toBe('cautious');
  });

  it('should return restricted for level 49', () => {
    expect(resolveTier(49, thresholds)).toBe('restricted');
  });

  it('should return restricted for level 25', () => {
    expect(resolveTier(25, thresholds)).toBe('restricted');
  });

  it('should return lockdown for level 24', () => {
    expect(resolveTier(24, thresholds)).toBe('lockdown');
  });

  it('should return lockdown for level 0', () => {
    expect(resolveTier(0, thresholds)).toBe('lockdown');
  });
});

// =============================================================================
// createTaintTracker
// =============================================================================

describe('createTaintTracker', () => {
  let tracker: ReturnType<typeof createTaintTracker>;

  beforeEach(() => {
    tracker = createTaintTracker(defaultConfig);
  });

  it('should start at initial level', () => {
    expect(tracker.getLevel()).toBe(100);
    expect(tracker.getTier()).toBe('permissive');
  });

  it('should decrease taint on penalty', () => {
    const event = tracker.applyPenalty('untrusted URL', 'https://evil.com', 'evil.com');
    expect(tracker.getLevel()).toBe(90);
    expect(event.previousLevel).toBe(100);
    expect(event.newLevel).toBe(90);
    expect(event.type).toBe('penalty');
  });

  it('should change tier when crossing threshold', () => {
    // Apply 3 penalties: 100 → 90 → 80 → 70 (crosses into cautious)
    tracker.applyPenalty('url 1');
    tracker.applyPenalty('url 2');
    const event = tracker.applyPenalty('url 3');

    expect(tracker.getLevel()).toBe(70);
    expect(tracker.getTier()).toBe('cautious');
    expect(event.tier).toBe('cautious');
  });

  it('should reach lockdown after many penalties', () => {
    for (let i = 0; i < 10; i++) {
      tracker.applyPenalty(`url ${i}`);
    }
    expect(tracker.getLevel()).toBe(0);
    expect(tracker.getTier()).toBe('lockdown');
  });

  it('should not go below minimum level', () => {
    for (let i = 0; i < 15; i++) {
      tracker.applyPenalty(`url ${i}`);
    }
    expect(tracker.getLevel()).toBe(0);
  });

  it('should recover taint when configured', () => {
    tracker.applyPenalty('untrusted');
    expect(tracker.getLevel()).toBe(90);

    const event = tracker.applyRecovery('trusted URL', 'https://github.com');
    expect(tracker.getLevel()).toBe(95);
    expect(event.type).toBe('recovery');
    expect(event.amount).toBe(5);
  });

  it('should not exceed 100 on recovery', () => {
    const event = tracker.applyRecovery('trusted');
    expect(tracker.getLevel()).toBe(100);
    expect(event.newLevel).toBe(100);
  });

  it('should track events in state', () => {
    tracker.applyPenalty('url 1');
    tracker.applyPenalty('url 2');
    tracker.applyRecovery('good url');

    const state = tracker.getState();
    expect(state.events).toHaveLength(3);
    expect(state.events[0].type).toBe('penalty');
    expect(state.events[2].type).toBe('recovery');
  });

  it('should reset to initial level', () => {
    tracker.applyPenalty('url 1');
    tracker.applyPenalty('url 2');
    expect(tracker.getLevel()).toBe(80);

    tracker.reset();
    expect(tracker.getLevel()).toBe(100);
    expect(tracker.getTier()).toBe('permissive');
    expect(tracker.getState().events).toHaveLength(0);
  });

  it('should handle no recovery when recoveryPerTrustedUrl is 0', () => {
    const noRecoveryTracker = createTaintTracker({
      ...defaultConfig,
      recoveryPerTrustedUrl: 0,
    });

    noRecoveryTracker.applyPenalty('url');
    expect(noRecoveryTracker.getLevel()).toBe(90);

    const event = noRecoveryTracker.applyRecovery('trusted');
    expect(noRecoveryTracker.getLevel()).toBe(90); // No change
    expect(event.amount).toBe(0);
  });

  it('should progress through all tiers', () => {
    // Start: permissive (100)
    expect(tracker.getTier()).toBe('permissive');

    // Drop to cautious (70)
    tracker.applyPenalty('1');
    tracker.applyPenalty('2');
    tracker.applyPenalty('3');
    expect(tracker.getTier()).toBe('cautious');

    // Drop to restricted (40)
    tracker.applyPenalty('4');
    tracker.applyPenalty('5');
    tracker.applyPenalty('6');
    expect(tracker.getTier()).toBe('restricted');

    // Drop to lockdown (10)
    tracker.applyPenalty('7');
    tracker.applyPenalty('8');
    tracker.applyPenalty('9');
    expect(tracker.getTier()).toBe('lockdown');
  });
});

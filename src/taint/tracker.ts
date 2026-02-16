/**
 * Taint Level Tracker
 *
 * Manages the session's taint level. The taint level starts high (100 = fully trusted)
 * and decreases when untrusted URLs are accessed, triggering progressively
 * stricter shell restrictions.
 */

import type { TaintConfig, RestrictionTier, TaintThreshold } from '../config/schema.js';
import type { Logger } from '../utils/logger.js';

// =============================================================================
// TYPES
// =============================================================================

export interface TaintEvent {
  timestamp: number;
  type: 'penalty' | 'recovery';
  amount: number;
  reason: string;
  url?: string;
  domain?: string;
  previousLevel: number;
  newLevel: number;
  tier: RestrictionTier;
}

export interface TaintState {
  /** Current taint level (0-100) */
  level: number;
  /** Current restriction tier */
  tier: RestrictionTier;
  /** History of taint events */
  events: TaintEvent[];
}

export interface TaintTracker {
  /** Get the current taint level */
  getLevel(): number;
  /** Get the current restriction tier */
  getTier(): RestrictionTier;
  /** Get the full taint state */
  getState(): Readonly<TaintState>;
  /** Apply a penalty (untrusted URL accessed) */
  applyPenalty(reason: string, url?: string, domain?: string): TaintEvent;
  /** Apply recovery (trusted URL accessed) */
  applyRecovery(reason: string, url?: string, domain?: string): TaintEvent;
  /** Reset taint to initial level */
  reset(): void;
}

// =============================================================================
// TIER RESOLUTION
// =============================================================================

/**
 * Determine the restriction tier for a given taint level.
 */
export function resolveTier(
  level: number,
  thresholds: TaintThreshold[]
): RestrictionTier {
  // Sort thresholds by minTaint descending to find the first match
  const sorted = [...thresholds].sort((a, b) => b.minTaint - a.minTaint);

  for (const threshold of sorted) {
    if (level >= threshold.minTaint && level <= threshold.maxTaint) {
      return threshold.tier;
    }
  }

  // Fallback: if level is 0 or below all thresholds, use the most restrictive
  if (level <= 0) return 'lockdown';
  // If above all thresholds, use the most permissive
  return 'permissive';
}

// =============================================================================
// TAINT TRACKER
// =============================================================================

/**
 * Create a taint level tracker.
 */
export function createTaintTracker(
  config: TaintConfig,
  logger?: Logger
): TaintTracker {
  const log = logger;

  const state: TaintState = {
    level: config.initialLevel,
    tier: resolveTier(config.initialLevel, config.thresholds),
    events: [],
  };

  function clampLevel(level: number): number {
    return Math.max(config.minimumLevel, Math.min(100, level));
  }

  function applyPenalty(reason: string, url?: string, domain?: string): TaintEvent {
    const previousLevel = state.level;
    const previousTier = state.tier;

    state.level = clampLevel(state.level - config.penaltyPerUntrustedUrl);
    state.tier = resolveTier(state.level, config.thresholds);

    const event: TaintEvent = {
      timestamp: Date.now(),
      type: 'penalty',
      amount: config.penaltyPerUntrustedUrl,
      reason,
      url,
      domain,
      previousLevel,
      newLevel: state.level,
      tier: state.tier,
    };

    state.events.push(event);

    log?.info(
      `Taint penalty: ${previousLevel} → ${state.level} (${previousTier} → ${state.tier}) | ${reason}`
    );

    if (previousTier !== state.tier) {
      log?.warn(
        `⚠ Restriction tier changed: ${previousTier} → ${state.tier}`
      );
    }

    return event;
  }

  function applyRecovery(reason: string, url?: string, domain?: string): TaintEvent {
    if (config.recoveryPerTrustedUrl === 0) {
      // No recovery configured, return a no-op event
      return {
        timestamp: Date.now(),
        type: 'recovery',
        amount: 0,
        reason,
        url,
        domain,
        previousLevel: state.level,
        newLevel: state.level,
        tier: state.tier,
      };
    }

    const previousLevel = state.level;
    const previousTier = state.tier;

    state.level = clampLevel(state.level + config.recoveryPerTrustedUrl);
    state.tier = resolveTier(state.level, config.thresholds);

    const event: TaintEvent = {
      timestamp: Date.now(),
      type: 'recovery',
      amount: config.recoveryPerTrustedUrl,
      reason,
      url,
      domain,
      previousLevel,
      newLevel: state.level,
      tier: state.tier,
    };

    state.events.push(event);

    log?.debug(
      `Taint recovery: ${previousLevel} → ${state.level} (${previousTier} → ${state.tier}) | ${reason}`
    );

    return event;
  }

  function reset(): void {
    state.level = config.initialLevel;
    state.tier = resolveTier(config.initialLevel, config.thresholds);
    state.events = [];
    log?.info(`Taint level reset to ${config.initialLevel}`);
  }

  return {
    getLevel: () => state.level,
    getTier: () => state.tier,
    getState: () => ({ ...state, events: [...state.events] }),
    applyPenalty,
    applyRecovery,
    reset,
  };
}

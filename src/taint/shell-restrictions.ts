/**
 * Shell Restriction Engine
 *
 * Determines whether a shell command is allowed based on the current
 * restriction tier. Tiers are progressively stricter:
 *
 *   permissive  → All commands allowed (except always-blocked)
 *   cautious    → Dangerous commands blocked
 *   restricted  → Only safe commands allowed
 *   lockdown    → All shell commands blocked
 */

import type { ShellRestrictions, RestrictionTier } from '../config/schema.js';
import type { Logger } from '../utils/logger.js';

// =============================================================================
// TYPES
// =============================================================================

export interface ShellCheckResult {
  /** Whether the command is allowed */
  allowed: boolean;
  /** Reason for blocking (if blocked) */
  reason?: string;
  /** The current restriction tier */
  tier: RestrictionTier;
  /** The matched pattern that caused blocking (if any) */
  matchedPattern?: string;
}

export interface ShellRestrictionEngine {
  /** Check if a shell command is allowed under the given tier */
  check(command: string, tier: RestrictionTier): ShellCheckResult;
  /** Check if a tool name is a shell tool */
  isShellTool(toolName: string): boolean;
}

// =============================================================================
// COMMAND MATCHING
// =============================================================================

/**
 * Check if a command string contains a pattern (case-insensitive).
 */
function commandContains(command: string, pattern: string): boolean {
  return command.toLowerCase().includes(pattern.toLowerCase());
}

/**
 * Extract the base command name from a command string.
 * e.g., "ls -la /tmp" → "ls"
 */
function extractBaseCommand(command: string): string {
  const trimmed = command.trim();
  // Handle command chains: take the first command
  const firstCmd = trimmed.split(/[;&|]/)[0].trim();
  // Extract the executable name
  const parts = firstCmd.split(/\s+/);
  return parts[0].toLowerCase();
}

// =============================================================================
// SHELL RESTRICTION ENGINE
// =============================================================================

/**
 * Create a shell restriction engine.
 */
export function createShellRestrictionEngine(
  config: ShellRestrictions,
  logger?: Logger
): ShellRestrictionEngine {
  const log = logger;

  // Normalize tool names for matching
  const shellToolNames = new Set(
    config.toolNames.map((name) => name.toLowerCase())
  );

  function isShellTool(toolName: string): boolean {
    return shellToolNames.has(toolName.toLowerCase());
  }

  function check(command: string, tier: RestrictionTier): ShellCheckResult {
    // 1. Always-blocked commands (regardless of tier, even permissive)
    for (const pattern of config.alwaysBlocked) {
      if (commandContains(command, pattern)) {
        log?.warn(`Command blocked (always-blocked): "${command}" matched "${pattern}"`);
        return {
          allowed: false,
          reason: `Command matches always-blocked pattern: "${pattern}"`,
          tier,
          matchedPattern: pattern,
        };
      }
    }

    // 2. Apply tier-based restrictions
    switch (tier) {
      case 'permissive':
        // Everything allowed (except always-blocked above)
        return { allowed: true, tier };

      case 'cautious':
        // Block dangerous commands
        for (const pattern of config.dangerousCommands) {
          if (commandContains(command, pattern)) {
            log?.info(`Command blocked (cautious tier): "${command}" matched "${pattern}"`);
            return {
              allowed: false,
              reason: `Taint level reduced to "cautious" tier. Dangerous command blocked: "${pattern}"`,
              tier,
              matchedPattern: pattern,
            };
          }
        }
        return { allowed: true, tier };

      case 'restricted': {
        // Only safe commands allowed
        const baseCmd = extractBaseCommand(command);
        const isSafe = config.safeCommands.some((safe) => {
          const safeBase = safe.toLowerCase().split(/\s+/)[0];
          return baseCmd === safeBase;
        });

        if (isSafe) {
          return { allowed: true, tier };
        }

        log?.info(`Command blocked (restricted tier): "${command}" is not in safe list`);
        return {
          allowed: false,
          reason: `Taint level reduced to "restricted" tier. Only safe commands are allowed (ls, cat, echo, etc.). Command "${baseCmd}" is not in the safe list.`,
          tier,
        };
      }

      case 'lockdown':
        // All shell commands blocked
        log?.warn(`Command blocked (lockdown tier): all shell commands blocked`);
        return {
          allowed: false,
          reason: 'Taint level critically low — LOCKDOWN. All shell commands are blocked. The agent has accessed too many untrusted websites.',
          tier,
        };

      default:
        // Unknown tier, fail-safe to block
        return {
          allowed: false,
          reason: `Unknown restriction tier: ${tier as string}`,
          tier,
        };
    }
  }

  return { check, isShellTool };
}

/**
 * Before Tool Call Hook Handler
 *
 * Intercepts every tool call to:
 * 1. Check if the tool accesses a URL → update taint level
 * 2. Check if the tool is a shell command → enforce restrictions based on taint tier
 */

import type { ClawTaintConfig } from '../../config/schema.js';
import type { Logger } from '../../utils/logger.js';
import type { TaintTracker } from '../../taint/tracker.js';
import type { UrlTrustChecker } from '../../taint/url-trust.js';
import type { ShellRestrictionEngine } from '../../taint/shell-restrictions.js';
import type { BeforeToolCallHandler, ToolCallContext, BeforeToolCallResult } from '../../index.js';

// =============================================================================
// TYPES
// =============================================================================

export interface BeforeToolCallHandlerDeps {
  taintTracker: TaintTracker;
  urlTrustChecker: UrlTrustChecker;
  shellEngine: ShellRestrictionEngine;
}

// =============================================================================
// HANDLER FACTORY
// =============================================================================

/**
 * Create the before-tool-call handler.
 *
 * Flow:
 * 1. Check if plugin is enabled
 * 2. Extract URL from tool input → check trust → update taint
 * 3. Check if tool is shell → enforce restrictions based on current tier
 * 4. Return allow/block result
 */
export function createBeforeToolCallHandler(
  config: ClawTaintConfig,
  deps: BeforeToolCallHandlerDeps,
  logger?: Logger
): BeforeToolCallHandler {
  const log = logger;
  const { taintTracker, urlTrustChecker, shellEngine } = deps;

  return async (context: ToolCallContext): Promise<BeforeToolCallResult> => {
    try {
      const toolName = context.toolName;
      const toolInput = context.toolInput || context.params || {};

      log?.debug(`[Hook:before-tool-call] Entry: tool=${toolName}`);

      // 1. Check if plugin is disabled
      if (config.global?.enabled === false) {
        return { block: false };
      }

      // 2. Check URL trust and update taint level
      const urlCheck = urlTrustChecker.check(toolInput);

      if (urlCheck.urlFound) {
        if (urlCheck.trusted) {
          // Trusted URL: optionally recover taint
          taintTracker.applyRecovery(
            `Accessed trusted URL: ${urlCheck.domain}`,
            urlCheck.url,
            urlCheck.domain
          );
        } else {
          // Untrusted URL: apply penalty
          const event = taintTracker.applyPenalty(
            `Accessed untrusted URL: ${urlCheck.domain || urlCheck.url}`,
            urlCheck.url,
            urlCheck.domain
          );

          log?.info(
            `Taint level: ${event.previousLevel} → ${event.newLevel} (tier: ${event.tier})`
          );
        }
      }

      // 3. Check shell restrictions
      if (shellEngine.isShellTool(toolName)) {
        // Extract command from tool input
        const command = extractCommand(toolInput);

        if (command) {
          const currentTier = taintTracker.getTier();
          const shellCheck = shellEngine.check(command, currentTier);

          if (!shellCheck.allowed) {
            log?.info(
              `[Hook:before-tool-call] Shell command BLOCKED: tool=${toolName}, tier=${currentTier}, taint=${taintTracker.getLevel()}`
            );

            return {
              block: true,
              blockReason: shellCheck.reason,
              metadata: {
                category: 'shell-restriction',
                severity: currentTier === 'lockdown' ? 'critical' : 'high',
                reason: shellCheck.reason || 'Shell command blocked by taint level restrictions',
                taintLevel: taintTracker.getLevel(),
                tier: currentTier,
              },
            };
          }
        }
      }

      // 4. Allow the tool call
      log?.debug(`[Hook:before-tool-call] Exit: tool=${toolName}, result=allow, taint=${taintTracker.getLevel()}`);
      return { block: false };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      log?.error(`[Hook:before-tool-call] Unhandled error: ${errorMessage}`);
      return { block: false }; // Fail-open
    }
  };
}

// =============================================================================
// HELPERS
// =============================================================================

/**
 * Extract the command string from tool input.
 * Handles various field names used by different shell tools.
 */
function extractCommand(toolInput: Record<string, unknown>): string | null {
  const commandFields = ['command', 'cmd', 'script', 'input', 'code', 'content'];
  for (const field of commandFields) {
    const value = toolInput[field];
    if (typeof value === 'string' && value.trim().length > 0) {
      return value.trim();
    }
  }
  return null;
}

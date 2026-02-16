/**
 * Before Agent Start Hook Handler
 *
 * Injects taint level awareness into the agent's system prompt
 * so the agent understands it's operating under a trust-based
 * restriction system.
 */

import type { ClawTaintConfig } from '../../config/schema.js';
import type { Logger } from '../../utils/logger.js';
import type { TaintTracker } from '../../taint/tracker.js';
import type { AgentStartContext, BeforeAgentStartResult, BeforeAgentStartHandler } from '../../index.js';

// =============================================================================
// TYPES
// =============================================================================

export interface BeforeAgentStartHandlerDeps {
  taintTracker: TaintTracker;
}

// =============================================================================
// PROMPT BUILDING
// =============================================================================

/**
 * Build the security context prompt to inject into the agent's system prompt.
 */
export function buildSecurityContextPrompt(config: ClawTaintConfig, taintLevel: number, tier: string): string {
  const lines: string[] = [
    '[CLAWTAINT SECURITY CONTEXT]',
    '',
    'This session uses a dynamic trust-based security system (ClawTaint).',
    '',
    `Current taint level: ${taintLevel}/100`,
    `Current restriction tier: ${tier.toUpperCase()}`,
    '',
    'How it works:',
    '- Your taint level starts at 100 (fully trusted).',
    '- Each time you access a website NOT in the trusted URL list, your taint level decreases.',
    '- As your taint level drops, shell command restrictions become stricter:',
    '',
    '  100-75 (PERMISSIVE): All shell commands allowed.',
    '  74-50  (CAUTIOUS):   Dangerous commands blocked (rm -rf, DROP TABLE, etc.).',
    '  49-25  (RESTRICTED): Only safe commands allowed (ls, cat, echo, etc.).',
    '  24-0   (LOCKDOWN):   ALL shell commands blocked.',
    '',
  ];

  if (config.trustedUrls.patterns.length > 0) {
    lines.push('Trusted URL patterns:');
    for (const pattern of config.trustedUrls.patterns.slice(0, 10)) {
      lines.push(`  - ${pattern}`);
    }
    if (config.trustedUrls.patterns.length > 10) {
      lines.push(`  ... and ${config.trustedUrls.patterns.length - 10} more`);
    }
    lines.push('');
  }

  lines.push(
    'To maintain your shell access, prefer using trusted URLs.',
    'If a command is blocked, check your current taint level before retrying.',
  );

  return lines.join('\n');
}

// =============================================================================
// HANDLER FACTORY
// =============================================================================

/**
 * Create the before-agent-start handler.
 */
export function createBeforeAgentStartHandler(
  config: ClawTaintConfig,
  deps: BeforeAgentStartHandlerDeps,
  logger?: Logger
): BeforeAgentStartHandler {
  const log = logger;
  const { taintTracker } = deps;

  // Track injected sessions to avoid duplicates
  const injectedSessions = new Set<string>();

  return async (context: AgentStartContext): Promise<BeforeAgentStartResult> => {
    try {
      // Generate session ID
      let sessionId: string | undefined = context.sessionId;
      if (!sessionId) {
        sessionId = `session_${context.timestamp || Date.now()}`;
      }

      log?.info(`[Hook:before-agent-start] Entry: session=${sessionId}`);

      // Don't re-inject for the same session
      if (injectedSessions.has(sessionId)) {
        log?.debug(`[Hook:before-agent-start] Already injected for session=${sessionId}`);
        return {};
      }

      if (config.global?.enabled === false) {
        return {};
      }

      // Build prompt
      const prependContext = buildSecurityContextPrompt(
        config,
        taintTracker.getLevel(),
        taintTracker.getTier()
      );

      injectedSessions.add(sessionId);
      log?.info(`[Hook:before-agent-start] Exit: injected ${prependContext.length} chars`);

      return { prependContext };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      log?.error(`[Hook:before-agent-start] Error: ${errorMessage}`);
      return {};
    }
  };
}

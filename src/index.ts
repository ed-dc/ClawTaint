/**
 * ClawTaint - Taint Level Plugin for OpenClaw.ai
 *
 * Dynamic trust-based security: tracks a taint level that decreases
 * when untrusted websites are accessed, progressively restricting
 * shell command capabilities.
 */

// =============================================================================
// VERSION & CONSTANTS
// =============================================================================

export const VERSION = '0.1.0';
export const PLUGIN_ID = 'clawtaint';
export const PLUGIN_NAME = 'ClawTaint - Taint Level Plugin';

// =============================================================================
// IMPORTS
// =============================================================================

import { createLogger, createNoOpLogger, type Logger } from './utils/logger.js';
import { loadConfig } from './config/loader.js';
import type { ClawTaintConfig } from './config/schema.js';
import { createTaintTracker, type TaintTracker } from './taint/tracker.js';
import { createUrlTrustChecker, type UrlTrustChecker } from './taint/url-trust.js';
import { createShellRestrictionEngine, type ShellRestrictionEngine } from './taint/shell-restrictions.js';
import { createBeforeToolCallHandler } from './hooks/before-tool-call/handler.js';
import { createBeforeAgentStartHandler } from './hooks/before-agent-start/handler.js';

// =============================================================================
// TYPE DEFINITIONS (OpenClaw Plugin API)
// =============================================================================

/**
 * Base context provided to all hooks
 */
export interface HookContext {
  sessionId?: string;
  userId?: string;
  timestamp: number;
}

/**
 * Tool call context passed to before-tool-call hook
 */
export interface ToolCallContext extends HookContext {
  toolName: string;
  toolInput?: Record<string, unknown>;
  params?: Record<string, unknown>;
}

/**
 * Result from before-tool-call hook
 */
export interface BeforeToolCallResult {
  block?: boolean;
  blockReason?: string;
  params?: Record<string, unknown>;
  metadata?: {
    category?: string;
    severity?: string;
    reason?: string;
    taintLevel?: number;
    tier?: string;
    rule?: string;
  };
}

/**
 * Handler type for before-tool-call hook
 */
export type BeforeToolCallHandler = (
  context: ToolCallContext
) => Promise<BeforeToolCallResult>;

/**
 * Agent start context
 */
export interface AgentStartContext extends HookContext {
  systemPrompt?: string;
  agentConfig?: Record<string, unknown>;
  prompt?: string;
  messages?: Array<{
    role: string;
    content: unknown;
    timestamp?: number;
    [key: string]: unknown;
  }>;
}

/**
 * Result from before-agent-start hook
 */
export interface BeforeAgentStartResult {
  systemPrompt?: string;
  prependContext?: string;
  modifiedConfig?: Record<string, unknown>;
}

/**
 * Handler type for before-agent-start hook
 */
export type BeforeAgentStartHandler = (
  context: AgentStartContext
) => Promise<BeforeAgentStartResult>;

/**
 * OpenClaw Plugin API interface
 */
export interface OpenClawPluginAPI {
  on: (hookName: string, handler: unknown, options?: { priority?: number }) => void;
  config: PluginConfig;
  log: (level: 'debug' | 'info' | 'warn' | 'error', message: string, data?: unknown) => void;
}

/**
 * Plugin configuration from OpenClaw
 */
export interface PluginConfig {
  configPath?: string;
  enabled?: boolean;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
}

// =============================================================================
// PLUGIN STATE
// =============================================================================

interface PluginState {
  api: OpenClawPluginAPI | null;
  config: PluginConfig | null;
  clawtaintConfig: ClawTaintConfig | null;
  initialized: boolean;
  logger: Logger;
  // Core components
  taintTracker: TaintTracker | null;
  urlTrustChecker: UrlTrustChecker | null;
  shellEngine: ShellRestrictionEngine | null;
}

const state: PluginState = {
  api: null,
  config: null,
  clawtaintConfig: null,
  initialized: false,
  logger: createNoOpLogger(),
  taintTracker: null,
  urlTrustChecker: null,
  shellEngine: null,
};

// =============================================================================
// PLUGIN LIFECYCLE
// =============================================================================

/**
 * Activates the ClawTaint plugin and registers all hooks.
 */
export function activate(api: OpenClawPluginAPI): () => void {
  if (state.initialized) {
    state.logger.warn('Plugin already activated, skipping');
    return () => deactivate();
  }

  // Store API reference
  state.api = api;
  state.config = api.config;
  state.logger = createLogger(api, state.config);

  state.logger.info(`Activating ClawTaint Plugin v${VERSION}`);

  // Check if plugin is enabled
  if (state.config?.enabled === false) {
    state.logger.info('Plugin is disabled via configuration');
    state.initialized = true;
    return () => deactivate();
  }

  // Load configuration
  let config: ClawTaintConfig;
  try {
    const configPath = state.config?.configPath;
    config = loadConfig(configPath, state.logger);
    state.clawtaintConfig = config;
    state.logger.info('Configuration loaded successfully');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    state.logger.error(`Failed to load configuration: ${errorMessage}`);
    state.logger.warn('Using default configuration');
    config = loadConfig(undefined, state.logger); // loadConfig returns defaults on failure
    state.clawtaintConfig = config;
  }

  // Initialize core components
  state.taintTracker = createTaintTracker(config.taint, state.logger);
  state.urlTrustChecker = createUrlTrustChecker(config.trustedUrls, state.logger);
  state.shellEngine = createShellRestrictionEngine(config.shellRestrictions, state.logger);

  // Create hook handlers
  const beforeToolCallHandler = createBeforeToolCallHandler(config, {
    taintTracker: state.taintTracker,
    urlTrustChecker: state.urlTrustChecker,
    shellEngine: state.shellEngine,
  }, state.logger);

  const beforeAgentStartHandler = createBeforeAgentStartHandler(config, {
    taintTracker: state.taintTracker,
  }, state.logger);

  // Register hooks with OpenClaw
  api.on('before_tool_call', beforeToolCallHandler, { priority: 100 });
  api.on('before_agent_start', beforeAgentStartHandler, { priority: 50 });

  state.initialized = true;
  state.logger.info('All hooks registered successfully');

  return () => deactivate();
}

/**
 * Deactivates the ClawTaint plugin.
 */
export function deactivate(): void {
  if (!state.initialized) return;

  state.logger.info('Deactivating ClawTaint Plugin');

  state.api = null;
  state.config = null;
  state.clawtaintConfig = null;
  state.taintTracker = null;
  state.urlTrustChecker = null;
  state.shellEngine = null;
  state.initialized = false;
  state.logger = createNoOpLogger();
}

/**
 * Check if the plugin is currently active
 */
export function isActive(): boolean {
  return state.initialized;
}

/**
 * Get the current taint state (for testing/debugging)
 */
export function getTaintState(): { level: number; tier: string } | null {
  if (!state.taintTracker) return null;
  return {
    level: state.taintTracker.getLevel(),
    tier: state.taintTracker.getTier(),
  };
}

// =============================================================================
// CONFIG SCHEMA
// =============================================================================

export const pluginConfigSchema = {
  type: 'object',
  properties: {
    configPath: {
      type: 'string',
      default: './clawtaint.yaml',
      description: 'Path to the ClawTaint YAML configuration file',
    },
    enabled: {
      type: 'boolean',
      default: true,
      description: 'Whether the taint level plugin is enabled',
    },
    logLevel: {
      type: 'string',
      enum: ['debug', 'info', 'warn', 'error'],
      default: 'info',
      description: 'Logging verbosity level',
    },
  },
  additionalProperties: false,
} as const;

// =============================================================================
// REGISTER & DEFAULT EXPORT
// =============================================================================

function register(api: OpenClawPluginAPI): () => void {
  return activate(api);
}

export default {
  id: PLUGIN_ID,
  name: PLUGIN_NAME,
  version: VERSION,
  configSchema: pluginConfigSchema,
  register,
  activate,
  deactivate,
};

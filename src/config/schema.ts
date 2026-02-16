/**
 * ClawTaint Configuration Schema
 *
 * Defines the shape of clawtaint.yaml configuration using Zod.
 */

import { z } from 'zod';

// =============================================================================
// SCHEMA DEFINITIONS
// =============================================================================

/**
 * Shell restriction tier applied at different taint levels
 */
export const RestrictionTierSchema = z.enum([
  'permissive',  // All shell commands allowed
  'cautious',    // Dangerous commands blocked
  'restricted',  // Only safe commands allowed
  'lockdown',    // All shell commands blocked
]);

/**
 * A taint threshold that maps a taint range to a restriction tier
 */
export const TaintThresholdSchema = z.object({
  /** Minimum taint level for this tier (inclusive) */
  minTaint: z.number().min(0).max(100),
  /** Maximum taint level for this tier (inclusive) */
  maxTaint: z.number().min(0).max(100),
  /** Restriction tier to apply */
  tier: RestrictionTierSchema,
});

/**
 * Shell restriction configuration
 */
export const ShellRestrictionsSchema = z.object({
  /** Shell tool names to intercept (e.g., "Bash", "shell", "terminal") */
  toolNames: z.array(z.string()).default(['Bash', 'shell', 'terminal', 'run_command', 'execute']),

  /** Commands always blocked regardless of taint level */
  alwaysBlocked: z.array(z.string()).default([
    'rm -rf /',
    'mkfs',
    'dd if=',
    ':(){:|:&};:',
    '> /dev/sda',
  ]),

  /** Commands considered dangerous (blocked at 'cautious' tier and below) */
  dangerousCommands: z.array(z.string()).default([
    'rm -rf',
    'rm -r',
    'rmdir',
    'format',
    'shutdown',
    'reboot',
    'halt',
    'poweroff',
    'init 0',
    'init 6',
    'kill -9',
    'killall',
    'pkill',
    'chmod 777',
    'chmod -R',
    'chown -R',
    'iptables -F',
    'systemctl stop',
    'systemctl disable',
    'DROP TABLE',
    'DROP DATABASE',
    'TRUNCATE',
    'DELETE FROM',
    'curl | sh',
    'curl | bash',
    'wget | sh',
    'wget | bash',
  ]),

  /** Commands considered safe (allowed at 'restricted' tier) */
  safeCommands: z.array(z.string()).default([
    'ls',
    'dir',
    'pwd',
    'cd',
    'cat',
    'head',
    'tail',
    'echo',
    'whoami',
    'date',
    'uname',
    'hostname',
    'env',
    'printenv',
    'which',
    'where',
    'type',
    'file',
    'wc',
    'sort',
    'uniq',
    'grep',
    'find',
    'tree',
    'df',
    'du',
    'free',
    'top',
    'ps',
    'uptime',
    'node --version',
    'npm --version',
    'python --version',
    'git status',
    'git log',
    'git diff',
    'git branch',
  ]),
});

/**
 * Taint level configuration
 */
export const TaintConfigSchema = z.object({
  /** Starting taint level (0-100) */
  initialLevel: z.number().min(0).max(100).default(100),

  /** How much taint decreases per untrusted URL access */
  penaltyPerUntrustedUrl: z.number().min(0).max(100).default(10),

  /** How much taint recovers per trusted URL access (0 = no recovery) */
  recoveryPerTrustedUrl: z.number().min(0).max(100).default(0),

  /** Minimum taint level (floor) */
  minimumLevel: z.number().min(0).max(100).default(0),

  /** Taint thresholds defining restriction tiers */
  thresholds: z.array(TaintThresholdSchema).default([
    { minTaint: 75, maxTaint: 100, tier: 'permissive' },
    { minTaint: 50, maxTaint: 74, tier: 'cautious' },
    { minTaint: 25, maxTaint: 49, tier: 'restricted' },
    { minTaint: 0, maxTaint: 24, tier: 'lockdown' },
  ]),
});

/**
 * Trusted URLs configuration
 */
export const TrustedUrlsSchema = z.object({
  /** List of trusted URL patterns (supports glob: *.github.com, docs.*.org) */
  patterns: z.array(z.string()).default([
    '*.github.com',
    '*.stackoverflow.com',
    '*.npmjs.com',
    '*.python.org',
    '*.mozilla.org',
    '*.microsoft.com',
    '*.typescriptlang.org',
    '*.nodejs.org',
    '*.developer.mozilla.org',
  ]),
});

/**
 * Global plugin settings
 */
export const GlobalConfigSchema = z.object({
  enabled: z.boolean().default(true),
  logLevel: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
});

/**
 * Root configuration schema
 */
export const ClawTaintConfigSchema = z.object({
  version: z.string().default('1.0'),
  global: GlobalConfigSchema.default({}),
  taint: TaintConfigSchema.default({}),
  trustedUrls: TrustedUrlsSchema.default({}),
  shellRestrictions: ShellRestrictionsSchema.default({}),
});

// =============================================================================
// TYPE EXPORTS
// =============================================================================

export type RestrictionTier = z.infer<typeof RestrictionTierSchema>;
export type TaintThreshold = z.infer<typeof TaintThresholdSchema>;
export type ShellRestrictions = z.infer<typeof ShellRestrictionsSchema>;
export type TaintConfig = z.infer<typeof TaintConfigSchema>;
export type TrustedUrls = z.infer<typeof TrustedUrlsSchema>;
export type GlobalConfig = z.infer<typeof GlobalConfigSchema>;
export type ClawTaintConfig = z.infer<typeof ClawTaintConfigSchema>;

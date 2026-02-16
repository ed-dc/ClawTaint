/**
 * Configuration Loader
 *
 * Loads and validates clawtaint.yaml configuration files.
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { ClawTaintConfigSchema, type ClawTaintConfig } from './schema.js';
import { getDefaultConfig } from './defaults.js';
import type { Logger } from '../utils/logger.js';

/**
 * Load configuration from a YAML file.
 *
 * @param configPath - Path to the YAML config file (default: ./clawtaint.yaml)
 * @param logger - Optional logger instance
 * @returns Validated ClawTaintConfig
 */
export function loadConfig(
  configPath?: string,
  logger?: Logger
): ClawTaintConfig {
  const filePath = resolve(configPath || './clawtaint.yaml');

  if (!existsSync(filePath)) {
    logger?.warn(`Config file not found at ${filePath}, using defaults`);
    return getDefaultConfig();
  }

  try {
    const rawYaml = readFileSync(filePath, 'utf-8');
    const parsed = parseYaml(rawYaml);

    if (!parsed || typeof parsed !== 'object') {
      logger?.warn('Config file is empty or invalid, using defaults');
      return getDefaultConfig();
    }

    // Validate and apply defaults via Zod
    const result = ClawTaintConfigSchema.safeParse(parsed);

    if (!result.success) {
      logger?.error(`Config validation failed: ${result.error.message}`);
      logger?.warn('Using default configuration');
      return getDefaultConfig();
    }

    logger?.info(`Configuration loaded from ${filePath}`);
    return result.data;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger?.error(`Failed to load config: ${errorMessage}`);
    return getDefaultConfig();
  }
}

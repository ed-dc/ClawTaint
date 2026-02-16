/**
 * Logger utility for safe logging with fallback to console
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export interface Logger {
  debug: (message: string, data?: unknown) => void;
  info: (message: string, data?: unknown) => void;
  warn: (message: string, data?: unknown) => void;
  error: (message: string, data?: unknown) => void;
}

/**
 * OpenClaw plugin API shape (minimal for logger)
 */
interface PluginAPILike {
  log: (level: LogLevel, message: string, data?: unknown) => void;
}

interface PluginConfigLike {
  logLevel?: LogLevel;
}

/**
 * Creates a safe logger that uses api.log when available, falls back to console.
 */
export function createLogger(
  api: PluginAPILike | null,
  config: PluginConfigLike | null
): Logger {
  const configuredLevel = config?.logLevel || 'info';
  const minLevel = LOG_LEVELS[configuredLevel];

  function shouldLog(level: LogLevel): boolean {
    return LOG_LEVELS[level] >= minLevel;
  }

  function log(level: LogLevel, message: string, data?: unknown): void {
    if (!shouldLog(level)) return;

    const prefixedMessage = `[clawtaint] ${message}`;

    // Try API logging first
    if (api && typeof api.log === 'function') {
      try {
        api.log(level, prefixedMessage, data);
        return;
      } catch {
        // API logging failed, fall through to console
      }
    }

    // Fallback to console
    const consoleMapping: Record<LogLevel, typeof console.log> = {
      debug: console.log,
      info: console.info,
      warn: console.warn,
      error: console.error,
    };
    const consoleMethod = consoleMapping[level];
    if (data !== undefined) {
      consoleMethod(prefixedMessage, data);
    } else {
      consoleMethod(prefixedMessage);
    }
  }

  return {
    debug: (message, data) => log('debug', message, data),
    info: (message, data) => log('info', message, data),
    warn: (message, data) => log('warn', message, data),
    error: (message, data) => log('error', message, data),
  };
}

/**
 * Creates a no-op logger that discards all logs
 */
export function createNoOpLogger(): Logger {
  const noop = (): void => {};
  return { debug: noop, info: noop, warn: noop, error: noop };
}

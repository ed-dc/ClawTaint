/**
 * URL Trust Detector
 *
 * Checks whether URLs are trusted based on glob patterns.
 * Extracts domains from various tool input formats.
 */

import type { TrustedUrls } from '../config/schema.js';
import type { Logger } from '../utils/logger.js';

// =============================================================================
// TYPES
// =============================================================================

export interface UrlCheckResult {
  /** Whether a URL was found in the tool context */
  urlFound: boolean;
  /** The extracted URL */
  url?: string;
  /** The extracted domain */
  domain?: string;
  /** Whether the URL is trusted */
  trusted: boolean;
  /** The pattern that matched (if trusted) */
  matchedPattern?: string;
}

// =============================================================================
// DOMAIN EXTRACTION
// =============================================================================

/**
 * Extract the domain from a URL string.
 */
export function extractDomain(url: string): string | null {
  try {
    // Add protocol if missing
    let normalizedUrl = url;
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
      normalizedUrl = `https://${normalizedUrl}`;
    }
    const parsed = new URL(normalizedUrl);
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Extract a URL from a tool call context.
 * Checks various common field names used by different tools.
 */
export function extractUrlFromContext(toolInput: Record<string, unknown>): string | null {
  // Direct URL fields
  const urlFields = ['url', 'href', 'link', 'target', 'src', 'source', 'uri', 'endpoint'];
  for (const field of urlFields) {
    const value = toolInput[field];
    if (typeof value === 'string' && value.length > 0) {
      return value;
    }
  }

  // Check nested command string for URLs (e.g., "curl https://example.com")
  const commandFields = ['command', 'cmd', 'script', 'input'];
  for (const field of commandFields) {
    const value = toolInput[field];
    if (typeof value === 'string') {
      const urlMatch = value.match(/https?:\/\/[^\s"'`<>]+/);
      if (urlMatch) {
        return urlMatch[0];
      }
    }
  }

  return null;
}

// =============================================================================
// GLOB MATCHING
// =============================================================================

/**
 * Convert a glob pattern to a RegExp.
 *   *  → matches any characters except dots (single segment)
 *   ** → matches anything including dots (multi-segment)
 *   ?  → matches a single character
 */
export function globToRegex(pattern: string): RegExp {
  let regexStr = '';
  let i = 0;
  while (i < pattern.length) {
    const char = pattern[i];
    if (char === '*') {
      if (pattern[i + 1] === '*') {
        regexStr += '.*';
        i += 2;
        continue;
      }
      regexStr += '[^.]*';
    } else if (char === '?') {
      regexStr += '.';
    } else if ('.+^${}()|[]\\'.includes(char)) {
      regexStr += `\\${char}`;
    } else {
      regexStr += char;
    }
    i++;
  }
  return new RegExp(`^${regexStr}$`, 'i');
}

/**
 * Check if a domain matches a glob pattern.
 */
export function matchesGlobPattern(domain: string, pattern: string): boolean {
  try {
    const regex = globToRegex(pattern);
    return regex.test(domain);
  } catch {
    return false;
  }
}

// =============================================================================
// URL TRUST CHECKER
// =============================================================================

export interface UrlTrustChecker {
  /** Check if a URL from tool input is trusted */
  check(toolInput: Record<string, unknown>): UrlCheckResult;
  /** Check if a specific domain is trusted */
  isDomainTrusted(domain: string): boolean;
}

/**
 * Create a URL trust checker based on trusted URL patterns.
 */
export function createUrlTrustChecker(
  trustedUrls: TrustedUrls,
  logger?: Logger
): UrlTrustChecker {
  const log = logger;

  function isDomainTrusted(domain: string): boolean {
    for (const pattern of trustedUrls.patterns) {
      if (matchesGlobPattern(domain, pattern)) {
        return true;
      }
    }
    return false;
  }

  function check(toolInput: Record<string, unknown>): UrlCheckResult {
    const url = extractUrlFromContext(toolInput);

    if (!url) {
      return { urlFound: false, trusted: true }; // No URL = no penalty
    }

    const domain = extractDomain(url);
    if (!domain) {
      log?.warn(`Could not extract domain from URL: ${url}`);
      return { urlFound: true, url, trusted: false }; // Unparseable = untrusted
    }

    // Check against trusted patterns
    for (const pattern of trustedUrls.patterns) {
      if (matchesGlobPattern(domain, pattern)) {
        log?.debug(`Domain ${domain} matches trusted pattern: ${pattern}`);
        return {
          urlFound: true,
          url,
          domain,
          trusted: true,
          matchedPattern: pattern,
        };
      }
    }

    log?.info(`Domain ${domain} is NOT trusted`);
    return { urlFound: true, url, domain, trusted: false };
  }

  return { check, isDomainTrusted };
}

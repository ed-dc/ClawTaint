/**
 * Tests for URL Trust Detector
 */

import { describe, it, expect } from 'vitest';
import {
  extractDomain,
  extractUrlFromContext,
  globToRegex,
  matchesGlobPattern,
  createUrlTrustChecker,
} from './url-trust.js';

// =============================================================================
// extractDomain
// =============================================================================

describe('extractDomain', () => {
  it('should extract domain from full URL', () => {
    expect(extractDomain('https://github.com/user/repo')).toBe('github.com');
  });

  it('should extract domain from URL without protocol', () => {
    expect(extractDomain('stackoverflow.com/questions')).toBe('stackoverflow.com');
  });

  it('should extract subdomain', () => {
    expect(extractDomain('https://docs.python.org/3/library')).toBe('docs.python.org');
  });

  it('should return lowercase domain', () => {
    expect(extractDomain('https://GitHub.COM/user')).toBe('github.com');
  });

  it('should return null for invalid input', () => {
    expect(extractDomain('')).toBe(null);
  });

  it('should handle URL with port', () => {
    expect(extractDomain('http://localhost:3000')).toBe('localhost');
  });
});

// =============================================================================
// extractUrlFromContext
// =============================================================================

describe('extractUrlFromContext', () => {
  it('should extract from url field', () => {
    expect(extractUrlFromContext({ url: 'https://example.com' })).toBe('https://example.com');
  });

  it('should extract from href field', () => {
    expect(extractUrlFromContext({ href: 'https://example.com' })).toBe('https://example.com');
  });

  it('should extract URL from command string', () => {
    expect(extractUrlFromContext({ command: 'curl https://evil.com/data' })).toBe('https://evil.com/data');
  });

  it('should return null when no URL present', () => {
    expect(extractUrlFromContext({ name: 'test', value: 42 })).toBe(null);
  });

  it('should prefer direct URL fields over command extraction', () => {
    expect(extractUrlFromContext({
      url: 'https://direct.com',
      command: 'curl https://from-cmd.com',
    })).toBe('https://direct.com');
  });

  it('should extract from link field', () => {
    expect(extractUrlFromContext({ link: 'https://link.com/page' })).toBe('https://link.com/page');
  });
});

// =============================================================================
// globToRegex
// =============================================================================

describe('globToRegex', () => {
  it('should match wildcard single segment', () => {
    const regex = globToRegex('*.github.com');
    expect(regex.test('docs.github.com')).toBe(true);
    expect(regex.test('api.github.com')).toBe(true);
    expect(regex.test('github.com')).toBe(false); // * requires at least one char segment
  });

  it('should match double wildcard for multi-segment', () => {
    const regex = globToRegex('**.github.com');
    expect(regex.test('docs.github.com')).toBe(true);
    expect(regex.test('sub.docs.github.com')).toBe(true);
  });

  it('should match exact domain', () => {
    const regex = globToRegex('example.com');
    expect(regex.test('example.com')).toBe(true);
    expect(regex.test('notexample.com')).toBe(false);
  });

  it('should be case-insensitive', () => {
    const regex = globToRegex('*.GitHub.com');
    expect(regex.test('docs.github.com')).toBe(true);
  });
});

// =============================================================================
// matchesGlobPattern
// =============================================================================

describe('matchesGlobPattern', () => {
  it('should match domain against glob pattern', () => {
    expect(matchesGlobPattern('docs.github.com', '*.github.com')).toBe(true);
  });

  it('should not match non-matching domain', () => {
    expect(matchesGlobPattern('evil.com', '*.github.com')).toBe(false);
  });

  it('should match exact pattern', () => {
    expect(matchesGlobPattern('npmjs.com', 'npmjs.com')).toBe(true);
  });
});

// =============================================================================
// createUrlTrustChecker
// =============================================================================

describe('createUrlTrustChecker', () => {
  const checker = createUrlTrustChecker({
    patterns: ['*.github.com', '*.stackoverflow.com', 'npmjs.com'],
  });

  it('should mark trusted URL as trusted', () => {
    const result = checker.check({ url: 'https://docs.github.com/en/rest' });
    expect(result.urlFound).toBe(true);
    expect(result.trusted).toBe(true);
    expect(result.matchedPattern).toBe('*.github.com');
  });

  it('should mark untrusted URL as untrusted', () => {
    const result = checker.check({ url: 'https://suspicious-site.xyz/hack' });
    expect(result.urlFound).toBe(true);
    expect(result.trusted).toBe(false);
    expect(result.matchedPattern).toBeUndefined();
  });

  it('should return trusted when no URL found', () => {
    const result = checker.check({ name: 'test' });
    expect(result.urlFound).toBe(false);
    expect(result.trusted).toBe(true); // No URL = no penalty
  });

  it('should check domain trust directly', () => {
    expect(checker.isDomainTrusted('api.github.com')).toBe(true);
    expect(checker.isDomainTrusted('evil.com')).toBe(false);
  });

  it('should match exact domain pattern', () => {
    const result = checker.check({ url: 'https://npmjs.com/package/test' });
    expect(result.trusted).toBe(true);
  });

  it('should extract URL from command in tool input', () => {
    const result = checker.check({ command: 'curl https://evil.xyz/data' });
    expect(result.urlFound).toBe(true);
    expect(result.trusted).toBe(false);
  });
});

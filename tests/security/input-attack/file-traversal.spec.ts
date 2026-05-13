import { test, expect, request as playwrightRequest } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import { generateTraversalPayloads } from '../sec-objects/input-attack/path-traversal.logic';

/**
 * File Path Traversal Tests (OWASP API8:2023)
 * 
 * These tests verify that APIs properly validate file paths and prevent
 * directory traversal attacks that could allow unauthorized file access.
 * 
 * Security Risks Addressed:
 * 1. Directory traversal to access sensitive files
 * 2. Absolute path access to system files
 * 3. Null byte injection in filenames
 * 4. URL encoding bypass of path filters
 * 5. Double encoding attacks
 * 6. Windows vs Unix path confusion
 * 
 * Expected Behavior:
 * - Path traversal sequences rejected (../, ..\)
 * - Absolute paths blocked or sanitized
 * - File access restricted to allowed directories
 * - Proper path normalization and validation
 * - Consistent behavior across platforms
 */

/**
 * Test: Basic directory traversal protection
 * 
 * Purpose: Verifies that file access APIs reject basic directory
 * traversal attempts using ../ sequences.
 * 
 * Security Impact: Directory traversal can lead to:
 * - Reading sensitive system files (/etc/passwd, SAM)
 * - Accessing application configuration and secrets
 * - Reading other users' files
 * - Arbitrary file read leading to code execution
 * 
 * Test Strategy:
 * 1. Attempt various ../ traversal patterns
 * 2. Try both Unix (/) and Windows (\) separators
 * 3. Verify all attempts are blocked
 * 4. Check for proper error codes (400/403)
 */
test('File Traversal: basic directory traversal blocked', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportWarning(
      'File-traversal basic probe could not run because baseURL is not provided.',
      [
        'Set BASE_URL in CI before running input-attack security tests',
        'Ensure Playwright baseURL points to the deployed target environment',
        'Fail the pipeline earlier when baseURL is missing to avoid incomplete security coverage'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = [
    '/api/files/',
    '/api/documents/',
    '/api/download/',
    '/api/static/',
    '/files/',
    '/uploads/'
  ];
  
  const basicTraversal = generateTraversalPayloads().filter(p => 
    p.encoding === 'none' && (p.path.includes('../') || p.path.includes('..\\'))
  ).slice(0, 10);
  
  let endpointFound = false;
  let vulnerabilities: any[] = [];
  let blocked = 0;
  
  for (const endpoint of endpoints) {
    try {
      for (const payload of basicTraversal) {
        const res = await api.get(`${endpoint}${payload.path}`).catch(() => null);
        
        if (!res || res.status() === 404) continue;
        endpointFound = true;
        
        const status = res.status();
        const text = await res.text().catch(() => '');
        
        // A 200 here means the traversal attempt reached a real file path.
        if (status === 200) {
          vulnerabilities.push({
            endpoint,
            payload: payload.name,
            path: payload.path,
            risk: payload.risk,
            status,
            issue: 'Directory traversal succeeded - file access granted'
          });
        }
        
        // Crashes or 5xx responses suggest unsafe path handling.
        else if (status >= 500) {
          vulnerabilities.push({
            endpoint,
            payload: payload.name,
            path: payload.path,
            status,
            issue: 'Server crashed with traversal attempt'
          });
        }
        
        // Treat explicit client-side rejections as the safe outcome.
        else if ([400, 403].includes(status)) {
          blocked++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue to the next endpoint if this one does not respond.
    }
  }
  
  if (!endpointFound) {
    reporter.reportWarning(
      'File-traversal basic probe could not run because no file-access endpoints responded.',
      [
        'Expose/document at least one file retrieval endpoint in the target environment',
        'Ensure CI target includes representative file APIs for traversal testing',
        'Add route metadata so security tests can discover valid file endpoints'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }
  
  if (vulnerabilities.length > 0) {
    reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
      vulnerabilitiesFound: vulnerabilities.length,
      examples: vulnerabilities.slice(0, 3),
      blocked,
      issue: `Directory traversal vulnerabilities detected: ${vulnerabilities.length} attacks succeeded`
    }, [
      'Validate and sanitize all file paths before access',
      'Use allowlist of permitted filenames only',
      'Reject paths containing ../ or ..\\ sequences',
      'Resolve paths to absolute form and verify within allowed directory',
      'Use path.join() and path.normalize() then validate result',
      'Never construct file paths directly from user input',
      'Implement chroot or similar sandboxing',
      'Use database IDs instead of filenames in URLs'
    ]);
    expect(vulnerabilities.length).toBe(0);
  } else {
    reporter.reportPass(
      `Directory traversal attempts properly blocked (${blocked} attacks rejected)`,
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: Encoded traversal bypass attempts
 * 
 * Purpose: Verifies that URL-encoded, double-encoded, and Unicode-encoded
 * traversal attempts are also blocked.
 */
test('File Traversal: encoded traversal attempts blocked', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportWarning(
      'File-traversal encoded probe could not run because baseURL is not provided.',
      [
        'Set BASE_URL in CI before running input-attack security tests',
        'Ensure Playwright baseURL points to the deployed target environment',
        'Fail the pipeline earlier when baseURL is missing to avoid incomplete security coverage'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/files/', '/api/documents/', '/files/'];
  
  const encodedTraversal = generateTraversalPayloads().filter(p => 
    ['url', 'double', 'unicode'].includes(p.encoding)
  ).slice(0, 8);
  
  let endpointFound = false;
  let bypassSucceeded = 0;
  let crashes = 0;
  
  for (const endpoint of endpoints) {
    try {
      for (const payload of encodedTraversal) {
        // Don't double-encode - send as-is
        const res = await api.get(`${endpoint}${payload.path}`).catch(() => null);
        
        if (!res || res.status() === 404) continue;
        endpointFound = true;
        
        const status = res.status();
        
        if (status === 200) {
          bypassSucceeded++;
        } else if (status >= 500) {
          crashes++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportWarning(
      'File-traversal encoded probe could not run because no file endpoints responded.',
      [
        'Expose/document file retrieval endpoints for encoded-path testing',
        'Ensure CI target includes representative file APIs for traversal testing',
        'Add route metadata so security tests can discover valid file endpoints'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }
  
  if (bypassSucceeded > 0 || crashes > 0) {
    reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
      bypassSucceeded,
      crashes,
      issue: 'Encoded traversal attacks bypassed filters or crashed server'
    }, [
      'Decode URL encoding before path validation',
      'Handle double-encoding properly',
      'Normalize paths after all decoding',
      'Validate the final resolved path, not intermediate forms',
      'Reject paths with encoding after normalization'
    ]);
    expect(bypassSucceeded + crashes).toBe(0);
  } else {
    reporter.reportPass(
      'Encoded directory traversal attempts properly blocked',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: Absolute path access prevention
 * 
 * Purpose: Verifies that absolute file paths are blocked to prevent
 * direct access to system files.
 */
test('File Traversal: absolute paths rejected', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportWarning(
      'File-traversal absolute-path probe could not run because baseURL is not provided.',
      [
        'Set BASE_URL in CI before running input-attack security tests',
        'Ensure Playwright baseURL points to the deployed target environment',
        'Fail the pipeline earlier when baseURL is missing to avoid incomplete security coverage'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/files/', '/api/documents/'];
  
  const absolutePaths = generateTraversalPayloads().filter(p => 
    p.name.includes('absolute')
  ).slice(0, 8);
  
  let endpointFound = false;
  let allowedAbsolute = 0;
  
  for (const endpoint of endpoints) {
    try {
      for (const payload of absolutePaths) {
        const res = await api.get(`${endpoint}${encodeURIComponent(payload.path)}`).catch(() => null);
        
        if (!res || res.status() === 404) continue;
        endpointFound = true;
        
        if (res.status() === 200) {
          allowedAbsolute++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportWarning(
      'File-traversal absolute-path probe could not run because no file endpoints responded.',
      [
        'Expose/document file retrieval endpoints for absolute-path testing',
        'Ensure CI target includes representative file APIs for traversal testing',
        'Add route metadata so security tests can discover valid file endpoints'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }
  
  if (allowedAbsolute > 0) {
    reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
      allowedAbsolute,
      issue: 'Absolute file paths allowed - direct system file access possible'
    }, [
      'Reject absolute paths (starting with / or C:\\)',
      'Only accept relative filenames',
      'Use basename() to extract filename only',
      'Map user-provided IDs to server-side file paths',
      'Implement a file access whitelist'
    ]);
    expect(allowedAbsolute).toBe(0);
  } else {
    reporter.reportPass(
      'Absolute file paths properly rejected',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: Null byte injection prevention
 * 
 * Purpose: Verifies that null bytes in filenames don't truncate
 * paths and bypass extension checks.
 */
test('File Traversal: null byte injection prevented', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportWarning(
      'File-traversal null-byte probe could not run because baseURL is not provided.',
      [
        'Set BASE_URL in CI before running input-attack security tests',
        'Ensure Playwright baseURL points to the deployed target environment',
        'Fail the pipeline earlier when baseURL is missing to avoid incomplete security coverage'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/files/', '/api/documents/'];
  
  const nullBytePayloads = generateTraversalPayloads().filter(p => 
    p.encoding === 'null'
  );
  
  let endpointFound = false;
  let nullByteWorked = 0;
  let crashes = 0;
  
  for (const endpoint of endpoints) {
    try {
      for (const payload of nullBytePayloads) {
        const res = await api.get(`${endpoint}${payload.path}`).catch(() => null);
        
        if (!res || res.status() === 404) continue;
        endpointFound = true;
        
        const status = res.status();
        
        if (status === 200) {
          nullByteWorked++;
        } else if (status >= 500) {
          crashes++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportWarning(
      'File-traversal null-byte probe could not run because no file endpoints responded.',
      [
        'Expose/document file retrieval endpoints for null-byte testing',
        'Ensure CI target includes representative file APIs for traversal testing',
        'Add route metadata so security tests can discover valid file endpoints'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }
  
  if (nullByteWorked > 0 || crashes > 0) {
    reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
      nullByteWorked,
      crashes,
      issue: 'Null byte injection successful or caused crashes'
    }, [
      'Remove null bytes from filenames before processing',
      'Validate extension after null byte removal',
      'Use modern language APIs that handle null safely',
      'Avoid C-style string operations in path handling'
    ]);
    expect(nullByteWorked + crashes).toBe(0);
  } else {
    reporter.reportPass(
      'Null byte injection properly prevented',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: Sensitive file access detection
 * 
 * Purpose: Attempts to access common sensitive files to verify
 * that even if traversal works, sensitive files are protected.
 */
test('File Traversal: sensitive files protected', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportWarning(
      'File-traversal sensitive-file probe could not run because baseURL is not provided.',
      [
        'Set BASE_URL in CI before running input-attack security tests',
        'Ensure Playwright baseURL points to the deployed target environment',
        'Fail the pipeline earlier when baseURL is missing to avoid incomplete security coverage'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/files/', '/files/'];
  
  const sensitiveFiles = [
    '.env',
    '.git/config',
    '.ssh/id_rsa',
    '.aws/credentials',
    'config/database.yml',
    'package.json',
    'composer.json',
    '.htaccess'
  ];
  
  let endpointFound = false;
  let exposedFiles = 0;
  
  for (const endpoint of endpoints) {
    try {
      for (const file of sensitiveFiles) {
        const res = await api.get(`${endpoint}${file}`).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        if (res.status() === 200) {
          const text = await res.text().catch(() => '');
          // Check if actual file content returned (not error page)
          if (text.length > 0 && !text.includes('<!DOCTYPE') && !text.includes('<html')) {
            exposedFiles++;
          }
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportWarning(
      'File-traversal sensitive-file probe could not run because no file endpoints responded.',
      [
        'Expose/document file retrieval endpoints for sensitive-file checks',
        'Ensure CI target includes representative file APIs for traversal testing',
        'Add route metadata so security tests can discover valid file endpoints'
      ],
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
    return;
  }
  
  if (exposedFiles > 0) {
    reporter.reportVulnerability('API8_SECURITY_MISCONFIGURATION', {
      exposedFiles,
      issue: `${exposedFiles} sensitive application files accessible`
    }, [
      'Move sensitive files outside web root',
      'Use .htaccess or web.config to block access',
      'Implement file extension whitelist',
      'Never serve hidden files (starting with .)',
      'Use separate storage for user uploads vs application files'
    ]);
    expect(exposedFiles).toBe(0);
  } else {
    reporter.reportPass(
      'Sensitive application files properly protected',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

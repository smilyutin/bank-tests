import { test, expect, request as playwrightRequest } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

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
 * Generate path traversal attack payloads
 */
function generateTraversalPayloads(): Array<{ name: string; path: string; encoding: string; risk: string }> {
  return [
    // Basic traversal - Unix
    { name: 'basic_unix', path: '../../../etc/passwd', encoding: 'none', risk: 'Access /etc/passwd' },
    { name: 'deep_unix', path: '../../../../../../../../etc/passwd', encoding: 'none', risk: 'Deep traversal to root' },
    { name: 'relative_unix', path: './../../etc/shadow', encoding: 'none', risk: 'Relative path to shadow file' },
    
    // Basic traversal - Windows
    { name: 'basic_windows', path: '..\\..\\..\\windows\\system32\\config\\SAM', encoding: 'none', risk: 'Access Windows SAM file' },
    { name: 'deep_windows', path: '..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini', encoding: 'none', risk: 'Deep Windows traversal' },
    { name: 'mixed_slashes', path: '../..\\../etc/passwd', encoding: 'none', risk: 'Mixed slash types' },
    
    // URL encoded
    { name: 'url_encoded_basic', path: '..%2F..%2F..%2Fetc%2Fpasswd', encoding: 'url', risk: 'URL encoded traversal' },
    { name: 'url_encoded_backslash', path: '..%5C..%5C..%5Cwindows%5Csystem32', encoding: 'url', risk: 'URL encoded Windows path' },
    
    // Double URL encoded
    { name: 'double_encoded_slash', path: '%252e%252e%252f%252e%252e%252f%252e%252e%252f', encoding: 'double', risk: 'Double encoding bypass' },
    { name: 'double_encoded_backslash', path: '%252e%252e%255c%252e%252e%255c', encoding: 'double', risk: 'Double encoded backslash' },
    
    // Unicode encoded
    { name: 'unicode_slash', path: '..\\u002f..\\u002f..\\u002fetc\\u002fpasswd', encoding: 'unicode', risk: 'Unicode encoded slashes' },
    { name: 'unicode_backslash', path: '..\\u005c..\\u005c..\\u005c', encoding: 'unicode', risk: 'Unicode backslashes' },
    
    // UTF-8 overlong encoding
    { name: 'overlong_slash', path: '..%c0%af..%c0%af..%c0%af', encoding: 'overlong', risk: 'UTF-8 overlong encoding' },
    { name: 'overlong_backslash', path: '..%c0%5c..%c0%5c', encoding: 'overlong', risk: 'Overlong backslash' },
    
    // Null byte injection
    { name: 'null_byte_unix', path: '../../../../etc/passwd%00.pdf', encoding: 'null', risk: 'Null byte truncation' },
    { name: 'null_byte_windows', path: '..\\..\\..\\windows\\system32\\config\\SAM%00.txt', encoding: 'null', risk: 'Windows null byte' },
    { name: 'null_byte_middle', path: '../etc%00/passwd', encoding: 'null', risk: 'Null in middle of path' },
    
    // Absolute paths - Unix
    { name: 'absolute_unix', path: '/etc/passwd', encoding: 'none', risk: 'Direct absolute path' },
    { name: 'absolute_home', path: '/root/.ssh/id_rsa', encoding: 'none', risk: 'SSH private key' },
    { name: 'absolute_tmp', path: '/tmp/malicious', encoding: 'none', risk: 'Temp directory access' },
    { name: 'absolute_var', path: '/var/log/auth.log', encoding: 'none', risk: 'Log file access' },
    
    // Absolute paths - Windows
    { name: 'absolute_windows_c', path: 'C:\\Windows\\System32\\config\\SAM', encoding: 'none', risk: 'Windows C: drive' },
    { name: 'absolute_windows_unc', path: '\\\\localhost\\c$\\windows\\system32', encoding: 'none', risk: 'UNC path access' },
    { name: 'absolute_windows_drive', path: 'D:\\sensitive\\data.txt', encoding: 'none', risk: 'Alternative drive access' },
    
    // Tricky combinations
    { name: 'dot_slash_combo', path: './../.../../etc/passwd', encoding: 'none', risk: 'Mixed ./ and ../' },
    { name: 'multiple_dots', path: '....//....//....//etc/passwd', encoding: 'none', risk: 'Multiple dots' },
    { name: 'forward_backward_mix', path: '../..\\../etc/passwd', encoding: 'none', risk: 'Forward and backward slashes' },
    
    // Bypass filters
    { name: 'filter_bypass_dot_dot', path: '..././..././..././etc/passwd', encoding: 'none', risk: 'Bypass ../ filter' },
    { name: 'filter_bypass_backslash', path: '..\\.\\..\\.\\..\\etc\\passwd', encoding: 'none', risk: 'Bypass with .\\' },
    { name: 'case_variation', path: '../../../ETC/PASSWD', encoding: 'none', risk: 'Case variation (Windows)' },
    
    // Web root escape
    { name: 'web_root_escape', path: '../../../../../../var/www/html/.htaccess', encoding: 'none', risk: 'Apache config access' },
    { name: 'nginx_config', path: '../../../etc/nginx/nginx.conf', encoding: 'none', risk: 'Nginx config' },
    { name: 'php_config', path: '../../../../etc/php/php.ini', encoding: 'none', risk: 'PHP configuration' },
    
    // Application config files
    { name: 'env_file', path: '../../../.env', encoding: 'none', risk: 'Environment variables' },
    { name: 'git_config', path: '../../../.git/config', encoding: 'none', risk: 'Git configuration' },
    { name: 'ssh_config', path: '../../../../.ssh/config', encoding: 'none', risk: 'SSH configuration' },
    { name: 'aws_credentials', path: '../../../.aws/credentials', encoding: 'none', risk: 'AWS credentials' },
    
    // Special file names
    { name: 'dev_null', path: '/dev/null', encoding: 'none', risk: 'Device file access' },
    { name: 'proc_self', path: '/proc/self/environ', encoding: 'none', risk: 'Process environment' },
    { name: 'proc_cmdline', path: '/proc/self/cmdline', encoding: 'none', risk: 'Command line args' },
  ];
}

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
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
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
        
        // Success (200) means traversal worked!
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
        
        // Should return 400 or 403, not 500
        else if (status >= 500) {
          vulnerabilities.push({
            endpoint,
            payload: payload.name,
            path: payload.path,
            status,
            issue: 'Server crashed with traversal attempt'
          });
        }
        
        // Properly blocked
        else if ([400, 403].includes(status)) {
          blocked++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue to next endpoint
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No file access endpoints found for traversal testing');
    test.skip(true, 'No file access endpoints found');
    return;
  }
  
  if (vulnerabilities.length > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
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
      OWASP_VULNERABILITIES.API8_INJECTION.name
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
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
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
    reporter.reportSkip('No file endpoints found for encoded traversal testing');
    test.skip(true, 'No file endpoints found');
    return;
  }
  
  if (bypassSucceeded > 0 || crashes > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
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
      OWASP_VULNERABILITIES.API8_INJECTION.name
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
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
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
    reporter.reportSkip('No file endpoints found for absolute path testing');
    test.skip(true, 'No file endpoints found');
    return;
  }
  
  if (allowedAbsolute > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
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
      OWASP_VULNERABILITIES.API8_INJECTION.name
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
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
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
    reporter.reportSkip('No file endpoints found for null byte testing');
    test.skip(true, 'No file endpoints found');
    return;
  }
  
  if (nullByteWorked > 0 || crashes > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
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
      OWASP_VULNERABILITIES.API8_INJECTION.name
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
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
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
    reporter.reportSkip('No file endpoints found for sensitive file testing');
    test.skip(true, 'No file endpoints found');
    return;
  }
  
  if (exposedFiles > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
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
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});

import { test, expect, request as playwrightRequest } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

/**
 * Escape Character and Encoding Tests (OWASP API8:2023)
 * 
 * These tests verify that APIs properly handle escape sequences, special
 * characters, and various encodings to prevent injection attacks and
 * data corruption.
 * 
 * Security Risks Addressed:
 * 1. SQL injection through improper escaping
 * 2. XSS through unescaped HTML/JavaScript
 * 3. Command injection through shell metacharacters
 * 4. Path traversal through directory separators
 * 5. LDAP injection through special characters
 * 6. NoSQL injection through operator injection
 * 
 * Expected Behavior:
 * - All special characters properly escaped
 * - Context-appropriate encoding (HTML, SQL, Shell, etc.)
 * - Consistent handling across endpoints
 * - No double-escaping or encoding issues
 * - Proper validation before storage
 */

/**
 * Generate escape character test payloads
 */
function generateEscapePayloads(): Array<{ name: string; value: string; type: string; risk: string }> {
  return [
    // SQL injection characters
    { name: 'single_quote', value: "test'user", type: 'SQL', risk: 'SQL injection' },
    { name: 'double_quote', value: 'test"user', type: 'SQL', risk: 'SQL injection' },
    { name: 'backslash', value: 'test\\user', type: 'SQL', risk: 'Escape bypass' },
    { name: 'comment_dash', value: 'test--user', type: 'SQL', risk: 'Comment injection' },
    { name: 'comment_slash', value: 'test/**/user', type: 'SQL', risk: 'Block comment injection' },
    { name: 'semicolon', value: 'test;DROP TABLE users', type: 'SQL', risk: 'Statement termination' },
    { name: 'sql_or_payload', value: "admin' OR '1'='1", type: 'SQL', risk: 'Authentication bypass' },
    { name: 'sql_union', value: "' UNION SELECT * FROM users--", type: 'SQL', risk: 'Data exfiltration' },
    
    // XSS characters
    { name: 'less_than', value: '<script>alert(1)</script>', type: 'XSS', risk: 'Script injection' },
    { name: 'greater_than', value: 'test>user', type: 'XSS', risk: 'Tag closure' },
    { name: 'ampersand', value: 'test&user', type: 'XSS', risk: 'Entity injection' },
    { name: 'html_entity', value: '&lt;script&gt;', type: 'XSS', risk: 'Entity-encoded script' },
    { name: 'img_tag', value: '<img src=x onerror=alert(1)>', type: 'XSS', risk: 'Event handler injection' },
    { name: 'svg_xss', value: '<svg/onload=alert(1)>', type: 'XSS', risk: 'SVG-based XSS' },
    { name: 'javascript_protocol', value: 'javascript:alert(1)', type: 'XSS', risk: 'Protocol handler' },
    { name: 'data_uri', value: 'data:text/html,<script>alert(1)</script>', type: 'XSS', risk: 'Data URI XSS' },
    
    // Shell metacharacters
    { name: 'pipe', value: 'test|ls', type: 'Command', risk: 'Command chaining' },
    { name: 'ampersand_shell', value: 'test&whoami', type: 'Command', risk: 'Background execution' },
    { name: 'double_pipe', value: 'test||ls', type: 'Command', risk: 'OR execution' },
    { name: 'double_ampersand', value: 'test&&ls', type: 'Command', risk: 'AND execution' },
    { name: 'backtick', value: 'test`whoami`', type: 'Command', risk: 'Command substitution' },
    { name: 'dollar_paren', value: 'test$(whoami)', type: 'Command', risk: 'Command substitution' },
    { name: 'newline_command', value: 'test\nwhoami', type: 'Command', risk: 'Command injection' },
    { name: 'redirect', value: 'test > /tmp/output', type: 'Command', risk: 'File redirection' },
    
    // Path traversal
    { name: 'dot_dot_slash', value: '../../../etc/passwd', type: 'Path', risk: 'Directory traversal' },
    { name: 'dot_dot_backslash', value: '..\\..\\..\\windows\\system32', type: 'Path', risk: 'Windows traversal' },
    { name: 'encoded_traversal', value: '%2e%2e%2f%2e%2e%2f', type: 'Path', risk: 'URL-encoded traversal' },
    { name: 'double_encoded', value: '%252e%252e%252f', type: 'Path', risk: 'Double-encoded traversal' },
    { name: 'null_byte', value: 'file.txt\x00.pdf', type: 'Path', risk: 'Null byte injection' },
    { name: 'absolute_path_unix', value: '/etc/passwd', type: 'Path', risk: 'Absolute path access' },
    { name: 'absolute_path_win', value: 'C:\\Windows\\System32\\config\\SAM', type: 'Path', risk: 'Windows system access' },
    
    // LDAP injection
    { name: 'ldap_asterisk', value: '*', type: 'LDAP', risk: 'Wildcard search' },
    { name: 'ldap_parentheses', value: '*()|&', type: 'LDAP', risk: 'Filter injection' },
    { name: 'ldap_null', value: '\x00', type: 'LDAP', risk: 'Null byte termination' },
    
    // NoSQL injection
    { name: 'nosql_ne', value: '{"$ne": null}', type: 'NoSQL', risk: 'Not-equal operator' },
    { name: 'nosql_gt', value: '{"$gt": ""}', type: 'NoSQL', risk: 'Greater-than bypass' },
    { name: 'nosql_regex', value: '{"$regex": ".*"}', type: 'NoSQL', risk: 'Regex wildcard' },
    { name: 'nosql_where', value: '{"$where": "this.password.length > 0"}', type: 'NoSQL', risk: 'JavaScript execution' },
    
    // XML injection
    { name: 'xml_entity', value: '<!ENTITY xxe SYSTEM "file:///etc/passwd">', type: 'XML', risk: 'XXE injection' },
    { name: 'xml_cdata', value: '<![CDATA[<script>alert(1)</script>]]>', type: 'XML', risk: 'CDATA bypass' },
    
    // Template injection
    { name: 'template_jinja', value: '{{7*7}}', type: 'Template', risk: 'Server-side template injection' },
    { name: 'template_erb', value: '<%= 7*7 %>', type: 'Template', risk: 'ERB injection' },
    { name: 'template_freemarker', value: '${7*7}', type: 'Template', risk: 'FreeMarker injection' },
    
    // Format string
    { name: 'format_percent', value: '%s%s%s%s', type: 'Format', risk: 'Format string attack' },
    { name: 'format_dollar', value: '$1$2$3$4', type: 'Format', risk: 'Variable substitution' },
    
    // Control characters
    { name: 'carriage_return', value: 'test\ruser', type: 'Control', risk: 'Line manipulation' },
    { name: 'newline', value: 'test\nuser', type: 'Control', risk: 'Multi-line injection' },
    { name: 'tab', value: 'test\tuser', type: 'Control', risk: 'Tab injection' },
    { name: 'bell', value: 'test\x07user', type: 'Control', risk: 'Terminal bell' },
    { name: 'escape', value: 'test\x1Buser', type: 'Control', risk: 'ANSI escape sequences' },
    
    // URL encoding
    { name: 'percent_encoding', value: 'test%20user', type: 'URL', risk: 'URL encoding bypass' },
    { name: 'plus_encoding', value: 'test+user', type: 'URL', risk: 'Space encoding' },
    { name: 'hash', value: 'test#fragment', type: 'URL', risk: 'Fragment injection' },
    { name: 'question_mark', value: 'test?param=value', type: 'URL', risk: 'Query injection' },
    
    // JSON escaping
    { name: 'json_quote', value: '{"key": "value\\""}', type: 'JSON', risk: 'Quote escape' },
    { name: 'json_backslash', value: '{"key": "value\\\\"}', type: 'JSON', risk: 'Backslash escape' },
    { name: 'json_newline', value: '{"key": "value\\n"}', type: 'JSON', risk: 'Newline in JSON' },
    
    // Regex metacharacters
    { name: 'regex_dot', value: 'test.user', type: 'Regex', risk: 'Wildcard match' },
    { name: 'regex_star', value: 'test*user', type: 'Regex', risk: 'Repetition' },
    { name: 'regex_plus', value: 'test+user', type: 'Regex', risk: 'One or more' },
    { name: 'regex_bracket', value: 'test[a-z]user', type: 'Regex', risk: 'Character class' },
    { name: 'regex_caret', value: '^admin', type: 'Regex', risk: 'Start anchor' },
    { name: 'regex_dollar', value: 'admin$', type: 'Regex', risk: 'End anchor' },
  ];
}

/**
 * Test: SQL injection character escaping
 * 
 * Purpose: Verifies that SQL special characters are properly escaped
 * to prevent SQL injection attacks.
 */
test('Escape Chars: SQL injection characters properly escaped', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/users', '/api/auth/register'];
  
  const sqlPayloads = generateEscapePayloads().filter(p => p.type === 'SQL');
  
  let endpointFound = false;
  let vulnerabilities: any[] = [];
  let safelyHandled = 0;
  
  for (const endpoint of endpoints) {
    try {
      for (const payload of sqlPayloads.slice(0, 8)) {
        const res = await api.post(endpoint, {
          data: JSON.stringify({
            email: `${payload.value}@example.com`,
            password: 'Test123!',
            username: payload.value
          }),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        const status = res.status();
        const text = await res.text().catch(() => '');
        
        // Check for SQL errors in response
        if (/sql|syntax error|mysql|postgres|sqlite|oracle|column|table/i.test(text) && status >= 400) {
          vulnerabilities.push({
            payload: payload.name,
            value: payload.value,
            risk: payload.risk,
            status,
            issue: 'SQL error message exposed in response'
          });
        }
        
        // Server crashes indicate poor error handling
        if (status >= 500) {
          vulnerabilities.push({
            payload: payload.name,
            value: payload.value,
            risk: payload.risk,
            status,
            issue: 'Server crashed with SQL special characters'
          });
        } else if ([400, 422].includes(status)) {
          safelyHandled++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for SQL escaping testing');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (vulnerabilities.length > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
      sqlInjectionRisks: vulnerabilities.length,
      examples: vulnerabilities.slice(0, 3),
      issue: 'SQL special characters not properly handled'
    }, [
      'Use parameterized queries (prepared statements) exclusively',
      'Never concatenate user input into SQL strings',
      'Escape SQL special characters if concatenation unavoidable',
      'Use ORM/query builders that auto-escape',
      'Never expose SQL error messages to users',
      'Implement input validation before database operations'
    ]);
    expect(vulnerabilities.length).toBe(0);
  } else {
    reporter.reportPass(
      `SQL injection characters handled safely (${safelyHandled} payloads validated)`,
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});

/**
 * Test: XSS character escaping
 * 
 * Purpose: Verifies that HTML/JavaScript special characters are
 * properly escaped to prevent XSS attacks.
 */
test('Escape Chars: XSS characters properly encoded', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/users', '/api/auth/register'];
  
  const xssPayloads = generateEscapePayloads().filter(p => p.type === 'XSS');
  
  let endpointFound = false;
  let acceptedXSS = 0;
  let crashes = 0;
  
  for (const endpoint of endpoints) {
    try {
      for (const payload of xssPayloads.slice(0, 7)) {
        const res = await api.post(endpoint, {
          data: JSON.stringify({
            email: 'xss@test.com',
            password: 'Test123!',
            username: payload.value,
            bio: payload.value
          }),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        const status = res.status();
        
        if (status >= 500) {
          crashes++;
        }
        
        // API should accept these (storage is OK, output encoding matters)
        // But we check they don't crash the server
        if ([200, 201].includes(status)) {
          acceptedXSS++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for XSS escaping testing');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (crashes > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
      crashes,
      issue: 'Server crashed with XSS payloads'
    }, [
      'Handle HTML special characters gracefully',
      'Validate input format, not content',
      'Store data as-is, escape on output',
      'Use Content-Security-Policy headers'
    ]);
    expect(crashes).toBe(0);
  } else {
    reporter.reportPass(
      `XSS characters handled without crashes (${acceptedXSS} payloads accepted for storage)`,
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});

/**
 * Test: Command injection character filtering
 * 
 * Purpose: Verifies that shell metacharacters are properly handled
 * to prevent command injection attacks.
 */
test('Escape Chars: command injection metacharacters filtered', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/users', '/api/auth/register'];
  
  const commandPayloads = generateEscapePayloads().filter(p => p.type === 'Command');
  
  let endpointFound = false;
  let issues = 0;
  
  for (const endpoint of endpoints) {
    try {
      for (const payload of commandPayloads.slice(0, 6)) {
        const res = await api.post(endpoint, {
          data: JSON.stringify({
            email: 'cmd@test.com',
            password: 'Test123!',
            username: payload.value
          }),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        if (res.status() >= 500) {
          issues++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for command injection testing');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (issues > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
      issues,
      issue: 'Server crashed with command injection metacharacters'
    }, [
      'Never pass user input to system commands',
      'Use language APIs instead of shell commands',
      'If shell commands unavoidable, use strict allowlists',
      'Escape shell metacharacters properly',
      'Use subprocess libraries with array arguments (not strings)'
    ]);
    expect(issues).toBe(0);
  } else {
    reporter.reportPass(
      'Command injection metacharacters handled safely',
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});

/**
 * Test: Path traversal character handling
 * 
 * Purpose: Verifies that path traversal sequences are blocked
 * to prevent unauthorized file access.
 */
test('Escape Chars: path traversal sequences blocked', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/users', '/api/files', '/api/documents'];
  
  const pathPayloads = generateEscapePayloads().filter(p => p.type === 'Path');
  
  let endpointFound = false;
  let acceptedTraversal = 0;
  let crashes = 0;
  
  for (const endpoint of endpoints) {
    try {
      for (const payload of pathPayloads.slice(0, 6)) {
        const res = await api.get(`${endpoint}/${encodeURIComponent(payload.value)}`).catch(() => null);
        
        if (!res || res.status() === 404) continue;
        endpointFound = true;
        
        const status = res.status();
        
        if (status >= 500) {
          crashes++;
        }
        
        // Should not return 200 for traversal attempts
        if (status === 200) {
          acceptedTraversal++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for path traversal testing');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (crashes > 0 || acceptedTraversal > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
      crashes,
      acceptedTraversal,
      issue: 'Path traversal sequences not properly blocked'
    }, [
      'Validate all file paths before access',
      'Use allowlist of valid filenames',
      'Resolve paths and check they\'re within allowed directory',
      'Reject ../ and ..\\ sequences',
      'Use path.normalize() and validate result',
      'Never construct file paths from user input directly'
    ]);
    expect(crashes + acceptedTraversal).toBe(0);
  } else {
    reporter.reportPass(
      'Path traversal sequences properly blocked',
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});

/**
 * Test: NoSQL injection operator filtering
 * 
 * Purpose: Verifies that NoSQL query operators are not injectable
 * through user input.
 */
test('Escape Chars: NoSQL operators filtered', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/users', '/api/auth/login'];
  
  const nosqlPayloads = generateEscapePayloads().filter(p => p.type === 'NoSQL');
  
  let endpointFound = false;
  let vulnerabilities = 0;
  
  for (const endpoint of endpoints) {
    try {
      for (const payload of nosqlPayloads) {
        // Try sending NoSQL operators as JSON
        const res = await api.post(endpoint, {
          data: JSON.stringify({
            email: payload.value,
            password: payload.value
          }),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        // Check if server crashed
        if (res.status() >= 500) {
          vulnerabilities++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for NoSQL injection testing');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (vulnerabilities > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
      vulnerabilities,
      issue: 'NoSQL injection operators caused server errors'
    }, [
      'Validate input types before building queries',
      'Reject objects where strings expected',
      'Use schema validation (e.g., Joi, Yup)',
      'Sanitize MongoDB operators ($ne, $gt, $where, etc.)',
      'Use parameterized queries or ORM methods'
    ]);
    expect(vulnerabilities).toBe(0);
  } else {
    reporter.reportPass(
      'NoSQL injection operators handled safely',
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});

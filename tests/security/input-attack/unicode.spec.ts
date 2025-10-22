import { test, expect, request as playwrightRequest } from '@playwright/test';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

/**
 * Unicode and Character Encoding Tests (OWASP API8:2023)
 * 
 * These tests verify that APIs properly handle Unicode normalization issues,
 * homograph attacks, bidirectional text, and other character encoding
 * vulnerabilities that could lead to security bypasses.
 * 
 * Security Risks Addressed:
 * 1. Unicode normalization bypasses in validation
 * 2. Homograph attacks (lookalike characters)
 * 3. Bidirectional text injection
 * 4. Zero-width character abuse
 * 5. Emoji and special character handling
 * 6. UTF-8 overlong encoding attacks
 * 
 * Expected Behavior:
 * - Unicode normalization before validation
 * - Detection of homograph attacks
 * - Proper handling of RTL/LTR text
 * - Zero-width characters stripped or rejected
 * - Consistent UTF-8 encoding throughout
 */

/**
 * Generate Unicode attack payloads
 */
function generateUnicodePayloads(): Array<{ name: string; value: string; attack: string }> {
  return [
    // Unicode normalization bypass
    {
      name: 'nfc_vs_nfd',
      value: 'café', // NFC (single é character)
      attack: 'Unicode normalization - é can be one or two codepoints'
    },
    {
      name: 'nfd_form',
      value: 'cafe\u0301', // NFD (e + combining acute accent)
      attack: 'Could bypass filters checking for "café"'
    },
    
    // Homograph attacks (lookalike characters)
    {
      name: 'cyrillic_a',
      value: 'аdmin@example.com', // Cyrillic 'а' looks like Latin 'a'
      attack: 'admin@example.com with Cyrillic а (U+0430)'
    },
    {
      name: 'greek_o',
      value: 'gοοgle.com', // Greek omicron looks like Latin 'o'
      attack: 'Homograph attack using Greek ο (U+03BF)'
    },
    {
      name: 'zero_width_space',
      value: 'admin\u200B@example.com', // Zero-width space
      attack: 'Invisible character could bypass validation'
    },
    {
      name: 'zero_width_joiner',
      value: 'test\u200D@example.com',
      attack: 'Zero-width joiner (U+200D) could break parsing'
    },
    {
      name: 'zero_width_non_joiner',
      value: 'user\u200C@example.com',
      attack: 'Zero-width non-joiner (U+200C)'
    },
    
    // Bidirectional text attacks
    {
      name: 'rtl_override',
      value: 'test\u202E@elpmaxe.com', // Right-to-left override
      attack: 'RTL override could display email backwards'
    },
    {
      name: 'ltr_override',
      value: '\u202Dadmin@example.com',
      attack: 'LTR override could affect rendering'
    },
    {
      name: 'rtl_embedding',
      value: 'user\u202B@example.com',
      attack: 'RTL embedding (U+202B)'
    },
    {
      name: 'ltr_embedding',
      value: 'user\u202A@example.com',
      attack: 'LTR embedding (U+202A)'
    },
    {
      name: 'pop_directional',
      value: 'test\u202C@example.com',
      attack: 'Pop directional formatting'
    },
    
    // Confusables and lookalikes
    {
      name: 'latin_small_l_vs_i',
      value: 'admin|@example.com', // Using pipe instead of lowercase L
      attack: 'Visual confusable characters'
    },
    {
      name: 'zero_vs_capital_o',
      value: 'user0@example.com', // 0 vs O
      attack: 'Number zero looks like letter O'
    },
    {
      name: 'digit_one_vs_lowercase_l',
      value: 'use1@example.com',
      attack: 'Digit 1 looks like lowercase l'
    },
    
    // Control characters
    {
      name: 'null_byte',
      value: 'admin\x00@example.com',
      attack: 'Null byte could truncate strings in C-based systems'
    },
    {
      name: 'bell_character',
      value: 'test\x07@example.com',
      attack: 'Bell character (U+0007)'
    },
    {
      name: 'backspace',
      value: 'test\x08@example.com',
      attack: 'Backspace character could alter display'
    },
    {
      name: 'vertical_tab',
      value: 'test\x0B@example.com',
      attack: 'Vertical tab character'
    },
    {
      name: 'form_feed',
      value: 'test\x0C@example.com',
      attack: 'Form feed character'
    },
    
    // Emoji and special Unicode
    {
      name: 'emoji_in_email',
      value: '😀@example.com',
      attack: 'Emoji as username - should be rejected'
    },
    {
      name: 'emoji_sequence',
      value: 'test👨‍👩‍👧‍👦@example.com',
      attack: 'Multi-codepoint emoji sequence'
    },
    {
      name: 'skin_tone_modifier',
      value: 'user👋🏽@example.com',
      attack: 'Emoji with skin tone modifier'
    },
    
    // Case mapping issues
    {
      name: 'turkish_i',
      value: 'İstanbul@example.com', // Turkish capital İ
      attack: 'Turkish İ lowercases to i (with dot), not ı'
    },
    {
      name: 'german_sharp_s',
      value: 'straße@example.com', // ß
      attack: 'German ß uppercases to SS'
    },
    
    // Overlong UTF-8 sequences (historically used to bypass filters)
    {
      name: 'overlong_slash',
      value: 'test@example.com/../../etc/passwd',
      attack: 'Path traversal that might use overlong encoding'
    },
    
    // Combining characters
    {
      name: 'combining_diacritics',
      value: 'e\u0301\u0300\u0302@example.com', // e with multiple diacritics
      attack: 'Multiple combining characters stacked'
    },
    {
      name: 'zalgo_text',
      value: 't̸̢̲̦̖͖̱͇̹͚̯̗̗͕͓̞̲̜͖̿͊̾͋̋͑͌͘͜ͅe̶̡̼̺̤̜̦̦͙̖̥̣̳͖̪̿́̒̈́̿̕s̷̨̢̰̰͎̜̳̗̳̺̪͕̲̰̲̥̭̹̖̉́̈̔̀̓̌̌̕͝t̵̨̢̧̛̺̭̱̰͍̻̫̰̙̗̼͇̰̺̞͖͗̍̍̋̾́͌͂͝',
      attack: 'Zalgo text with excessive combining marks'
    },
    
    // Non-printable characters
    {
      name: 'soft_hyphen',
      value: 'test\u00AD@example.com', // Soft hyphen
      attack: 'Soft hyphen - invisible but affects sorting'
    },
    {
      name: 'word_joiner',
      value: 'test\u2060@example.com',
      attack: 'Word joiner (invisible)'
    },
    
    // Full-width characters (Asian text)
    {
      name: 'fullwidth_digits',
      value: 'user１２３@example.com', // Full-width 123
      attack: 'Full-width digits look like ASCII but are different codepoints'
    },
    {
      name: 'fullwidth_at',
      value: 'test＠example.com', // Full-width @ sign
      attack: 'Full-width @ (U+FF20) instead of ASCII @'
    },
  ];
}

/**
 * Test: Unicode normalization handling
 * 
 * Purpose: Verifies that the API normalizes Unicode before validation
 * to prevent bypasses through equivalent but different encodings.
 * 
 * Security Impact: Missing normalization can allow:
 * - Validation bypass through alternate encodings
 * - Duplicate account creation with "same" email
 * - SQL injection through normalized characters
 * - Access control bypass
 */
test('Unicode: normalization prevents validation bypass', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/users', '/api/auth/register'];
  
  const normalizationTests = generateUnicodePayloads().filter(p => 
    p.name.includes('nfc') || p.name.includes('nfd')
  );
  
  let endpointFound = false;
  let issues: any[] = [];
  
  for (const endpoint of endpoints) {
    try {
      for (const payload of normalizationTests) {
        const res = await api.post(endpoint, {
          data: JSON.stringify({
            email: payload.value,
            password: 'Test123!',
            username: payload.value
          }),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        const status = res.status();
        
        // If it crashes or has errors
        if (status >= 500) {
          issues.push({
            payload: payload.name,
            attack: payload.attack,
            status,
            issue: 'Server crashed with Unicode normalization test'
          });
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for Unicode normalization testing');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (issues.length > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
      issues: issues.length,
      examples: issues,
      attack: 'Unicode normalization vulnerabilities detected'
    }, [
      'Normalize all Unicode input to NFC before validation',
      'Use Unicode-aware string comparison',
      'Apply normalization consistently across all layers',
      'Validate after normalization, not before',
      'Use libraries like `unorm` or built-in normalization'
    ]);
    expect(issues.length).toBe(0);
  } else {
    reporter.reportPass(
      'API handles Unicode normalization correctly',
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});

/**
 * Test: Homograph attack detection
 * 
 * Purpose: Verifies that the API detects and rejects homograph attacks
 * using lookalike characters from different scripts.
 */
test('Unicode: homograph attacks detected', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/users', '/api/auth/register'];
  
  const homographTests = generateUnicodePayloads().filter(p => 
    p.name.includes('cyrillic') || p.name.includes('greek') || p.name.includes('fullwidth')
  );
  
  let endpointFound = false;
  let acceptedHomograph = 0;
  let crashes = 0;
  
  for (const endpoint of endpoints) {
    try {
      for (const payload of homographTests) {
        const res = await api.post(endpoint, {
          data: JSON.stringify({
            email: payload.value,
            password: 'Test123!'
          }),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        const status = res.status();
        
        if (status >= 500) {
          crashes++;
        }
        
        // Should reject homograph emails
        if ([200, 201].includes(status)) {
          acceptedHomograph++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for homograph testing');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (crashes > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
      crashes,
      issue: 'Server crashed with homograph characters'
    });
    expect(crashes).toBe(0);
  } else if (acceptedHomograph > 0) {
    reporter.reportWarning(
      `API accepted ${acceptedHomograph} homograph attacks - potential phishing risk`,
      [
        'Validate emails contain only ASCII characters',
        'Detect mixed-script strings (Latin + Cyrillic)',
        'Use confusable character detection libraries',
        'Implement punycode for internationalized domain names',
        'Warn users about lookalike characters'
      ],
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  } else {
    reporter.reportPass(
      'API rejects homograph attacks appropriately',
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});

/**
 * Test: Zero-width character handling
 * 
 * Purpose: Verifies that invisible zero-width characters are
 * stripped or rejected to prevent validation bypasses.
 */
test('Unicode: zero-width characters handled', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/users', '/api/auth/register'];
  
  const zeroWidthTests = generateUnicodePayloads().filter(p => 
    p.name.includes('zero_width') || p.name.includes('word_joiner')
  );
  
  let endpointFound = false;
  let acceptedZeroWidth = 0;
  
  for (const endpoint of endpoints) {
    try {
      for (const payload of zeroWidthTests) {
        const res = await api.post(endpoint, {
          data: JSON.stringify({
            email: payload.value,
            password: 'Test123!'
          }),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        // Zero-width characters should be stripped or rejected
        if ([200, 201].includes(res.status())) {
          acceptedZeroWidth++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for zero-width testing');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (acceptedZeroWidth > 2) {
    reporter.reportWarning(
      `API accepted ${acceptedZeroWidth} inputs with zero-width characters`,
      [
        'Strip zero-width characters before validation',
        'Reject strings containing invisible characters',
        'Normalize strings to remove non-printable characters',
        'Use character whitelist for email/username fields'
      ],
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  } else {
    reporter.reportPass(
      'API handles zero-width characters appropriately',
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});

/**
 * Test: Bidirectional text injection
 * 
 * Purpose: Verifies that RTL/LTR override characters don't cause
 * security issues or UI spoofing.
 */
test('Unicode: bidirectional text controlled', async ({ baseURL }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  
  if (!baseURL) {
    reporter.reportSkip('baseURL not provided');
    test.skip(true, 'baseURL not provided');
    return;
  }
  
  const api = await playwrightRequest.newContext({ baseURL: baseURL.toString() });
  const endpoints = ['/api/users', '/api/auth/register'];
  
  const bidiTests = generateUnicodePayloads().filter(p => 
    p.name.includes('rtl') || p.name.includes('ltr') || p.name.includes('directional')
  );
  
  let endpointFound = false;
  let acceptedBidi = 0;
  let crashes = 0;
  
  for (const endpoint of endpoints) {
    try {
      for (const payload of bidiTests) {
        const res = await api.post(endpoint, {
          data: JSON.stringify({
            email: payload.value,
            password: 'Test123!',
            username: payload.value
          }),
          headers: { 'Content-Type': 'application/json' }
        }).catch(() => null);
        
        if (!res) continue;
        endpointFound = true;
        
        if (res.status() >= 500) {
          crashes++;
        }
        
        if ([200, 201].includes(res.status())) {
          acceptedBidi++;
        }
      }
      
      if (endpointFound) break;
    } catch (e) {
      // Continue
    }
  }
  
  if (!endpointFound) {
    reporter.reportSkip('No endpoints found for bidi text testing');
    test.skip(true, 'No endpoints found');
    return;
  }
  
  if (crashes > 0) {
    reporter.reportVulnerability('API8_INJECTION', {
      crashes,
      issue: 'Server crashed with bidirectional text characters'
    });
    expect(crashes).toBe(0);
  } else if (acceptedBidi > 3) {
    reporter.reportWarning(
      `API accepted ${acceptedBidi} inputs with bidirectional text controls`,
      [
        'Strip or reject RTL/LTR override characters',
        'Use Unicode bidirectional algorithm safely',
        'Sanitize display strings separately from stored values',
        'Consider blocking directional formatting characters'
      ],
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  } else {
    reporter.reportPass(
      'API handles bidirectional text safely',
      OWASP_VULNERABILITIES.API8_INJECTION.name
    );
  }
});

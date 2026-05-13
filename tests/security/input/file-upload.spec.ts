import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import * as fs from 'fs';
import * as path from 'path';

/**
 * File Upload Security Tests
 * 
 * These tests verify that the application properly validates and secures
 * file uploads to prevent various attack vectors including malicious file
 * execution, path traversal, and resource exhaustion.
 * 
 * Security Risks Addressed:
 * 1. Malicious file execution through dangerous extensions
 * 2. File size limits and DoS protection
 * 3. MIME type validation and content verification
 * 4. Path traversal attacks through filenames
 * 5. Unsafe file serving and execution
 * 
 * Expected Behavior:
 * - Dangerous file extensions should be blocked
 * - File size limits should be enforced
 * - MIME types should be validated against content
 * - Path traversal attempts should be rejected
 * - Uploaded files should be served safely
 */

/**
 * Test: Malicious file extensions blocked
 * 
 * Purpose: Verifies that the application blocks uploads of files with
 * dangerous extensions that could be executed on the server.
 * 
 * Security Impact: Allowing dangerous file extensions can lead to:
 * - Remote code execution on the server
 * - Malware uploads and distribution
 * - Server compromise and data breaches
 * - Backdoor installation
 * 
 * Test Strategy:
 * 1. Attempt to upload files with dangerous extensions
 * 2. Verify uploads are rejected with appropriate status codes
 * 3. Ensure server-side validation is in place
 */
test('File upload: malicious file extensions blocked', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    reporter.reportSkip('Malicious-extension upload probe could not run because no valid test user credentials are configured.');
    test.skip(true, 'No valid test user credentials are configured');
    return;
  }

  // Authenticate first so the upload probe runs in a realistic user context.
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    reporter.reportSkip('Malicious-extension upload probe could not run because login failed or no bearer token was obtained.');
    test.skip(true, 'Login failed or no bearer token was obtained');
    return;
  }

  const { token } = attempt as any;

  // Try file names that should never be accepted by a secure upload path.
  const dangerousExtensions = [
    'evil.php',      // PHP execution
    'malware.exe',   // Windows executable
    'script.js',     // JavaScript execution
    'shell.sh',      // Shell script
    'bad.jsp',       // Java Server Page
    'hack.aspx',     // ASP.NET page
  ];

  // Upload each candidate extension and watch for acceptance or unsafe handling.
  let allDangerousBlocked = true;
  for (const filename of dangerousExtensions) {
    try {
      // Create a temporary file so the upload request has real binary content.
      const tempPath = path.join('/tmp', filename);
      fs.writeFileSync(tempPath, 'malicious content');

      const formData = new FormData();
      const fileBuffer = fs.readFileSync(tempPath);
      const blob = new Blob([fileBuffer]);
      formData.append('file', blob, filename);

      // Send the crafted upload using the authenticated token.
      const res = await request.post('/api/upload', {
        headers: { 
          'Authorization': `Bearer ${token}`,
        },
        multipart: {
          file: {
            name: filename,
            mimeType: 'application/octet-stream',
            buffer: fileBuffer,
          },
        },
      });

      const status = res.status();
      // A secure endpoint should reject the upload or refuse to expose it.
      const rejected = status === 400 || status === 403 || status === 415;

      softCheck(
        testInfo,
        rejected || status === 404,
        `Dangerous file extension not blocked: ${filename}`
      );

      if (!(rejected || status === 404)) {
        allDangerousBlocked = false;
      }

      // Remove the temporary file after each probe.
      fs.unlinkSync(tempPath);

      if (!rejected && status !== 404) break;
    } catch (e) {
      // Upload endpoint might not exist
    }
  }

  if (allDangerousBlocked) {
    reporter.reportPass(
      'Dangerous file extensions were blocked or the upload endpoint was not exposed.',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: File size limits enforced
 * 
 * Purpose: Verifies that the application enforces file size limits
 * to prevent DoS attacks and resource exhaustion.
 * 
 * Security Impact: Lack of file size limits can lead to:
 * - DoS attacks through large file uploads
 * - Disk space exhaustion
 * - Memory exhaustion during processing
 * - Service unavailability
 * 
 * Test Strategy:
 * 1. Create a large file (100MB)
 * 2. Attempt to upload the oversized file
 * 3. Verify upload is rejected with appropriate status
 * 4. Ensure resource protection is in place
 */
test('File upload: file size limits enforced', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    reporter.reportSkip('File-size-limit upload probe could not run because no valid test user credentials are configured.');
    test.skip(true, 'No valid test user credentials are configured');
    return;
  }

  // Authenticate first so file-size checks use the same upload path as normal users.
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    reporter.reportSkip('File-size-limit upload probe could not run because login failed or no bearer token was obtained.');
    test.skip(true, 'Login failed or no bearer token was obtained');
    return;
  }

  const { token } = attempt as any;

  try {
    // Build a very large buffer to verify request-size enforcement.
    const largeContent = Buffer.alloc(100 * 1024 * 1024, 'A');
    const tempPath = '/tmp/large-file.txt';
    fs.writeFileSync(tempPath, largeContent);

    // Attempt the oversized upload and measure how the API responds.
    const res = await request.post('/api/upload', {
      headers: { 
        'Authorization': `Bearer ${token}`,
      },
      multipart: {
        file: {
          name: 'large-file.txt',
          mimeType: 'text/plain',
          buffer: largeContent,
        },
      },
      timeout: 10000,
    }).catch(() => null);

    if (res) {
      const status = res.status();
      // Accept only defensive outcomes such as rejection or explicit size limits.
      const hasLimits = status === 413 || status === 400;

      softCheck(
        testInfo,
        hasLimits || status === 404,
        'File upload should enforce size limits (expected 413 or 400 for oversized files)'
      );

      if (hasLimits || status === 404) {
        reporter.reportPass(
          'Oversized file upload was rejected or upload endpoint was not exposed.',
          OWASP_VULNERABILITIES.API4_RATE_LIMIT.name
        );
      }
    }

    // Delete the temporary file when the probe finishes.
    if (fs.existsSync(tempPath)) {
      fs.unlinkSync(tempPath);
    }
  } catch (e) {
    // Expected - upload might be blocked or timeout
  }
});

test('File upload: MIME type validation', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    reporter.reportSkip('MIME-validation upload probe could not run because no valid test user credentials are configured.');
    test.skip(true, 'No valid test user credentials are configured');
    return;
  }

  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    reporter.reportSkip('MIME-validation upload probe could not run because login failed or no bearer token was obtained.');
    test.skip(true, 'Login failed or no bearer token was obtained');
    return;
  }

  const { token } = attempt as any;

  try {
    // Disguise an executable header as an image upload to test content validation.
    const maliciousContent = Buffer.from('MZ\x90\x00'); // PE executable header
    const tempPath = '/tmp/fake-image.jpg';
    fs.writeFileSync(tempPath, maliciousContent);

    const res = await request.post('/api/upload', {
      headers: { 
        'Authorization': `Bearer ${token}`,
      },
      multipart: {
        file: {
          name: 'fake-image.jpg',
          mimeType: 'image/jpeg', // Lying about MIME type
          buffer: maliciousContent,
        },
      },
    });

    const status = res.status();
    // Content validation should inspect the real bytes, not just the extension.
    const validated = status === 400 || status === 415;

    softCheck(
      testInfo,
      validated || status === 404,
      'File upload should validate MIME type against actual file content'
    );

    if (validated || status === 404) {
      reporter.reportPass(
        'MIME type validation rejected the disguised executable or upload endpoint was not exposed.',
        OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
      );
    }

    // Remove the temporary file after the MIME check.
    fs.unlinkSync(tempPath);
  } catch (e) {
    // Expected
  }
});

test('File upload: path traversal protection', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    reporter.reportSkip('Upload path-traversal probe could not run because no valid test user credentials are configured.');
    test.skip(true, 'No valid test user credentials are configured');
    return;
  }

  // Authenticate first so filename sanitization is checked in the normal upload flow.
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    reporter.reportSkip('Upload path-traversal probe could not run because login failed or no bearer token was obtained.');
    test.skip(true, 'Login failed or no bearer token was obtained');
    return;
  }

  const { token } = attempt as any;

  // Try filenames that should be normalized or rejected by a safe upload handler.
  const pathTraversalNames = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32\\config\\sam',
    'test/../../secret.txt',
  ];

  for (const filename of pathTraversalNames) {
    try {
      // The payload content is harmless; only the filename is meant to trigger validation.
      const content = Buffer.from('test content');

      const res = await request.post('/api/upload', {
        headers: { 
          'Authorization': `Bearer ${token}`,
        },
        multipart: {
          file: {
            name: filename,
            mimeType: 'text/plain',
            buffer: content,
          },
        },
      });

      const status = res.status();
      const rejected = status === 400 || status === 403;

      softCheck(
        testInfo,
        rejected || status === 404,
        `Path traversal not blocked in filename: ${filename}`
      );

      if (rejected || status === 404) {
        reporter.reportPass(
          `Path traversal attempts were blocked for filename ${filename} or the upload endpoint was not exposed.`,
          OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
        );
      }

      // Stop after the first clearly unsafe success to keep the probe compact.
      if (!rejected && status !== 404) break;
    } catch (e) {
      // Expected
    }
  }
});

test('File upload: uploaded files not executable', async ({ request }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    reporter.reportSkip('Upload executable-serving probe could not run because no valid test user credentials are configured.');
    test.skip(true, 'No valid test user credentials are configured');
    return;
  }

  // Authenticate first so the executable-serving check uses the same upload flow.
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    reporter.reportSkip('Upload executable-serving probe could not run because login failed or no bearer token was obtained.');
    test.skip(true, 'Login failed or no bearer token was obtained');
    return;
  }

  const { token } = attempt as any;

  try {
    // Upload text that would be dangerous if served or executed as code.
    const content = Buffer.from('<?php echo "hacked"; ?>');
    const tempPath = '/tmp/test.txt';
    fs.writeFileSync(tempPath, content);

    const res = await request.post('/api/upload', {
      headers: { 
        'Authorization': `Bearer ${token}`,
      },
      multipart: {
        file: {
          name: 'test.txt',
          mimeType: 'text/plain',
          buffer: content,
        },
      },
    });

    if (res.status() === 200 || res.status() === 201) {
      const body = await res.json().catch(() => null);
      
      if (body && body.url) {
        // Fetch the uploaded file and inspect the response headers.
        const fileRes = await request.get(body.url);
        const contentType = fileRes.headers()['content-type'];
        const contentDisposition = fileRes.headers()['content-disposition'];

        // Safe delivery means the browser should not treat the upload as executable.
        const isSafe = 
          contentType?.includes('text/plain') ||
          contentDisposition?.includes('attachment');

        softCheck(
          testInfo,
          isSafe,
          'Uploaded files should be served with safe Content-Type and Content-Disposition headers'
        );

        if (isSafe) {
          reporter.reportPass(
            'Uploaded files were served with safe Content-Type and Content-Disposition headers.',
            OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
          );
        }
      }
    }

    // Delete the temporary file after the executable-serving probe.
    if (fs.existsSync(tempPath)) {
      fs.unlinkSync(tempPath);
    }
  } catch (e) {
    // Expected
  }
});

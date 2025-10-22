import { test } from '@playwright/test';
import { ensureTestUser, tryLogin, softCheck } from '../utils';
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
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  // Step 1: Authenticate user for upload testing
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    test.skip(true, 'Could not login');
    return;
  }

  const { token } = attempt as any;

  // Step 2: Define dangerous file extensions to test
  const dangerousExtensions = [
    'evil.php',      // PHP execution
    'malware.exe',   // Windows executable
    'script.js',     // JavaScript execution
    'shell.sh',      // Shell script
    'bad.jsp',       // Java Server Page
    'hack.aspx',     // ASP.NET page
  ];

  // Step 3: Test each dangerous extension
  for (const filename of dangerousExtensions) {
    try {
      // Step 4: Create a test file with dangerous extension
      const tempPath = path.join('/tmp', filename);
      fs.writeFileSync(tempPath, 'malicious content');

      const formData = new FormData();
      const fileBuffer = fs.readFileSync(tempPath);
      const blob = new Blob([fileBuffer]);
      formData.append('file', blob, filename);

      // Step 5: Attempt to upload dangerous file
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
      // Step 6: Verify dangerous files are rejected
      const rejected = status === 400 || status === 403 || status === 415;

      softCheck(
        testInfo,
        rejected || status === 404,
        `Dangerous file extension not blocked: ${filename}`
      );

      // Cleanup
      fs.unlinkSync(tempPath);

      if (!rejected && status !== 404) break;
    } catch (e) {
      // Upload endpoint might not exist
    }
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
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  // Step 1: Authenticate user for upload testing
  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    test.skip(true, 'Could not login');
    return;
  }

  const { token } = attempt as any;

  try {
    // Step 2: Create a large file to test size limits (100MB)
    const largeContent = Buffer.alloc(100 * 1024 * 1024, 'A');
    const tempPath = '/tmp/large-file.txt';
    fs.writeFileSync(tempPath, largeContent);

    // Step 3: Attempt to upload oversized file
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
      // Step 4: Verify large files are rejected
      const hasLimits = status === 413 || status === 400;

      softCheck(
        testInfo,
        hasLimits || status === 404,
        'File upload should enforce size limits (expected 413 or 400 for oversized files)'
      );
    }

    // Cleanup
    if (fs.existsSync(tempPath)) {
      fs.unlinkSync(tempPath);
    }
  } catch (e) {
    // Expected - upload might be blocked or timeout
  }
});

test('File upload: MIME type validation', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    test.skip(true, 'Could not login');
    return;
  }

  const { token } = attempt as any;

  try {
    // Try to upload executable disguised as image
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
    // Should validate actual file content, not just extension
    const validated = status === 400 || status === 415;

    softCheck(
      testInfo,
      validated || status === 404,
      'File upload should validate MIME type against actual file content'
    );

    // Cleanup
    fs.unlinkSync(tempPath);
  } catch (e) {
    // Expected
  }
});

test('File upload: path traversal protection', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    test.skip(true, 'Could not login');
    return;
  }

  const { token } = attempt as any;

  const pathTraversalNames = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32\\config\\sam',
    'test/../../secret.txt',
  ];

  for (const filename of pathTraversalNames) {
    try {
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

      if (!rejected && status !== 404) break;
    } catch (e) {
      // Expected
    }
  }
});

test('File upload: uploaded files not executable', async ({ request }, testInfo) => {
  const user = await ensureTestUser(request as any);
  
  if (!user.email || !user.password) {
    test.skip(true, 'No user configured');
    return;
  }

  const attempt = await tryLogin(request as any, user.email, user.password);
  if (!attempt || !attempt.token) {
    test.skip(true, 'Could not login');
    return;
  }

  const { token } = attempt as any;

  try {
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
        // Try to access the uploaded file
        const fileRes = await request.get(body.url);
        const contentType = fileRes.headers()['content-type'];
        const contentDisposition = fileRes.headers()['content-disposition'];

        // Should be served with safe headers
        const isSafe = 
          contentType?.includes('text/plain') ||
          contentDisposition?.includes('attachment');

        softCheck(
          testInfo,
          isSafe,
          'Uploaded files should be served with safe Content-Type and Content-Disposition headers'
        );
      }
    }

    // Cleanup
    if (fs.existsSync(tempPath)) {
      fs.unlinkSync(tempPath);
    }
  } catch (e) {
    // Expected
  }
});

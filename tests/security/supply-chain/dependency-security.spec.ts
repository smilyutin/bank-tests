import { test } from '@playwright/test';
import { softCheck } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Dependency Security Tests
 * 
 * These tests verify that the application's dependencies are properly
 * managed and secured to prevent supply chain attacks and ensure
 * reproducible builds.
 * 
 * Security Risks Addressed:
 * 1. Missing dependency declarations
 * 2. Unreproducible builds without lock files
 * 3. Vulnerable dependencies
 * 4. Unsafe version ranges allowing malicious updates
 * 5. Insecure package registry configurations
 * 6. Credentials exposed in package files
 * 
 * Expected Behavior:
 * - package.json should declare all dependencies
 * - Lock files should exist for reproducible builds
 * - Dependencies should be regularly audited
 * - Version ranges should be safe and pinned
 * - Registry configurations should use HTTPS
 * - No credentials should be in package files
 */

/**
 * Test: Package.json exists and has dependencies
 * 
 * Purpose: Verifies that the project properly declares its dependencies
 * in package.json for transparency and security auditing.
 * 
 * Security Impact: Missing dependency declarations can lead to:
 * - Hidden dependencies not being audited
 * - Supply chain attacks through undeclared packages
 * - Difficulty in vulnerability assessment
 * - Unreproducible builds
 * 
 * Test Strategy:
 * 1. Check for package.json existence
 * 2. Verify dependencies are declared
 * 3. Ensure proper dependency management
 */
test('Dependencies: package.json exists and has dependencies', async ({}, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const packagePath = path.join(process.cwd(), 'package.json');
  
  if (!fs.existsSync(packagePath)) {
    test.skip(true, 'No package.json found');
    return;
  }

  // Read and parse package.json to see which dependencies are declared.
  const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf-8'));
  
  // Check that dependency declarations are present and readable.
  const hasDeps = 
    (packageJson.dependencies && Object.keys(packageJson.dependencies).length > 0) ||
    (packageJson.devDependencies && Object.keys(packageJson.devDependencies).length > 0);

  // Verify the declared dependencies are available in the project metadata.
  softCheck(
    testInfo,
    hasDeps,
    'package.json should declare dependencies'
  );

  if (hasDeps) {
    reporter.reportPass(
      'package.json exists and declares dependencies.',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

/**
 * Test: Lock files exist for reproducible builds
 * 
 * Purpose: Verifies that lock files exist to ensure reproducible builds
 * and prevent supply chain attacks through dependency version changes.
 * 
 * Security Impact: Missing lock files can lead to:
 * - Unreproducible builds across environments
 * - Supply chain attacks through dependency updates
 * - Hidden dependency changes
 * - Build inconsistencies
 * 
 * Test Strategy:
 * 1. Check for common lock file formats
 * 2. Verify at least one lock file exists
 * 3. Ensure reproducible dependency resolution
 */
test('Dependencies: package-lock.json exists for reproducible builds', async ({}, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const lockPath = path.join(process.cwd(), 'package-lock.json');
  const yarnLockPath = path.join(process.cwd(), 'yarn.lock');
  const pnpmLockPath = path.join(process.cwd(), 'pnpm-lock.yaml');
  
  const hasLockFile = 
    fs.existsSync(lockPath) ||
    fs.existsSync(yarnLockPath) ||
    fs.existsSync(pnpmLockPath);

  softCheck(
    testInfo,
    hasLockFile,
    'Lock file (package-lock.json, yarn.lock, or pnpm-lock.yaml) should exist for reproducible builds'
  );

  if (hasLockFile) {
    reporter.reportPass(
      'A lock file exists for reproducible builds.',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

test('Dependencies: no known vulnerable packages (check advisories)', async ({}, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  reporter.reportSkip('Dependency vulnerability status was not validated in this test.');
  test.skip(true, 'This suite does not perform a live dependency vulnerability audit.');
});

test('Dependencies: version pinning or ranges are safe', async ({}, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const packagePath = path.join(process.cwd(), 'package.json');
  
  if (!fs.existsSync(packagePath)) {
    test.skip(true, 'No package.json found');
    return;
  }

  const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf-8'));
  const allDeps = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
  };

  const unsafeRanges: string[] = [];

  for (const [name, version] of Object.entries(allDeps)) {
    const ver = version as string;
    // Check for wildcard or very loose version ranges
    if (ver === '*' || ver === 'latest' || ver.startsWith('>=')) {
      unsafeRanges.push(`${name}: ${ver}`);
    }
  }

  softCheck(
    testInfo,
    unsafeRanges.length === 0,
    `Unsafe version ranges found (should use ^ or ~ for semver): ${unsafeRanges.slice(0, 5).join(', ') || 'none'}`
  );

  if (unsafeRanges.length === 0) {
    reporter.reportPass(
      'Dependency version ranges are safe and do not use wildcard/latest/>= patterns.',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

test('Supply chain: .npmrc or similar config exists', async ({}, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const npmrcPath = path.join(process.cwd(), '.npmrc');
  
  if (!fs.existsSync(npmrcPath)) {
    reporter.reportSkip('No .npmrc file was found, so registry configuration could not be validated.');
    test.skip(true, 'No .npmrc file found');
    return;
  }

  const content = fs.readFileSync(npmrcPath, 'utf-8');
  
  // Check for security best practices
  const hasRegistry = content.includes('registry=');
  const usesHTTPS = content.includes('https://');
  
  if (!hasRegistry) {
    reporter.reportSkip('The .npmrc file does not declare a registry configuration to validate.');
    test.skip(true, '.npmrc does not declare a registry setting');
    return;
  }

  softCheck(
    testInfo,
    usesHTTPS,
    '.npmrc should use HTTPS registry URLs'
  );

  if (usesHTTPS) {
    reporter.reportPass(
      '.npmrc registry configuration uses HTTPS.',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

test('Supply chain: no credentials in package files', async ({}, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const packagePath = path.join(process.cwd(), 'package.json');
  
  if (!fs.existsSync(packagePath)) {
    test.skip(true, 'No package.json found');
    return;
  }

  const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf-8'));
  const content = JSON.stringify(packageJson);

  const hasCredentials = 
    content.includes('password') ||
    content.includes('token=') ||
    content.includes('api_key') ||
    content.includes('secret');

  softCheck(
    testInfo,
    !hasCredentials,
    'package.json should not contain credentials or secrets'
  );

  if (!hasCredentials) {
    reporter.reportPass(
      'No credentials or secrets were found in package.json.',
      OWASP_VULNERABILITIES.API8_SECURITY_MISCONFIGURATION.name
    );
  }
});

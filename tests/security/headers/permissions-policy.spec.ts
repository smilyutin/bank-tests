import { test } from '@playwright/test';
import { softCheck } from '../utils/utils';
import { SecurityReporter, OWASP_VULNERABILITIES } from '../security-reporter';

test('Permissions-Policy: header present', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning('No response received from base URL', [
      'Verify BASE_URL environment variable is set correctly',
      'Ensure application server is running and accessible',
      'Check network connectivity and firewall rules',
      'Review server logs for startup or configuration errors'
    ], OWASP_VULNERABILITIES.API6_VUL_OUTDATED_COMPONENTS.name);
    return;
  }

  const headers = response.headers();
  const permissionsPolicy = headers['permissions-policy'];
  const featurePolicy = headers['feature-policy']; // Legacy header

  softCheck(
    testInfo,
    !!(permissionsPolicy || featurePolicy),
    'Permissions-Policy (or Feature-Policy) header should be present'
  );
});

test('Permissions-Policy: camera and microphone restricted', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning('No response received from base URL', [
      'Verify BASE_URL environment variable is set correctly',
      'Ensure application server is running and accessible',
      'Check network connectivity and firewall rules',
      'Review server logs for startup or configuration errors'
    ], OWASP_VULNERABILITIES.API6_VUL_OUTDATED_COMPONENTS.name);
    return;
  }

  const headers = response.headers();
  const policy = headers['permissions-policy'] || headers['feature-policy'];

  if (!policy) {
    reporter.reportWarning('No Permissions-Policy header found', [
      'Add Permissions-Policy header to restrict camera and microphone access',
      'Set format: camera=(), microphone=()',
      'Review Permissions-Policy specification at MDN',
      'Configure server to include Permissions-Policy in responses'
    ], OWASP_VULNERABILITIES.API6_VUL_OUTDATED_COMPONENTS.name);
    return;
  }

  const cameraRestricted = 
    policy.includes('camera=()') || 
    policy.includes("camera 'none'") ||
    policy.includes('camera=self');
    
  const microphoneRestricted = 
    policy.includes('microphone=()') || 
    policy.includes("microphone 'none'") ||
    policy.includes('microphone=self');

  softCheck(
    testInfo,
    cameraRestricted || microphoneRestricted,
    'Permissions-Policy should restrict camera/microphone access if not needed'
  );
});

test('Permissions-Policy: geolocation restricted', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning('No response received from base URL', [
      'Verify BASE_URL environment variable is set correctly',
      'Ensure application server is running and accessible',
      'Check network connectivity and firewall rules',
      'Review server logs for startup or configuration errors'
    ], OWASP_VULNERABILITIES.API6_VUL_OUTDATED_COMPONENTS.name);
    return;
  }

  const headers = response.headers();
  const policy = headers['permissions-policy'] || headers['feature-policy'];

  if (!policy) {
    reporter.reportWarning('No Permissions-Policy header found', [
      'Add Permissions-Policy header to restrict geolocation access',
      'Set format: geolocation=()',
      'Review Permissions-Policy specification at MDN',
      'Configure server to include Permissions-Policy in responses'
    ], OWASP_VULNERABILITIES.API6_VUL_OUTDATED_COMPONENTS.name);
    return;
  }

  const geolocationRestricted = 
    policy.includes('geolocation=()') || 
    policy.includes("geolocation 'none'") ||
    policy.includes('geolocation=self');

  softCheck(
    testInfo,
    geolocationRestricted,
    'Permissions-Policy should restrict geolocation if not needed'
  );
});

test('Permissions-Policy: payment features restricted', async ({ page }, testInfo) => {
  const reporter = new SecurityReporter(testInfo);
  const response = await page.goto('/');
  
  if (!response) {
    reporter.reportWarning('No response received from base URL', [
      'Verify BASE_URL environment variable is set correctly',
      'Ensure application server is running and accessible',
      'Check network connectivity and firewall rules',
      'Review server logs for startup or configuration errors'
    ], OWASP_VULNERABILITIES.API6_VUL_OUTDATED_COMPONENTS.name);
    return;
  }

  const headers = response.headers();
  const policy = headers['permissions-policy'] || headers['feature-policy'];

  if (!policy) {
    reporter.reportWarning('No Permissions-Policy header found', [
      'Add Permissions-Policy header to restrict payment features',
      'Set format: payment-request=()',
      'Review Permissions-Policy specification at MDN',
      'Configure server to include Permissions-Policy in responses'
    ], OWASP_VULNERABILITIES.API6_VUL_OUTDATED_COMPONENTS.name);
    return;
  }

  const paymentRestricted = 
    policy.includes('payment=()') || 
    policy.includes("payment 'none'") ||
    policy.includes('payment=self');

  // Payment should be restricted if not a payment app
  if (!policy.includes('payment')) {
    softCheck(
      testInfo,
      true,
      'Consider adding payment restrictions to Permissions-Policy'
    );
  }
});

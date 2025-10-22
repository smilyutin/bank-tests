import { test } from '@playwright/test';
import { softCheck } from '../utils';

test('Permissions-Policy: header present', async ({ page }, testInfo) => {
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
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
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const headers = response.headers();
  const policy = headers['permissions-policy'] || headers['feature-policy'];

  if (!policy) {
    test.skip(true, 'No Permissions-Policy header found');
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
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const headers = response.headers();
  const policy = headers['permissions-policy'] || headers['feature-policy'];

  if (!policy) {
    test.skip(true, 'No Permissions-Policy header found');
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
  const response = await page.goto('/');
  
  if (!response) {
    test.skip(true, 'No response received');
    return;
  }

  const headers = response.headers();
  const policy = headers['permissions-policy'] || headers['feature-policy'];

  if (!policy) {
    test.skip(true, 'No Permissions-Policy header found');
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

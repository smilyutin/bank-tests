import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 30_000,
  expect: { timeout: 5000 },
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: [
    ['list'],
    ['html', { 
      open: 'never',
      // Show all test statuses including skipped
      attachmentsBaseURL: undefined 
    }],
    ['allure-playwright', {
      detail: true,
      outputFolder: 'allure-results',
      suiteTitle: true,
      categories: [
        {
          name: 'Critical Security Issues',
          matchedStatuses: ['failed'],
          messageRegex: '.*CRITICAL.*'
        },
        {
          name: 'High Risk Vulnerabilities',
          matchedStatuses: ['failed'],
          messageRegex: '.*HIGH.*'
        }
      ],
      environmentInfo: {
        'Test Suite': 'Bank API Security Tests',
        'Framework': 'Playwright + OWASP',
        'Node Version': process.version
      }
    }]
  ],
  use: {
    baseURL: process.env.BASE_URL || 'http://localhost:5001',
    headless: true,
    ignoreHTTPSErrors: true,
    viewport: { width: 1280, height: 720 },
    actionTimeout: 10000,
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
});

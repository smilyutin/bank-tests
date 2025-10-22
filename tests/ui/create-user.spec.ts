import { test, expect } from '@playwright/test';
import { RegisterPage } from './pages/registerPage';
import { findOrCreateUser, saveUser, createRandomUser } from '../utils/credentials';

/**
 * UI User Registration Tests
 * 
 * These tests verify that the application provides a functional user interface
 * for user registration and account creation, ensuring the system can be
 * properly tested with valid user credentials through the UI.
 * 
 * Test Strategy:
 * 1. Create fresh random user credentials for each test
 * 2. Navigate to registration page
 * 3. Fill registration form using Page Object Model
 * 4. Submit form and verify success
 * 5. Persist user credentials for future tests
 * 
 * Expected Behavior:
 * - Registration form should be accessible
 * - Form fields should accept valid input
 * - Submission should create user account
 * - Success should be indicated through navigation or message
 * - User credentials should be persisted
 */

/**
 * Test: Create user account via UI
 * 
 * Purpose: Verifies that the application supports user account creation
 * through the user interface, enabling automated testing with valid credentials.
 * 
 * Test Strategy:
 * 1. Generate fresh random user credentials
 * 2. Navigate to registration page
 * 3. Fill email and password fields using POM
 * 4. Submit registration form
 * 5. Wait for success indication (navigation or message)
 * 6. Verify registration was successful
 * 7. Persist user credentials for future tests
 */
test.describe('UI - Create user account', () => {
  test('should create a user via UI', async ({ page, baseURL }) => {
    if (!baseURL) throw new Error('baseURL is not defined');
    const register = new RegisterPage(page);
    
    // Step 1: Generate fresh random user credentials for this test
    const user = createRandomUser('e2e', true);
    await register.goto(baseURL.toString());

    // Step 2: Define common form field selectors for flexibility
    const emailSelectorCandidates = [
      'input[name="email"]',
      'input[id="email"]',
      'input[type="email"]',
      'text=Email',
    ];
    const passwordSelectorCandidates = [
      'input[name="password"]',
      'input[id="password"]',
      'input[type="password"]',
      'text=Password',
    ];

    // Step 3: Use Page Object Model to fill and submit form
    if (!user.email || !user.password) {
      throw new Error('User email or password is undefined');
    }
    const filledEmail = await register.fillEmail(user.email);
    const filledPassword = await register.fillPassword(user.password);
    const clicked = await register.submit();
    
    // Step 4: Verify form interaction was successful
    expect(filledEmail).toBeTruthy();
    expect(filledPassword).toBeTruthy();
    expect(clicked).toBeTruthy();

    // Step 5: Wait for success indication (navigation or success message)
    await Promise.race([
      page.waitForNavigation({ timeout: 5000 }).catch(() => null),
      page.waitForSelector('text=Welcome', { timeout: 5000 }).catch(() => null),
      page.waitForSelector('text=Account created', { timeout: 5000 }).catch(() => null),
    ]);

    // Step 6: Verify registration was successful
    const urlAfter = page.url();
    const sawSuccess = await page.$('text=Welcome') || await page.$('text=Account created') || await page.$('text=Check your email');
    expect(!!sawSuccess || !urlAfter.endsWith('/register')).toBeTruthy();

    // Step 7: Persist user credentials for future tests
    saveUser(user);
  });
});

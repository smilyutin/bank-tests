import { test, expect } from '@playwright/test';
import { LoginPage } from './pages/loginPage';
import { DashboardPage } from './pages/dashboardPage';
import { findOrCreateUser } from '../utils/credentials';

/**
 * Dashboard Functionality Tests
 * 
 * These tests verify that the application's main dashboard provides
 * all expected functionality including navigation, account information,
 * and user interactions.
 * 
 * Test Strategy:
 * 1. Authenticate with test user in beforeEach
 * 2. Navigate to dashboard and wait for load
 * 3. Test welcome message and navigation elements
 * 4. Verify account balance display
 * 5. Check recent transactions list
 * 6. Test logout functionality
 * 
 * Expected Behavior:
 * - Dashboard should display welcome message with user info
 * - Navigation menu should contain expected items
 * - Account balance should be displayed correctly
 * - Recent transactions should be listed
 * - Logout should work properly
 */

/**
 * Test: Dashboard functionality
 * 
 * Purpose: Verifies that the dashboard provides all expected functionality
 * including user information, navigation, account details, and logout.
 * 
 * Test Strategy:
 * 1. Set up authentication in beforeEach
 * 2. Test welcome message and navigation
 * 3. Verify account balance display
 * 4. Check recent transactions
 * 5. Test logout functionality
 */
test.describe('Dashboard functionality', () => {
  let loginPage: LoginPage;
  let dashboardPage: DashboardPage;

  test.beforeEach(async ({ page, baseURL }) => {
    if (!baseURL) throw new Error('baseURL is not defined');

    // Step 1: Get test user from credentials store
    const user = findOrCreateUser('e2e');

    // Step 2: Authenticate user
    loginPage = new LoginPage(page);
    await loginPage.goto(baseURL);
    const identifier = user.username || user.email;
    if (!identifier) throw new Error('No username or email found in credentials');
    await loginPage.fillEmail(identifier);
    await loginPage.fillPassword(user.password);
    await loginPage.submit();

    // Step 3: Initialize dashboard page and wait for it to load
    dashboardPage = new DashboardPage(page);
    await dashboardPage.waitForLoad();
  });

  test('should display welcome message and navigation', async () => {
    const welcomeText = await dashboardPage.getWelcomeMessage();
    expect(welcomeText).toBeTruthy();

    // welcome should contain username or email fragment
    const user = findOrCreateUser('e2e');
    const identifier = user.username || user.email || '';
  if (identifier && welcomeText) expect(welcomeText.toLowerCase()).toContain(identifier.split('@')[0].toLowerCase());

  // Assert full navigation texts (from visual: left menu)
    const navTexts = await dashboardPage.getNavigationTexts();
    const expected = [
      'Profile',
      'Money Transfer',
      'Loans',
      'Transaction History',
      'Virtual Cards',
      'Bill Payments',
      'Logout'
    ];
    // normalize whitespace and case
  // normalize: remove emojis/non-alphanumeric chars, collapse whitespace, lowercase
  const norm = (s: string) => s.replace(/[^^\p{L}\p{N}\s]/gu, '').replace(/\s+/g, ' ').trim().toLowerCase();
    const got = navTexts.map(norm);
    const want = expected.map(norm);
    // Ensure expected items appear in order (may be additional items)
    let idx = 0;
    for (const w of want) {
      const found = got.indexOf(w, idx);
      expect(found).toBeGreaterThanOrEqual(0);
      idx = found + 1;
    }

    // Also assert hrefs/anchors from snapshot order
    const navLinks = await dashboardPage.getNavigationLinks();
    const gotHrefs = navLinks.map(l => l.href || '').filter(Boolean);
    const expectedHrefs = ['#profile', '#transfers', '#loans', '#transactions', '#virtual-cards', '#bill-payments', '#'];
    // ensure each expected href appears in order in gotHrefs
    let j = 0;
    for (const eh of expectedHrefs) {
      const found = gotHrefs.indexOf(eh, j);
      expect(found).toBeGreaterThanOrEqual(0);
      j = found + 1;
    }
  });

  test('should show account balance', async () => {
    const balance = await dashboardPage.getAccountBalance();
    expect(balance).not.toBeNull();
    expect(typeof balance).toBe('number');
    expect((balance as number) >= 0).toBeTruthy();
  });

  test('should list recent transactions', async () => {
    const transactions = await dashboardPage.getRecentTransactions();
    // transactions may be empty; if present, assert they contain an amount-like string
    expect(transactions.length).toBeGreaterThanOrEqual(0);
    if (transactions.length > 0) {
      const first = transactions[0];
      const text = await first.innerText();
      // look for date or amount pattern
      expect(/\d{1,2}\/\d{1,2}\/\d{2,4}|\d{4}-\d{2}-\d{2}|[$€£]\s*\d+/.test(text)).toBeTruthy();
    }
  });

  test('should allow logout', async () => {
    const logoutExists = await dashboardPage.logout();
    expect(logoutExists).toBeTruthy();
    
      // Wait for navigation after logout
      await dashboardPage.page.waitForURL(/\/(login|register|$)/, { timeout: 5000 });
    
      // Verify we're logged out
    const isStillLoggedIn = await dashboardPage.isLoggedIn();
    expect(isStillLoggedIn).toBeFalsy();
  });
});
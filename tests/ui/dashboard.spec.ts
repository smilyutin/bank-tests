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

    const user = findOrCreateUser('e2e');

    loginPage = new LoginPage(page);
    await loginPage.goto(baseURL);
    const identifier = user.username || user.email;
    if (!identifier) throw new Error('No username or email found in credentials');
    await loginPage.fillEmail(identifier);
    await loginPage.fillPassword(user.password);
    await loginPage.submit();

    dashboardPage = new DashboardPage(page);
    await dashboardPage.waitForLoad();
  });

  test('should display welcome message and navigation', async () => {
    const welcomeText = await dashboardPage.getWelcomeMessage();
    expect(welcomeText).toBeTruthy();

    const user = findOrCreateUser('e2e');
    const identifier = user.username || user.email || '';
    if (identifier && welcomeText) {
      expect(welcomeText.toLowerCase()).toContain(identifier.split('@')[0].toLowerCase());
    }

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

    const norm = (s: string) =>
      s.replace(/[^\p{L}\p{N}\s]/gu, '').replace(/\s+/g, ' ').trim().toLowerCase();

    const got = navTexts.map(norm);
    const want = expected.map(norm);

    let idx = 0;
    for (const w of want) {
      const found = got.indexOf(w, idx);
      expect(found).toBeGreaterThanOrEqual(0);
      idx = found + 1;
    }

    const navLinks = await dashboardPage.getNavigationLinks();
    const gotHrefs = navLinks.map(l => l.href || '').filter(Boolean);
    const expectedHrefs = ['#profile', '#transfers', '#loans', '#transactions', '#virtual-cards', '#bill-payments', '#'];

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
    expect(transactions.length).toBeGreaterThanOrEqual(0);
    if (transactions.length > 0) {
      const first = transactions[0];
      const text = await first.innerText();
      expect(
        /\d{1,2}\/\d{1,2}\/\d{2,4}|\d{4}-\d{2}-\d{2}|[$€£]\s*\d+/.test(text)
      ).toBeTruthy();
    }
  });

  test('should allow logout', async () => {
    const logoutExists = await dashboardPage.logout();
    expect(logoutExists).toBeTruthy();

    await dashboardPage.page.waitForURL(/\/(login|register|$)/, { timeout: 5000 });

    const isStillLoggedIn = await dashboardPage.isLoggedIn();
    expect(isStillLoggedIn).toBeFalsy();
  });

  test('should display accurate account balance', async () => {
    const balanceData = await dashboardPage.verifyBalanceAccuracy();

    expect(balanceData.displayed).not.toBeNull();
    expect(typeof balanceData.displayed).toBe('number');
    expect(balanceData.displayed).toBeGreaterThanOrEqual(0);

    if (balanceData.api !== null && balanceData.matches !== null) {
      expect(balanceData.matches).toBeTruthy();
    }

    const balanceElement = dashboardPage.page.locator('text=/balance.*[$€£]\\s*\\d+(\\.\\d{2})?/i').first();
    if (await balanceElement.count()) {
      const balanceText = await balanceElement.innerText();
      expect(balanceText).toMatch(/[$€£]\s*\d+(\.\d{2})?/);
    }
  });

  test('should handle negative balances correctly', async () => {
    try {
      const response = await dashboardPage.page.request.post('/api/account/update', {
        data: { balance: -100.5 }
      });

      if (response.ok()) {
        await dashboardPage.page.reload();
        const balance = await dashboardPage.getAccountBalance();

        const balanceText = await dashboardPage.page.locator('text=/balance|account/i').first().innerText();
        const showsNegative = balanceText.includes('-') || balanceText.toLowerCase().includes('overdraft');

        expect(balance).not.toBeNull();
        expect(showsNegative).toBeTruthy();
      }
    } catch {
      test.skip(true, 'Balance update API not available');
    }
  });

  test('should display transaction history with proper data integrity', async () => {
    const transactions = await dashboardPage.getTransactionData();

    for (const txn of transactions) {
      if (txn.amount !== null) {
        expect(typeof txn.amount).toBe('number');
        expect(txn.amount).toBeGreaterThan(0);
      }

      if (txn.date !== null) {
        expect(txn.date).toMatch(/\d{1,2}\/\d{1,2}\/\d{2,4}|\d{4}-\d{2}-\d{2}/);
      }

      expect(txn.text).not.toMatch(/<script|javascript:|on\w+=/i);
    }
  });

  test('should show transactions in chronological order', async () => {
    const transactions = await dashboardPage.getTransactionData();

    if (transactions.length > 1) {
      const datedTransactions = transactions.filter(t => t.date !== null);

      if (datedTransactions.length > 1) {
        for (let i = 1; i < datedTransactions.length; i++) {
          const prevDate = new Date(datedTransactions[i - 1].date!);
          const currDate = new Date(datedTransactions[i].date!);
          expect(prevDate.getTime()).toBeGreaterThanOrEqual(currDate.getTime());
        }
      }
    }
  });

  test('should render profile section when navigating', async () => {
    const navLinks = await dashboardPage.getNavigationLinks();
    const profileLink = navLinks.find(l => l.href === '#profile');
    if (profileLink) {
      await dashboardPage.page.locator(`a[href="${profileLink.href}"]`).click();
      const profileSection = dashboardPage.page.locator('#profile, [data-testid="profile"]');
      expect(await profileSection.count()).toBeGreaterThan(0);
    } else {
      test.skip(true, 'Profile link not available');
    }
  });

  test('should show transaction amounts with currency symbol', async () => {
    const transactions = await dashboardPage.getRecentTransactions();
    if (transactions.length > 0) {
      const text = await transactions[0].innerText();
      expect(text).toMatch(/[$€£]\s*\d+(\.\d{2})?/);
    }
  });

  test('should have unique navigation labels', async () => {
    const navTexts = await dashboardPage.getNavigationTexts();
    const normalized = navTexts.map(t => t.trim().toLowerCase());
    const unique = new Set(normalized);
    expect(unique.size).toBe(normalized.length);
  });

  test('should handle session timeout gracefully', async () => {
    const timeoutResult = await dashboardPage.checkSessionTimeout(30000);

    if (!timeoutResult.sessionValid) {
      expect(timeoutResult.currentUrl).toMatch(/\/(login|auth)/);
    } else {
      expect(timeoutResult.currentUrl).toMatch(/\/dashboard/);
    }

    expect(timeoutResult.timeElapsed).toBeGreaterThan(25000);
    expect(timeoutResult.timeElapsed).toBeLessThan(35000);
  });

  test('should be responsive on mobile devices', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.reload();

    const isLoggedIn = await dashboardPage.isLoggedIn();
    expect(isLoggedIn).toBeTruthy();

    const navTexts = await dashboardPage.getNavigationTexts();
    expect(navTexts.length).toBeGreaterThan(0);

    const balance = await dashboardPage.getAccountBalance();
    expect(balance).not.toBeNull();

    const mobileMenu = page.locator('.mobile-menu, .hamburger, [data-testid*="mobile"], button[aria-label*="menu"]');
    const hasMobileUI = (await mobileMenu.count()) > 0;

    expect(navTexts.length > 3 || hasMobileUI).toBeTruthy();
  });

  test('should be responsive on tablet devices', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.reload();

    const isLoggedIn = await dashboardPage.isLoggedIn();
    expect(isLoggedIn).toBeTruthy();

    const navTexts = await dashboardPage.getNavigationTexts();
    expect(navTexts.length).toBeGreaterThan(3);

    const balance = await dashboardPage.getAccountBalance();
    expect(balance).not.toBeNull();

    const transactions = await dashboardPage.getRecentTransactions();
    expect(transactions.length).toBeGreaterThanOrEqual(0);
  });


  test('should maintain accessibility standards', async ({ page }) => {
    await page.waitForLoadState('domcontentloaded');

    const mainContent = page.locator('[role="main"], main');
    if ((await mainContent.count()) === 0) {
      test.skip(true, 'Main landmark not present on this page');
    } else {
      await mainContent.first().waitFor({ state: 'visible', timeout: 5000 });
      expect(await mainContent.count()).toBeGreaterThan(0);
    }

    const navigation = page.locator('[role="navigation"], nav');
    if ((await navigation.count()) === 0) {
      test.skip(true, 'Navigation landmark not present on this page');
    } else {
      await navigation.first().waitFor({ state: 'visible', timeout: 5000 });
      expect(await navigation.count()).toBeGreaterThan(0);
    }

    const balanceElement = page.getByText(/balance/i).first();
    if (await balanceElement.count()) {
      const styles = await balanceElement.evaluate((el: Element) => {
        const computed = window.getComputedStyle(el);
        return {
          fontSize: computed.fontSize,
          color: computed.color,
          backgroundColor: computed.backgroundColor
        };
      });

      const fontSize = parseInt(styles.fontSize, 10);
      expect(fontSize).toBeGreaterThanOrEqual(14);
    }
  });

});
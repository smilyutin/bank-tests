import { test, expect } from '@playwright/test';
import { LoginPage } from './pages/loginPage';
import { DashboardPage } from './pages/dashboardPage';
import { MoneyTransferPage } from './pages/moneyTransferPage';
import { findOrCreateUser } from '../utils/credentials';

/**
 * Money Transfer Flow Tests
 * 
 * These tests verify that the application provides a functional money transfer
 * feature that allows users to send money to other accounts successfully.
 * 
 * Test Strategy:
 * 1. Authenticate with test user
 * 2. Navigate to money transfer page
 * 3. Fill transfer form with recipient and amount
 * 4. Submit transfer and verify success
 * 5. Confirm transfer completion
 * 
 * Expected Behavior:
 * - Money transfer page should be accessible
 * - Form should accept valid recipient and amount
 * - Transfer should be processed successfully
 * - Success confirmation should be displayed
 * - Transfer should be recorded
 */

/**
 * Test: Send money successfully
 * 
 * Purpose: Verifies that the money transfer functionality works correctly
 * and allows users to send money to other accounts.
 * 
 * Test Strategy:
 * 1. Authenticate with test user
 * 2. Navigate to money transfer from dashboard
 * 3. Fill recipient account number and amount
 * 4. Add transfer description
 * 5. Submit transfer
 * 6. Verify success confirmation
 */
test.describe('Money transfer flow', () => {
  test('should send money successfully', async ({ page, baseURL }) => {
    if (!baseURL) throw new Error('baseURL is not defined');

    const user = findOrCreateUser('e2e');

    // Step 1: Authenticate with test user
    const login = new LoginPage(page);
    await login.goto(baseURL);
    const identifier = user.username || user.email;
    if (!identifier) throw new Error('No username/email');
    await login.fillEmail(identifier);
    await login.fillPassword(user.password);
    await login.submit();

    // Step 2: Navigate to dashboard and wait for load
    const dash = new DashboardPage(page);
    await dash.waitForLoad();

    // Step 3: Navigate to Money Transfer page
    const links = await dash.getNavigationLinks();
    const transfer = links.find(l => /transfers|money transfer|send money/i.test(l.text));
    if (transfer && transfer.href) {
      await page.click(`a[href="${transfer.href}"]`);
    } else {
      // Fallback: click a tile/button that contains 'Send Money'
      const tile = page.getByText(/send money|transfer money/i);
      if (await tile.count()) await tile.first().click();
    }

    // Step 4: Fill money transfer form
    const mt = new MoneyTransferPage(page);
    const recip = '1234567890';
    const amount = '10.00';
    await mt.fillRecipient(recip);
    await mt.fillAmount(amount);
    await mt.fillDescription('E2E test transfer');
    
    // Step 5: Submit transfer
    await mt.submit();

    // Step 6: Verify transfer success
    const ok = await mt.waitForSuccess(amount, 5000);
    expect(ok).toBeTruthy();
  });
});

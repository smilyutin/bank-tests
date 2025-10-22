import { Page, expect } from '@playwright/test';

export class DashboardPage {
  readonly page: Page;

  constructor(page: Page) {
    this.page = page;
  }

  async goto(baseURL: string) {
    await this.page.goto(new URL('/dashboard', baseURL).toString());
  }

  async isLoggedIn() {
      // Check URL is dashboard and elements exist
      const url = this.page.url();
      const onDashboard = url.toLowerCase().includes('/dashboard');
      if (!onDashboard) return false;
    
      // Look for typical dashboard elements
      const hasElements = await this.page.getByRole('heading', { name: /dashboard|welcome/i }).count() > 0 ||
        await this.page.getByRole('navigation').count() > 0 ||
        await this.page.getByRole('main').count() > 0;
    
      return hasElements;
  }

  async getWelcomeMessage() {
    const heading = this.page.getByRole('heading', { name: /dashboard|welcome/i });
    if (await heading.count()) return heading.innerText();
    return null;
  }

  async waitForLoad() {
    await this.page.waitForLoadState('networkidle');
    // Wait for typical dashboard elements to be ready
    await expect(async () => {
      const isReady = await this.isLoggedIn();
      expect(isReady).toBeTruthy();
    }).toPass({ timeout: 5000 });
  }

  async getNavigationItems() {
    const nav = this.page.getByRole('navigation');
    if (await nav.count()) {
      return nav.getByRole('link').all();
    }
    return [];
  }

  // Return visible navigation item texts in order
  async getNavigationTexts(): Promise<string[]> {
    const nav = this.page.getByRole('navigation');
    if (!(await nav.count())) return [];
    const links = nav.locator('a, button, [role="link"]');
    const count = await links.count();
    const out: string[] = [];
    for (let i = 0; i < count; i++) {
      const el = links.nth(i);
      const text = (await el.innerText()).trim();
      if (text) out.push(text);
    }
    return out;
  }

  // Return visible navigation items with hrefs (text, href) in order
  async getNavigationLinks(): Promise<Array<{ text: string; href: string }>> {
    const nav = this.page.getByRole('navigation');
    if (!(await nav.count())) return [];
    const anchors = nav.locator('a');
    const out: Array<{ text: string; href: string }> = [];
    const count = await anchors.count();
    for (let i = 0; i < count; i++) {
      const a = anchors.nth(i);
      const text = (await a.innerText()).trim();
      const href = (await a.getAttribute('href')) || '';
      out.push({ text, href });
    }
    return out;
  }

  async getAccountBalance() {
    // Try several selectors that might contain balance
    const balanceSelectors = [
      'text=/balance:\\s*[$€£]\\d+(\\.\\d{2})?/i',
      '[data-testid*="balance"]',
      '.balance',
      '#balance'
    ];
    for (const selector of balanceSelectors) {
      const el = this.page.locator(selector);
      if (await el.count()) {
        const text = await el.innerText();
        // Extract number from text
        const match = text.match(/[$€£]?\s*(\d+(\.\d{2})?)/);
        return match ? parseFloat(match[1]) : null;
      }
    }
    return null;
  }

  async getRecentTransactions() {
    // Look for a transactions list/table
    const txnSelectors = [
      '[data-testid*="transactions"]',
      'table:has-text("transactions")',
      '.transactions',
      '#transactions'
    ];
    for (const selector of txnSelectors) {
      const el = this.page.locator(selector);
      if (await el.count()) {
        // If it's a table, get rows
        const rows = el.locator('tr');
        if (await rows.count()) {
          return rows.all();
        }
        // If it's a list, get items
        const items = el.locator('li');
        if (await items.count()) {
          return items.all();
        }
      }
    }
    return [];
  }

  async logout() {
      // Try role=button with logout text
      const logoutBtn = this.page.getByRole('button', { name: /log ?out|sign ?out/i });
      if (await logoutBtn.count()) {
        await logoutBtn.click();
        return true;
      }

      // Try link with logout text
      const logoutLink = this.page.getByRole('link', { name: /log ?out|sign ?out/i });
      if (await logoutLink.count()) {
        await logoutLink.click();
        return true;
      }

      // Try text matching
      const logoutText = this.page.getByText(/log ?out|sign ?out/i);
      if (await logoutText.count()) {
        await logoutText.click();
        return true;
      }

      // Try other common selectors
      const otherSelectors = [
        '[data-testid*="logout"]',
        '.logout',
        '#logout',
        'button[type="button"]'
      ];
      for (const selector of otherSelectors) {
        const el = this.page.locator(selector);
        if (await el.count()) {
          await el.click();
          return true;
        }
      }

      return false;
  }
}
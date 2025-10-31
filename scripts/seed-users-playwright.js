#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const fixtures = path.join(__dirname, '..', 'tests', 'fixtures', 'users.json');
if (!fs.existsSync(fixtures)) {
  console.error('fixtures file not found:', fixtures);
  process.exit(1);
}

const users = JSON.parse(fs.readFileSync(fixtures, 'utf8')).users || [];
console.log(`Found ${users.length} users to seed via Playwright`);

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  const baseURL = process.env.BASE_URL || 'http://localhost:5001';

  for (const u of users.slice(0, 10)) {
    const username = u.username || (u.email || '').split('@')[0] || `user${Math.random().toString(36).slice(2,8)}`;
    const password = u.password || 'Password123!';

    try {
      const url = `${baseURL}/register`;
      console.log('Visiting', url);
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });

      // Fill form fields
      const emailInput = await page.$('input[name="email"]');
      const usernameInput = await page.$('input[name="username"]');
      const passwordInput = await page.$('input[name="password"]');
      const submitBtn = await page.$('button[type="submit"], button:has-text("Register"), input[type="submit"]');

      if (usernameInput) {
        await usernameInput.fill(username);
      } else if (emailInput) {
        // if only email field exists, use it
        await emailInput.fill(u.email || (username + '@example.com'));
      }
      if (passwordInput) await passwordInput.fill(password);

      // Wait for the registration POST response
      let response = null;
      page.once('response', (res) => {
        const req = res.request();
        if (req.method() === 'POST' && req.url().includes('/register')) {
          response = res;
        }
      });

      if (submitBtn) {
        await Promise.all([
          page.waitForTimeout(800),
          submitBtn.click().catch(()=>null)
        ]);
      } else {
        // try pressing enter on password input
        if (passwordInput) {
          await passwordInput.press('Enter').catch(()=>null);
        }
      }

      // Give it a moment to process
      await page.waitForTimeout(800);

      if (response) {
        console.log('Status', response.status(), 'for', username);
        const text = await response.text().catch(()=>null);
        if (text) console.log('  ->', text.slice(0,240).replace(/\n/g,' '));
      } else {
        // Try to determine success via navigation or by checking for an error message on the page
        const bodyText = await page.textContent('body');
        const snippet = (bodyText || '').slice(0,240).replace(/\n/g,' ');
        console.log('No direct register response captured. Page body snippet:', snippet);
      }

    } catch (e) {
      console.log('Error creating', u.email || u.username, e.message);
    }

    await page.waitForTimeout(300);
  }

  await browser.close();
  console.log('Playwright seeding done');
  process.exit(0);
})();

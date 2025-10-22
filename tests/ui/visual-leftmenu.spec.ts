import { test, expect } from '@playwright/test';
import { LoginPage } from './pages/loginPage';
import { DashboardPage } from './pages/dashboardPage';
import { findOrCreateUser } from '../utils/credentials';
import fs from 'fs';
import path from 'path';

/**
 * Visual Regression Tests
 * 
 * These tests verify that the application's visual elements remain consistent
 * across changes by comparing screenshots against baseline images.
 * 
 * Test Strategy:
 * 1. Authenticate with test user
 * 2. Navigate to dashboard
 * 3. Capture screenshot of navigation menu
 * 4. Compare against baseline image
 * 5. Save new baseline if missing
 * 
 * Expected Behavior:
 * - Navigation menu should be visible
 * - Visual elements should match baseline
 * - Screenshots should be consistent across runs
 */

const baselineDir = path.join(process.cwd(), 'tests', 'visual-baselines');
const baselineFile = path.join(baselineDir, 'left-menu.png');

/**
 * Test: Left menu visual regression
 * 
 * Purpose: Verifies that the left navigation menu maintains consistent
 * visual appearance across application changes.
 * 
 * Test Strategy:
 * 1. Authenticate with test user
 * 2. Navigate to dashboard
 * 3. Capture screenshot of navigation menu
 * 4. Compare against baseline or save new baseline
 * 5. Verify visual consistency
 */
test('left menu visual regression', async ({ page, baseURL }) => {
  if (!baseURL) throw new Error('baseURL is not defined');
  const user = findOrCreateUser('e2e');

  // Step 1: Authenticate with test user
  const login = new LoginPage(page);
  await login.goto(baseURL);
  const identifier = user.username || user.email;
  await login.fillEmail(identifier as string);
  await login.fillPassword(user.password);
  await login.submit();

  // Step 2: Navigate to dashboard and wait for load
  const dash = new DashboardPage(page);
  await dash.waitForLoad();

  // Step 3: Locate navigation menu and get bounding box
  const nav = page.getByRole('navigation');
  expect(await nav.count()).toBeGreaterThan(0);
  const clip = await nav.first().boundingBox();
  if (!clip) throw new Error('Could not determine nav bounding box');

  // Step 4: Ensure baseline directory exists
  if (!fs.existsSync(baselineDir)) fs.mkdirSync(baselineDir, { recursive: true });

  // Step 5: Capture screenshot of navigation menu
  const screenshotBuffer = await page.screenshot({ clip });
  if (!fs.existsSync(baselineFile)) {
    // Step 6: Save baseline if missing
    fs.writeFileSync(baselineFile, screenshotBuffer);
    test.info().attach('baseline-saved', { body: screenshotBuffer, contentType: 'image/png' });
    console.log('Saved baseline left-menu.png');
    return;
  }

  // Step 7: Compare against baseline image
  const baseline = fs.readFileSync(baselineFile);
  // Basic byte-compare (strict). For better diffs use pixelmatch.
  expect(screenshotBuffer.equals(baseline)).toBeTruthy();
});

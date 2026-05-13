import { Page } from '@playwright/test';

// Read a CSRF token from common meta tag locations.
export async function captureCsrfToken(page: Page): Promise<string | null> {
  return page.evaluate(() => {
    const meta = document.querySelector('meta[name="csrf-token"], meta[name="x-csrf-token"]');
    return meta?.getAttribute('content') || null;
  });
}

// Check whether the page exposes a CSRF token through meta tags or hidden fields.
export async function pageHasCsrfTokenField(page: Page): Promise<boolean> {
  return page.evaluate(() => {
    const meta = document.querySelector('meta[name="csrf-token"], meta[name="x-csrf-token"]');
    const input = document.querySelector('input[name="_csrf"], input[name="csrf_token"]');
    return !!meta || !!input;
  });
}

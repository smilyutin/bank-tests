/**
 * UI Selector Configuration
 * 
 * Customize these selectors to match your application's HTML structure.
 * Run `npm run discover:selectors` to automatically discover selectors.
 */

export const LOGIN_SELECTORS = {
  // Login page path
  loginPath: '/login',
  
  // Alternative login paths to try
  alternativePaths: ['/signin', '/auth', '/auth/login', '/auth/signin'],
  
  // Email/Username input selector
  // Try multiple selectors in order of preference
  // ✅ CONFIGURED FOR YOUR APP: Uses name="username"
  emailInput: [
    'input[name="username"]',      // ✅ Your app uses this
    'input[name="email"]',
    'input[type="email"]',
    'input[id="email"]',
    'input[id="username"]',
    'input[placeholder*="email" i]',
    'input[placeholder*="username" i]',
  ],
  
  // Password input selector
  // ✅ CONFIGURED FOR YOUR APP: Uses name="password"
  passwordInput: [
    'input[type="password"]',      // ✅ Your app uses this
    'input[name="password"]',      // ✅ Your app uses this
    'input[id="password"]',
  ],
  
  // Submit button selector
  // ✅ CONFIGURED FOR YOUR APP: Uses type="submit"
  submitButton: [
    'button[type="submit"]',       // ✅ Your app uses this
    'button:has-text("Login")',    // ✅ Your app uses this text
    'button:has-text("Sign in")',
    'button:has-text("Sign In")',
    'button:has-text("Log in")',
    'input[type="submit"]',
    'button[id*="login" i]',
    'button[id*="signin" i]',
  ],
  
  // Error message container selectors
  // ✅ CONFIGURED FOR YOUR APP: Uses #message
  errorMessage: [
    '#message',                    // ✅ Your app uses this
    '.error',
    '.alert',
    '.alert-danger',
    '.alert-error',
    '.error-message',
    '.message',
    '.notification',
    '[role="alert"]',
    '[aria-live="polite"]',
    '[aria-live="assertive"]',
    '#error',
    '#notification',
  ],
};

export const LOGOUT_SELECTORS = {
  // Logout page path
  logoutPath: '/logout',
  
  // Alternative logout paths
  alternativePaths: ['/signout', '/auth/logout', '/auth/signout'],
  
  // Logout button selector (if not a direct path)
  logoutButton: [
    'button:has-text("Logout")',
    'button:has-text("Log out")',
    'button:has-text("Sign out")',
    'a:has-text("Logout")',
    'a:has-text("Log out")',
    'a:has-text("Sign out")',
    'button[id*="logout" i]',
    'a[href*="logout"]',
  ],
};

/**
 * Helper function to try multiple selectors and return the first that exists
 */
export async function findFirstExisting(page: any, selectors: string[]): Promise<string | null> {
  for (const selector of selectors) {
    try {
      const count = await page.locator(selector).count();
      if (count > 0) {
        return selector;
      }
    } catch (e) {
      // Continue to next selector
    }
  }
  return null;
}

/**
 * Helper to get a locator with fallback selectors
 */
export async function getInputLocator(page: any, selectorList: string[]) {
  const selector = await findFirstExisting(page, selectorList);
  if (!selector) {
    return null;
  }
  return page.locator(selector).first();
}

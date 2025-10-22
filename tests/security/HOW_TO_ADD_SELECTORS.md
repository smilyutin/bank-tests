# 🎯 How to Add Selectors for New Pages

Quick guide for configuring tests for different HTML structures.

---

## 🚀 Quick Start (3 Steps)

### Step 1: Run Auto-Discovery

```bash
# Make sure your app is running on http://localhost:5001
npm start

# In another terminal, discover selectors
npm run discover:selectors
```

This will:
- ✅ Check `/login`, `/signin`, `/auth`, etc.
- ✅ Find all input fields and buttons
- ✅ Show recommended selectors
- ✅ Display them in your terminal

### Step 2: Copy to Config

Open `tests/security/selectors.config.ts` and update:

```typescript
export const LOGIN_SELECTORS = {
  loginPath: '/your-path',  // Change this
  
  emailInput: [
    'input[name="your-field"]',  // Add your selector here
    'input[name="email"]',       // Keep fallbacks
  ],
  
  // ... etc
};
```

### Step 3: Run Tests

```bash
npx playwright test tests/security/authentication/
```

Done! ✅

---

## 📋 Manual Configuration

If auto-discovery doesn't work, configure manually:

### 1. **Find Your Login Page**

Visit: `http://localhost:5001/login` (or your path)

### 2. **Inspect HTML**

Right-click on inputs → "Inspect Element"

### 3. **Identify Selectors**

Look for:
- `name` attribute: `<input name="username">`
- `id` attribute: `<input id="email-field">`
- `type` attribute: `<input type="email">`
- `class` attribute: `<input class="form-input">`
- `placeholder`: `<input placeholder="Enter email">`

### 4. **Add to Config**

```typescript
// Example based on your HTML
emailInput: [
  'input[name="username"]',     // Most specific
  'input[id="email"]',          // Alternative
  'input[type="email"]',        // Fallback
  'input[placeholder*="email" i]',  // Broad match
],
```

---

## 🎨 Selector Patterns

### For Input Fields

```typescript
// By name (most reliable)
'input[name="username"]'
'input[name="email"]'
'input[name="password"]'

// By type
'input[type="email"]'
'input[type="password"]'
'input[type="text"]'

// By ID
'input[id="email-input"]'
'input[id="username"]'

// By placeholder (case-insensitive)
'input[placeholder*="email" i]'
'input[placeholder*="username" i]'

// By class
'input.form-control'
'input.email-field'

// By aria-label
'input[aria-label="Email"]'
```

### For Buttons

```typescript
// By type (most reliable)
'button[type="submit"]'

// By text content
'button:has-text("Login")'
'button:has-text("Sign in")'
'button:has-text("Log in")'

// By ID
'button[id="login-btn"]'
'button[id="submit"]'

// By class
'button.btn-primary'
'button.login-button'

// Input submits
'input[type="submit"]'
'input[value="Login"]'
```

### For Error Messages

```typescript
// By ID
'#message'
'#error'
'#notification'

// By class
'.error'
'.alert'
'.alert-danger'
'.error-message'
'.notification'

// By role
'[role="alert"]'
'[aria-live="polite"]'
'[aria-live="assertive"]'

// By data attribute
'[data-error]'
'[data-message]'
```

---

## 🧪 Test Your Selectors

### Quick Console Test

Open browser console on login page:

```javascript
// Test if selector finds element
document.querySelector('input[name="username"]')  // Should return element
document.querySelectorAll('input[name="username"]').length  // Should return 1

// Test in Playwright
document.querySelectorAll('#message').length > 0
```

### In Playwright Test

```typescript
// Quick test
const element = await page.locator('input[name="username"]').count();
console.log('Found elements:', element);  // Should be > 0
```

---

## 📚 Common HTML Structures

### Standard HTML Form

```html
<form>
  <input name="email" type="email">
  <input name="password" type="password">
  <button type="submit">Login</button>
</form>
```

**Config:**
```typescript
emailInput: ['input[name="email"]'],
passwordInput: ['input[name="password"]'],
submitButton: ['button[type="submit"]'],
```

### Bootstrap Form

```html
<form>
  <input class="form-control" id="email" type="email">
  <input class="form-control" id="password" type="password">
  <button class="btn btn-primary" type="submit">Sign In</button>
</form>
```

**Config:**
```typescript
emailInput: ['input[id="email"]', 'input[type="email"]'],
passwordInput: ['input[id="password"]', 'input[type="password"]'],
submitButton: ['button[type="submit"]', 'button.btn-primary'],
```

### Material UI / React

```html
<form>
  <div class="MuiFormControl">
    <input id="email" aria-label="Email">
  </div>
  <div class="MuiFormControl">
    <input id="password" type="password" aria-label="Password">
  </div>
  <button class="MuiButton" type="submit">Login</button>
</form>
```

**Config:**
```typescript
emailInput: ['input[id="email"]', 'input[aria-label="Email"]'],
passwordInput: ['input[id="password"]', 'input[aria-label="Password"]'],
submitButton: ['button[type="submit"]', 'button.MuiButton'],
```

### Your App (Vulnerable Bank)

```html
<form id="loginForm">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Login</button>
</form>
<div id="message"></div>
```

**Config:** ✅ Already configured!
```typescript
emailInput: ['input[name="username"]'],  // ✅ 
passwordInput: ['input[name="password"]'],  // ✅
submitButton: ['button[type="submit"]'],  // ✅
errorMessage: ['#message'],  // ✅
```

---

## 🔧 Troubleshooting

### Problem: "Login form not found"

**Solution:**
1. Check if page loads: `http://localhost:5001/login`
2. Verify selectors in browser console
3. Run discovery tool: `npm run discover:selectors`
4. Add console log to debug:
   ```typescript
   const count = await page.locator('input[name="email"]').count();
   console.log('Email inputs found:', count);
   ```

### Problem: "Element not found"

**Solution:**
1. Check if element exists in HTML
2. Try more specific selector
3. Add multiple fallback selectors
4. Wait for page load:
   ```typescript
   await page.waitForLoadState('domcontentloaded');
   ```

### Problem: "Wrong element selected"

**Solution:**
1. Use `.first()` for multiple matches
2. Be more specific with selector
3. Combine selectors:
   ```typescript
   'form#loginForm input[name="username"]'
   ```

---

## ✅ Best Practices

### 1. **Order Selectors by Specificity**

```typescript
emailInput: [
  'input[name="username"]',     // ✅ Most specific (your app)
  'input[name="email"]',        // Fallback option 1
  'input[type="email"]',        // Fallback option 2
  'input[placeholder*="email" i]',  // Broad match
],
```

### 2. **Include Comments**

```typescript
emailInput: [
  'input[name="username"]',  // ✅ YOUR APP uses this
  'input[name="email"]',     // Standard fallback
],
```

### 3. **Keep Fallbacks**

Don't remove all fallbacks - they help tests work with different apps:

```typescript
// ❌ Bad - only one selector
emailInput: ['input[name="myCustomName"]'],

// ✅ Good - multiple options
emailInput: [
  'input[name="myCustomName"]',  // Your app
  'input[name="email"]',         // Standard
  'input[type="email"]',         // Fallback
],
```

### 4. **Test After Changes**

```bash
npx playwright test tests/security/authentication/ui-login-generic-errors.spec.ts --reporter=list
```

---

## 📖 Examples

### Example 1: Different Username Field

Your HTML:
```html
<input id="user-email" type="text">
```

Update config:
```typescript
emailInput: [
  'input[id="user-email"]',  // Add this
  'input[name="email"]',
  'input[type="email"]',
],
```

### Example 2: Different Submit Button

Your HTML:
```html
<button class="btn-login" onclick="submitForm()">Sign In</button>
```

Update config:
```typescript
submitButton: [
  'button.btn-login',           // Add this
  'button:has-text("Sign In")', // Add this
  'button[type="submit"]',
],
```

### Example 3: Different Error Container

Your HTML:
```html
<div class="error-toast" id="login-error"></div>
```

Update config:
```typescript
errorMessage: [
  '#login-error',        // Add this
  '.error-toast',        // Add this
  '#message',
  '.error',
],
```

---

## 🎓 Summary

1. **Run auto-discovery:** `npm run discover:selectors`
2. **Update config:** `tests/security/selectors.config.ts`
3. **Test it:** `npx playwright test tests/security/authentication/`
4. **Commit:** Working selectors for your app!

---

**💡 Pro Tip:** Always keep fallback selectors - they make tests work across different applications!

**📝 Need help?** Check `SELECTOR_FIX_SUMMARY.md` for more details.

import { chromium } from '@playwright/test';

/**
 * Selector Discovery Script
 * 
 * This script helps you discover the correct selectors for your login page.
 * Run it to see what inputs and buttons exist on your login page.
 */

async function discoverLoginSelectors() {
  const browser = await chromium.launch({ headless: false });
  const page = await browser.newPage();
  
  const baseURL = process.env.BASE_URL || 'http://localhost:5001';
  const loginPaths = ['/login', '/signin', '/auth', '/auth/login', '/auth/signin', '/'];
  
  console.log('🔍 Checking login pages...\n');
  
  for (const path of loginPaths) {
    try {
      console.log(`\n📄 Checking ${baseURL}${path}...`);
      const response = await page.goto(`${baseURL}${path}`, { 
        timeout: 5000, 
        waitUntil: 'domcontentloaded' 
      });
      
      if (!response || response.status() !== 200) {
        console.log(`   ⏭️  Skipped (status ${response?.status()})`);
        continue;
      }
      
      console.log(`   ✅ Page found!\n`);
      
      // Find all input fields
      const inputs = await page.evaluate(() => {
        const allInputs = Array.from(document.querySelectorAll('input'));
        return allInputs.map(input => ({
          type: input.type,
          name: input.name,
          id: input.id,
          placeholder: input.placeholder,
          class: input.className,
          ariaLabel: input.getAttribute('aria-label'),
          selector: [
            input.name ? `input[name="${input.name}"]` : null,
            input.id ? `input[id="${input.id}"]` : null,
            input.type ? `input[type="${input.type}"]` : null,
          ].filter(Boolean).join(' OR ')
        }));
      });
      
      if (inputs.length > 0) {
        console.log('   📝 Input Fields Found:');
        inputs.forEach((input, i) => {
          console.log(`\n   ${i + 1}. Type: ${input.type}`);
          if (input.name) console.log(`      name="${input.name}"`);
          if (input.id) console.log(`      id="${input.id}"`);
          if (input.placeholder) console.log(`      placeholder="${input.placeholder}"`);
          if (input.class) console.log(`      class="${input.class}"`);
          if (input.ariaLabel) console.log(`      aria-label="${input.ariaLabel}"`);
          console.log(`      ✅ Selector: ${input.selector}`);
        });
      }
      
      // Find all buttons
      const buttons = await page.evaluate(() => {
        const allButtons = Array.from(document.querySelectorAll('button, input[type="submit"]'));
        return allButtons.map(button => ({
          type: button.getAttribute('type') || 'button',
          text: button.textContent?.trim(),
          id: button.id,
          class: button.className,
          selector: [
            button.id ? `button[id="${button.id}"]` : null,
            button.getAttribute('type') ? `button[type="${button.getAttribute('type')}"]` : null,
            button.textContent?.trim() ? `text="${button.textContent.trim()}"` : null,
          ].filter(Boolean).join(' OR ')
        }));
      });
      
      if (buttons.length > 0) {
        console.log('\n   🔘 Buttons Found:');
        buttons.forEach((button, i) => {
          console.log(`\n   ${i + 1}. Type: ${button.type}`);
          if (button.text) console.log(`      text="${button.text}"`);
          if (button.id) console.log(`      id="${button.id}"`);
          if (button.class) console.log(`      class="${button.class}"`);
          console.log(`      ✅ Selector: ${button.selector}`);
        });
      }
      
      // Find error message containers
      const errorContainers = await page.evaluate(() => {
        const selectors = [
          '.error', '.alert', '.message', '.notification',
          '[role="alert"]', '[aria-live="polite"]', '[aria-live="assertive"]',
          '.error-message', '.alert-danger', '.alert-error',
          '#error', '#message', '#notification'
        ];
        
        const found: string[] = [];
        selectors.forEach(sel => {
          const elements = document.querySelectorAll(sel);
          if (elements.length > 0) {
            found.push(`${sel} (${elements.length} elements)`);
          }
        });
        return found;
      });
      
      if (errorContainers.length > 0) {
        console.log('\n   ⚠️  Error/Message Containers Found:');
        errorContainers.forEach(container => {
          console.log(`      - ${container}`);
        });
      }
      
      // Generate recommended selectors
      console.log('\n   📋 RECOMMENDED SELECTORS FOR TESTS:\n');
      
      const emailInput = inputs.find(i => 
        i.type === 'email' || 
        i.name?.toLowerCase().includes('email') ||
        i.id?.toLowerCase().includes('email') ||
        i.placeholder?.toLowerCase().includes('email')
      );
      
      const passwordInput = inputs.find(i => i.type === 'password');
      const submitButton = buttons.find(b => b.type === 'submit' || b.text?.toLowerCase().includes('login') || b.text?.toLowerCase().includes('sign in'));
      
      if (emailInput) {
        console.log(`   Email Input: page.locator('${emailInput.selector.split(' OR ')[0]}')`);
      }
      if (passwordInput) {
        console.log(`   Password Input: page.locator('${passwordInput.selector.split(' OR ')[0]}')`);
      }
      if (submitButton) {
        console.log(`   Submit Button: page.locator('${submitButton.selector.split(' OR ')[0]}')`);
      }
      
      if (errorContainers.length > 0) {
        console.log(`   Error Message: page.locator('${errorContainers[0].split(' (')[0]}')`);
      }
      
      console.log('\n   ✨ LOGIN PAGE FOUND! Use these selectors in your tests.\n');
      
      // Wait for user to inspect
      console.log('   Press Ctrl+C to exit...');
      await page.waitForTimeout(60000);
      break;
      
    } catch (e) {
      console.log(`   ⏭️  Skipped (${e})`);
    }
  }
  
  await browser.close();
}

discoverLoginSelectors().catch(console.error);

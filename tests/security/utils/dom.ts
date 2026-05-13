import { Page } from '@playwright/test';

type ElementSnapshot = {
  tagName: string;
  src: string | null;
  href: string | null;
  integrity: string | null;
  crossorigin: string | null;
  name: string | null;
  content: string | null;
  value: string | null;
  async: boolean;
  defer: boolean;
};

// Capture a lightweight snapshot of matching DOM elements.
export async function queryElements(page: Page, selector: string): Promise<ElementSnapshot[]> {
  return page.evaluate((sel) => {
    return Array.from(document.querySelectorAll(sel)).map((el) => ({
      tagName: el.tagName,
      src: el.getAttribute('src'),
      href: el.getAttribute('href'),
      integrity: el.getAttribute('integrity'),
      crossorigin: el.getAttribute('crossorigin'),
      name: el.getAttribute('name'),
      content: el.getAttribute('content'),
      value: el.getAttribute('value'),
      async: el.hasAttribute('async'),
      defer: el.hasAttribute('defer'),
    }));
  }, selector);
}

// Read the content attribute from a matching meta tag.
export async function getMetaContent(page: Page, selector: string): Promise<string | null> {
  return page.evaluate((sel) => {
    const meta = document.querySelector(sel);
    return meta?.getAttribute('content') || null;
  }, selector);
}

// Check whether any selector in the list exists on the page.
export async function pageHasAnySelector(page: Page, selectors: string[]): Promise<boolean> {
  return page.evaluate((sels) => sels.some((sel) => document.querySelector(sel) !== null), selectors);
}

// Check whether the page body contains any of the provided text terms.
export async function pageBodyContainsAnyText(page: Page, terms: string[]): Promise<boolean> {
  return page.evaluate((needles) => {
    const body = document.body?.innerHTML?.toLowerCase() || '';
    return needles.some((needle) => body.includes(needle.toLowerCase()));
  }, terms);
}

// Collect inline event handlers for security inspection.
export async function getInlineEventHandlers(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const elements = Array.from(document.querySelectorAll('*'));
    const handlers: string[] = [];

    elements.forEach((el) => {
      const attrs = Array.from(el.attributes);
      attrs.forEach((attr) => {
        if (attr.name.startsWith('on') && (attr.value || '').trim().length > 0) {
          handlers.push(`${el.tagName}.${attr.name}="${(attr.value || '').trim().slice(0, 80)}"`);
        }
      });
    });

    return Array.from(new Set(handlers)).slice(0, 10);
  });
}

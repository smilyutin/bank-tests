/**
 * Test User Management
 * 
 * Loads pre-configured test users from fixtures/users.json
 * Use these instead of creating random users for faster, more reliable tests.
 */

import * as fs from 'fs';
import * as path from 'path';

interface TestUser {
  username?: string;
  email: string;
  password: string;
}

interface UsersFixture {
  users: TestUser[];
}

let cachedUsers: TestUser[] | null = null;

/**
 * Load test users from fixtures/users.json
 */
export function loadTestUsers(): TestUser[] {
  if (cachedUsers) {
    return cachedUsers;
  }

  const fixturePath = path.join(__dirname, '../fixtures/users.json');
  
  try {
    const fileContent = fs.readFileSync(fixturePath, 'utf-8');
    const fixture: UsersFixture = JSON.parse(fileContent);
    cachedUsers = fixture.users;
    return cachedUsers;
  } catch (e) {
    console.warn('Could not load users.json:', e);
    // Fallback to default test user
    return [{
      email: 'test@example.com',
      password: 'Password123!'
    }];
  }
}

/**
 * Get a random test user from the fixture
 */
export function getRandomTestUser(): TestUser {
  const users = loadTestUsers();
  const randomIndex = Math.floor(Math.random() * users.length);
  return users[randomIndex];
}

/**
 * Get a test user with username (for apps that use username instead of email)
 */
export function getTestUserWithUsername(): TestUser {
  const users = loadTestUsers();
  const userWithUsername = users.find(u => u.username);
  
  if (userWithUsername) {
    return userWithUsername;
  }
  
  // Fallback to first user
  return users[0];
}

/**
 * Get test user by index (deterministic)
 */
export function getTestUser(index: number = 0): TestUser {
  const users = loadTestUsers();
  return users[index % users.length];
}

/**
 * Get multiple unique test users
 */
export function getTestUsers(count: number): TestUser[] {
  const users = loadTestUsers();
  return users.slice(0, Math.min(count, users.length));
}

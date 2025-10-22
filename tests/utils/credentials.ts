import fs from 'fs';
import path from 'path';

const filePath = path.join(__dirname, '..', 'fixtures', 'users.json');

export type User = { username?: string; email?: string; password: string };

export function loadUsers(): User[] {
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    const json = JSON.parse(raw);
    return json.users || [];
  } catch (e) {
    return [];
  }
}

export function saveUser(user: User) {
  const users = loadUsers();
  // avoid duplicates by email or username
  const exists = users.find(u => (u.email && user.email && u.email === user.email) || (u.username && user.username && u.username === user.username));
  if (exists) return;
  users.push(user);
  fs.writeFileSync(filePath, JSON.stringify({ users }, null, 2), 'utf-8');
}

export function findOrCreateUser(pref = 'e2e'): User {
  const users = loadUsers();
  if (users.length > 0) return users[0];
  const random = Math.random().toString(36).substring(2, 8);
  const username = `${pref}${random}`;
  const email = `${pref}+${random}@example.com`;
  const user: User = { username, email, password: 'Password123!' };
  saveUser(user);
  return user;
}

// Create a new random user and optionally persist it. Always returns a new user.
export function createRandomUser(pref = 'e2e', persist = true): User {
  const random = Math.random().toString(36).substring(2, 10);
  const username = `${pref}${random}`;
  const email = `${pref}+${random}@example.com`;
  const user: User = { username, email, password: 'Password123!' };
  if (persist) saveUser(user);
  return user;
}

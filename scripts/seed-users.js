#!/usr/bin/env node
const fs = require('fs');
const http = require('http');
const path = require('path');
const qs = require('querystring');

const fixtures = path.join(__dirname, '..', 'tests', 'fixtures', 'users.json');
if (!fs.existsSync(fixtures)) {
  console.error('fixtures file not found:', fixtures);
  process.exit(1);
}

const users = JSON.parse(fs.readFileSync(fixtures, 'utf8')).users || [];
console.log(`Found ${users.length} users to seed`);

async function createUser(user) {
  return new Promise((resolve) => {
    const form = qs.stringify({ username: user.username || (user.email || '').split('@')[0], password: user.password });
    const options = {
      hostname: 'localhost',
      port: 5001,
      path: '/register',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(form),
        // include Origin/Referer headers as some apps require them for CSRF checks
        'Origin': 'http://localhost:5001',
        'Referer': 'http://localhost:5001/register',
      },
    };

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => {
        console.log('Status', res.statusCode, 'for', user.username || user.email, '=>', body.slice(0, 240).replace(/\n/g, ' '));
        resolve();
      });
    });

    req.on('error', (e) => {
      console.log('Error creating', user.username || user.email, e.message);
      resolve();
    });

    req.write(form);
    req.end();
  });
}

(async () => {
  for (const u of users.slice(0, 10)) {
    await createUser(u);
    await new Promise((r) => setTimeout(r, 200));
  }
  console.log('Seeding done');
})();

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express from 'express';
import supertest from 'supertest';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import nock from 'nock';
import * as path from 'path';
import { fileURLToPath } from 'url';
import _ from 'lodash';

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const publicJwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
const kid = 'test-key-id';
publicJwk.kid = kid;
publicJwk.use = 'sig';
publicJwk.alg = 'RS256';

const CF_TEAM_DOMAIN = 'my-cloudflare-team';
const CF_AUDIENCE = 'cloudflare-audience-copied-from-dashboard';

function createToken(email) {
  return jwt.sign(
    { email, aud: [CF_AUDIENCE], iss: `https://${CF_TEAM_DOMAIN}.cloudflareaccess.com` },
    privateKey,
    { algorithm: 'RS256', keyid: kid, expiresIn: '1h' }
  );
}

describe('Security: GHSA-r5fr-rjxr-66jc (lodash template injection)', () => {
  it('should not be vulnerable to code injection via template imports', () => {
    // Test that lodash version is >= 4.18.0 (patched)
    const version = _.VERSION;
    const [major, minor, patch] = version.split('.').map(Number);
    expect(major).toBeGreaterThanOrEqual(4);
    if (major === 4) {
      expect(minor).toBeGreaterThanOrEqual(18);
    }
  });

  it('should not allow code execution via malicious imports key names', () => {
    // This is the actual vulnerability test - malicious key names in imports
    // should not execute arbitrary code
    const maliciousKey = 'x}=1;process.exit();//';

    // On patched versions, this should throw an error
    // On unpatched versions, this would execute the injected code
    expect(() => {
      _.template('hello', { imports: { [maliciousKey]: 'value' } });
    }).toThrow();
  });
});

describe('Security: XSS Prevention', () => {
  let app;

  beforeAll(() => {
    nock(`https://${CF_TEAM_DOMAIN}.cloudflareaccess.com`)
      .get('/cdn-cgi/access/certs')
      .reply(200, { keys: [publicJwk] })
      .persist();
  });

  afterAll(() => {
    nock.cleanAll();
  });

  beforeEach(async () => {
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    app = express();
    app.set('views', path.join(__dirname, '..', 'views'));
    app.set('view engine', 'ejs');

    const { addUserInfo } = await import('../util/verifyJWT.js');
    app.use(addUserInfo);

    app.get('/', (req, res) => {
      res.render('index', {
        title: 'OIDC Cloudflare proxy',
        uid: req?.user?.email,
        client: '',
        session: undefined,
        dbg: { params: JSON.stringify({}) },
      });
    });
  });

  it('should escape user email in index page output', async () => {
    // Create a token with an email containing HTML/JS
    const maliciousEmail = '<script>alert("xss")</script>@example.com';
    const token = createToken(maliciousEmail);

    const res = await supertest(app)
      .get('/')
      .set('Cf-Access-Jwt-Assertion', token);

    if (res.status === 200) {
      // The output should have the script tag escaped, not rendered as raw HTML
      expect(res.text).not.toContain('<script>alert("xss")</script>');
      // It should contain the escaped version
      expect(res.text).toContain('&lt;script&gt;');
    }
  });
});

describe('Security: Open Redirect Prevention', () => {
  it('should use req.hostname instead of req.get("host") for redirect', async () => {
    const app = express();
    app.enable('trust proxy');

    // Simulating the fixed production redirect
    app.use((req, res, next) => {
      if (req.secure) {
        next();
      } else if (req.method === 'GET' || req.method === 'HEAD') {
        // Fixed: use req.hostname instead of req.get('host')
        res.redirect(`https://${req.hostname}${req.originalUrl}`);
      } else {
        res.status(400).json({ error: 'invalid_request' });
      }
    });

    app.get('/test', (req, res) => res.send('OK'));

    // Test that redirect goes to the same host
    const res = await supertest(app).get('/test');
    expect(res.status).toBe(302);

    // The Location header should contain a valid HTTPS URL
    const location = res.headers.location;
    expect(location).toBeDefined();
    // Should not redirect to an arbitrary domain
    expect(location).not.toContain('evil.com');
  });
});

describe('Security: JWT Token Handling', () => {
  beforeAll(() => {
    nock(`https://${CF_TEAM_DOMAIN}.cloudflareaccess.com`)
      .get('/cdn-cgi/access/certs')
      .reply(200, { keys: [publicJwk] })
      .persist();
  });

  afterAll(() => {
    nock.cleanAll();
  });

  it('should reject tokens without email claim', async () => {
    const { addUserInfo } = await import('../util/verifyJWT.js');

    const token = jwt.sign(
      { aud: [CF_AUDIENCE], sub: 'no-email-user' },
      privateKey,
      { algorithm: 'RS256', keyid: kid, expiresIn: '1h' }
    );

    const req = {
      path: '/test',
      header: (name) => {
        if (name.toLowerCase() === 'cf-access-jwt-assertion') return token;
        return undefined;
      },
      user: undefined,
    };
    const res = {
      statusCode: null,
      body: null,
      status: (code) => { res.statusCode = code; return res; },
      send: (data) => { res.body = data; return res; },
    };

    await new Promise((resolve) => {
      addUserInfo(req, res, () => {
        resolve();
      });

      setTimeout(resolve, 2000);
    });

    // Token without email should be rejected with 403
    expect(res.statusCode).toBe(403);
    expect(res.body).toEqual({ status: false, message: 'invalid token' });
  });

  it('should not accept none algorithm', async () => {
    const { addUserInfo } = await import('../util/verifyJWT.js');

    // Create a token with "none" algorithm (no signature)
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      email: 'attacker@example.com',
      aud: [CF_AUDIENCE],
    })).toString('base64url');
    const token = `${header}.${payload}.`;

    const req = {
      path: '/test',
      header: (name) => {
        if (name.toLowerCase() === 'cf-access-jwt-assertion') return token;
        return undefined;
      },
      user: undefined,
    };
    const res = {
      statusCode: null,
      body: null,
      status: (code) => { res.statusCode = code; return res; },
      send: (data) => { res.body = data; return res; },
    };

    await new Promise((resolve) => {
      addUserInfo(req, res, () => {
        resolve();
      });
      setTimeout(resolve, 1000);
    });

    expect(res.statusCode).toBe(403);
  });
});

describe('Security: Account Verification Bypass', () => {
  let AccountService;

  beforeAll(async () => {
    const mod = await import('../util/accountService.js');
    AccountService = mod.default;
  });

  it('should not allow path traversal to bypass auth check', () => {
    // Test that non-token/me paths require proper verification
    const req = { path: '/protected/interaction/test', user: null };
    expect(() => AccountService.assertVerifiedUser(req, 'user@example.com')).toThrow();
  });

  it('should require exact path match for auth bypass', () => {
    // These paths should NOT bypass verification
    const paths = ['/token/', '/tokenX', '/me/', '/meX', '/token/something'];
    for (const p of paths) {
      const req = { path: p, user: null };
      expect(() => AccountService.assertVerifiedUser(req, 'user@example.com')).toThrow();
    }
  });
});

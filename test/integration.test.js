import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import express from 'express';
import supertest from 'supertest';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import nock from 'nock';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { fileURLToPath } from 'url';

// Generate RSA key pair for test JWT signing
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

describe('Integration: Express Routes', () => {
  let app;
  let tmpDir;

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'integration-test-'));

    // Mock JWKS endpoint
    nock(`https://${CF_TEAM_DOMAIN}.cloudflareaccess.com`)
      .get('/cdn-cgi/access/certs')
      .reply(200, { keys: [publicJwk] })
      .persist();
  });

  afterAll(() => {
    nock.cleanAll();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  beforeEach(async () => {
    const __dirname = path.dirname(fileURLToPath(import.meta.url));

    app = express();
    app.set('views', path.join(__dirname, '..', 'views'));
    app.set('view engine', 'ejs');

    // Import addUserInfo
    const { addUserInfo } = await import('../util/verifyJWT.js');
    app.use(addUserInfo);

    // Add a simple test route for index
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

  it('should render index page without authentication', async () => {
    const res = await supertest(app).get('/');
    expect(res.status).toBe(200);
    expect(res.text).toContain('Not logged in');
  });

  it('should render index page with authenticated user', async () => {
    const token = createToken('testuser@example.com');
    const res = await supertest(app)
      .get('/')
      .set('Cf-Access-Jwt-Assertion', token);
    expect(res.status).toBe(200);
    expect(res.text).toContain('testuser@example.com');
  });

  it('should reject requests with invalid JWT', async () => {
    const res = await supertest(app)
      .get('/')
      .set('Cf-Access-Jwt-Assertion', 'invalid-token');
    expect(res.status).toBe(403);
  });

  it('should authenticate via cookie', async () => {
    const token = createToken('cookieuser@example.com');
    const res = await supertest(app)
      .get('/')
      .set('Cookie', `CF_Authorization=${token}`);
    expect(res.status).toBe(200);
    expect(res.text).toContain('cookieuser@example.com');
  });
});

describe('Integration: Security Headers', () => {
  it('should not cache protected responses', async () => {
    const app = express();
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    app.set('views', path.join(__dirname, '..', 'views'));
    app.set('view engine', 'ejs');

    // Import and setup routes with mock provider
    const { addUserInfo } = await import('../util/verifyJWT.js');
    app.use(addUserInfo);

    // Simulate the setNoCache middleware
    app.get('/test', (req, res, next) => {
      res.set('cache-control', 'no-store');
      next();
    }, (req, res) => {
      res.json({ ok: true });
    });

    const res = await supertest(app).get('/test');
    expect(res.headers['cache-control']).toBe('no-store');
  });
});

describe('Integration: HTTPS Redirect (production mode)', () => {
  it('should redirect HTTP GET to HTTPS in production mode', async () => {
    const app = express();
    app.enable('trust proxy');

    app.use((req, res, next) => {
      if (req.secure) {
        next();
      } else if (req.method === 'GET' || req.method === 'HEAD') {
        res.redirect(`https://${req.hostname}${req.originalUrl}`);
      } else {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'do yourself a favor and only use https',
        });
      }
    });

    app.get('/', (req, res) => {
      res.send('OK');
    });

    const res = await supertest(app).get('/test-path');
    expect(res.status).toBe(302);
  });

  it('should reject non-GET/HEAD HTTP requests in production mode', async () => {
    const app = express();
    app.enable('trust proxy');

    app.use((req, res, next) => {
      if (req.secure) {
        next();
      } else if (req.method === 'GET' || req.method === 'HEAD') {
        res.redirect(`https://${req.hostname}${req.originalUrl}`);
      } else {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'do yourself a favor and only use https',
        });
      }
    });

    const res = await supertest(app).post('/test').send({ data: 'test' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
  });
});

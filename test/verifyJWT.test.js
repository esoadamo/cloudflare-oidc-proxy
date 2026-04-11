import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import nock from 'nock';

// Generate RSA key pair for test JWT signing
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Convert to JWK for JWKS endpoint mock
const publicJwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
const kid = 'test-key-id';
publicJwk.kid = kid;
publicJwk.use = 'sig';
publicJwk.alg = 'RS256';

const CF_TEAM_DOMAIN = 'my-cloudflare-team';
const CF_AUDIENCE = 'cloudflare-audience-copied-from-dashboard';

function createToken(payload, options = {}) {
  return jwt.sign(payload, privateKey, {
    algorithm: 'RS256',
    keyid: kid,
    ...options,
  });
}

function createMockReq(token, cookieToken) {
  const headers = {};
  if (token) headers['cf-access-jwt-assertion'] = token;
  if (cookieToken) headers['cookie'] = `CF_Authorization=${cookieToken}`;

  return {
    path: '/protected/test',
    header: (name) => headers[name.toLowerCase()] || headers[name] || undefined,
    user: undefined,
  };
}

function createMockRes() {
  const res = {
    statusCode: null,
    body: null,
    status: (code) => { res.statusCode = code; return res; },
    send: (data) => { res.body = data; return res; },
  };
  return res;
}

function runMiddleware(addUserInfo, req, res) {
  return new Promise((resolve) => {
    addUserInfo(req, res, () => resolve('next'));
    // For error/rejection cases, the middleware responds directly
    // and never calls next(). Use a timeout to detect that.
    setTimeout(() => resolve('timeout'), 2000);
  });
}

describe('JWT Verification (verifyJWT)', () => {
  let addUserInfo;

  beforeEach(async () => {
    // Mock the JWKS endpoint for every test
    nock(`https://${CF_TEAM_DOMAIN}.cloudflareaccess.com`)
      .get('/cdn-cgi/access/certs')
      .reply(200, { keys: [publicJwk] })
      .persist();

    // Fresh import to get the module with mocked config
    const module = await import('../util/verifyJWT.js');
    addUserInfo = module.addUserInfo;
  });

  afterEach(() => {
    nock.cleanAll();
  });

  it('should set user to null when no token is provided', async () => {
    const req = createMockReq(null);
    const res = createMockRes();

    const result = await runMiddleware(addUserInfo, req, res);
    expect(result).toBe('next');
    expect(req.user).toBeNull();
  });

  it('should verify valid JWT from header', async () => {
    const token = createToken({
      email: 'user@example.com',
      aud: [CF_AUDIENCE],
      iss: `https://${CF_TEAM_DOMAIN}.cloudflareaccess.com`,
    });

    const req = createMockReq(token);
    const res = createMockRes();

    const result = await runMiddleware(addUserInfo, req, res);
    expect(result).toBe('next');
    expect(req.user).toBeDefined();
    expect(req.user.email).toBe('user@example.com');
  });

  it('should verify valid JWT from cookie', async () => {
    const token = createToken({
      email: 'cookie-user@example.com',
      aud: [CF_AUDIENCE],
      iss: `https://${CF_TEAM_DOMAIN}.cloudflareaccess.com`,
    });

    const req = createMockReq(null, token);
    const res = createMockRes();

    const result = await runMiddleware(addUserInfo, req, res);
    expect(result).toBe('next');
    expect(req.user).toBeDefined();
    expect(req.user.email).toBe('cookie-user@example.com');
  });

  it('should reject invalid JWT', async () => {
    const req = createMockReq('invalid-token-value');
    const res = createMockRes();

    const result = await runMiddleware(addUserInfo, req, res);
    expect(result).toBe('timeout');
    expect(res.statusCode).toBe(403);
    expect(res.body).toEqual({ status: false, message: 'invalid token' });
  });

  it('should reject JWT signed with wrong key', async () => {
    const { privateKey: wrongKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });

    const token = jwt.sign(
      { email: 'attacker@example.com', aud: [CF_AUDIENCE] },
      wrongKey,
      { algorithm: 'RS256', keyid: kid }
    );

    const req = createMockReq(token);
    const res = createMockRes();

    const result = await runMiddleware(addUserInfo, req, res);
    expect(result).toBe('timeout');
    expect(res.statusCode).toBe(403);
  });

  it('should reject expired JWT', async () => {
    const token = createToken(
      { email: 'expired@example.com', aud: [CF_AUDIENCE] },
      { expiresIn: -10 }
    );

    const req = createMockReq(token);
    const res = createMockRes();

    const result = await runMiddleware(addUserInfo, req, res);
    expect(result).toBe('timeout');
    expect(res.statusCode).toBe(403);
  });

  it('should reject JWT with wrong audience', async () => {
    const token = createToken({
      email: 'user@example.com',
      aud: ['wrong-audience'],
    });

    const req = createMockReq(token);
    const res = createMockRes();

    const result = await runMiddleware(addUserInfo, req, res);
    expect(result).toBe('timeout');
    expect(res.statusCode).toBe(403);
  });

  it('should prefer header token over cookie token', async () => {
    const headerToken = createToken({
      email: 'header@example.com',
      aud: [CF_AUDIENCE],
    });
    const cookieToken = createToken({
      email: 'cookie@example.com',
      aud: [CF_AUDIENCE],
    });

    const req = createMockReq(headerToken, cookieToken);
    const res = createMockRes();

    const result = await runMiddleware(addUserInfo, req, res);
    expect(result).toBe('next');
    expect(req.user.email).toBe('header@example.com');
  });
});

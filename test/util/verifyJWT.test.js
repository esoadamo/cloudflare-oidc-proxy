import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { client, addUserInfo, addUserInfoPromise } from '../../util/verifyJWT.js';
import { MAIN_CONFIG } from '../../config/main.js';

describe('verifyJWT Middleware Unit Tests', () => {
    let originalGetSigningKey;
    let publicKey;
    let privateKey;

    beforeEach(() => {
        originalGetSigningKey = client.getSigningKey;
        // Generate test keys
        const keys = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
        });
        publicKey = keys.publicKey;
        privateKey = keys.privateKey;

        // Mock getSigningKey to return our test public key
        client.getSigningKey = (kid, cb) => {
            cb(null, {
                getPublicKey: () => publicKey
            });
        };
    });

    afterEach(() => {
        client.getSigningKey = originalGetSigningKey;
    });

    test('should set req.user = null when no token is present', (t) => {
        const req = {
            header: (name) => null
        };
        const res = {};
        let nextCalled = false;
        const next = () => { nextCalled = true; };

        addUserInfo(req, res, next);

        assert.strictEqual(req.user, null);
        assert.ok(nextCalled);
    });

    test('should verify valid token in Cf-Access-Jwt-Assertion header', (t) => {
        const token = jwt.sign(
            { email: 'adam@hlavacek.win' },
            privateKey,
            { algorithm: 'RS256', audience: MAIN_CONFIG.cf_audience }
        );

        const req = {
            header: (name) => {
                if (name === 'Cf-Access-Jwt-Assertion') return token;
                return null;
            }
        };
        const res = {};
        let nextCalled = false;
        const next = () => { nextCalled = true; };

        addUserInfo(req, res, next);

        assert.deepEqual(req.user, { email: 'adam@hlavacek.win' });
        assert.ok(nextCalled);
    });

    test('should verify valid token in CF_Authorization cookie', (t) => {
        const token = jwt.sign(
            { email: 'adam@hlavacek.win' },
            privateKey,
            { algorithm: 'RS256', audience: MAIN_CONFIG.cf_audience }
        );

        const req = {
            header: (name) => {
                if (name === 'Cookie') return `CF_Authorization=${token}`;
                return null;
            }
        };
        const res = {};
        let nextCalled = false;
        const next = () => { nextCalled = true; };

        addUserInfo(req, res, next);

        assert.deepEqual(req.user, { email: 'adam@hlavacek.win' });
        assert.ok(nextCalled);
    });

    test('should return 403 on invalid token signature', (t) => {
        // Sign with a different private key (simulated invalid signature)
        const keys2 = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
        });
        const token = jwt.sign(
            { email: 'adam@hlavacek.win' },
            keys2.privateKey,
            { algorithm: 'RS256', audience: MAIN_CONFIG.cf_audience }
        );

        const req = {
            header: (name) => {
                if (name === 'Cf-Access-Jwt-Assertion') return token;
                return null;
            }
        };

        let statusResponse;
        const res = {
            status: (code) => {
                statusResponse = code;
                return {
                    send: (body) => body
                };
            }
        };

        let nextCalled = false;
        const next = () => { nextCalled = true; };

        addUserInfo(req, res, next);

        assert.strictEqual(statusResponse, 403);
        assert.strictEqual(nextCalled, false);
    });

    test('should return 403 on token with incorrect audience', (t) => {
        const token = jwt.sign(
            { email: 'adam@hlavacek.win' },
            privateKey,
            { algorithm: 'RS256', audience: 'wrong-audience' }
        );

        const req = {
            header: (name) => {
                if (name === 'Cf-Access-Jwt-Assertion') return token;
                return null;
            }
        };

        let statusResponse;
        const res = {
            status: (code) => {
                statusResponse = code;
                return {
                    send: (body) => body
                };
            }
        };

        let nextCalled = false;
        const next = () => { nextCalled = true; };

        addUserInfo(req, res, next);

        assert.strictEqual(statusResponse, 403);
        assert.strictEqual(nextCalled, false);
    });

    test('addUserInfoPromise should resolve when token verification completes', async () => {
        const token = jwt.sign(
            { email: 'adam@hlavacek.win' },
            privateKey,
            { algorithm: 'RS256', audience: MAIN_CONFIG.cf_audience }
        );

        const req = {
            header: (name) => {
                if (name === 'Cf-Access-Jwt-Assertion') return token;
                return null;
            }
        };

        await addUserInfoPromise(req);
        assert.deepEqual(req.user, { email: 'adam@hlavacek.win' });
    });
});

import { test, describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import request from 'supertest';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { initializeApp } from '../../app.js';
import { client } from '../../util/verifyJWT.js';
import { MAIN_CONFIG } from '../../config/main.js';
import { ACCOUNTS, ACCOUNT_MAP } from '../../config/accounts.js';
import PersistentAdapter, { setStorage } from '../../util/persistentAdapter.js';
import { Cache } from '../../util/jsonKVStore.js';

describe('Express & OIDC Provider Integration Tests', () => {
    const testKeysPath = path.join('data', 'test-integration-keys.json');
    const testCookieSecretsPath = path.join('data', 'test-integration-cookie-secrets.json');
    const testStoragePath = path.join('data', 'test-integration-persistent.json');

    // Dynamic credentials from config/accounts.js to prevent local/CI mismatch
    const testAccount = ACCOUNTS[0];
    const testSub = testAccount.sub;
    const testName = testAccount.name || '';
    const testProfileEmail = testAccount.email;

    const entry = Object.entries(ACCOUNT_MAP).find(([localId, emails]) => localId === testSub && emails && emails.length > 0);
    const testLoginEmail = entry ? entry[1][0] : (Object.values(ACCOUNT_MAP)[0]?.[0] || testProfileEmail);

    const testClients = [
        {
            client_id: '395328',
            client_secret: 'a00378deddbf1b2d344b91c7abed8c0def825fa233c3f11071fdb7ee',
            grant_types: ['refresh_token', 'authorization_code', 'implicit', 'urn:ietf:params:oauth:grant-type:device_code'],
            redirect_uris: ['https://git.hlavacek.win/user/oauth2/CFA/callback'],
        }
    ];

    let app;
    let provider;
    let testStorage;

    let originalGetSigningKey;
    let publicKey;
    let privateKey;
    let testToken;

    const cleanUp = () => {
        [testKeysPath, testCookieSecretsPath, testStoragePath].forEach(file => {
            if (fs.existsSync(file)) {
                try {
                    fs.unlinkSync(file);
                } catch (err) {}
            }
        });
    };

    const getPath = (urlStr) => {
        if (!urlStr) return '';
        if (urlStr.startsWith('http://') || urlStr.startsWith('https://')) {
            const parsed = new URL(urlStr);
            return parsed.pathname + parsed.search;
        }
        return urlStr;
    };

    // Simulate browser cookie merging
    const mergeCookies = (currentCookies, setCookieHeaders) => {
        if (!setCookieHeaders) return currentCookies;
        const cookieMap = {};

        const parseCookieStr = (cookieStr) => {
            if (!cookieStr) return;
            const parts = cookieStr.split(';');
            parts.forEach(part => {
                const trimmed = part.trim();
                const eqIndex = trimmed.indexOf('=');
                if (eqIndex > 0) {
                    const name = trimmed.substring(0, eqIndex).trim();
                    const value = trimmed.substring(eqIndex + 1).trim();
                    if (!['path', 'expires', 'domain', 'httponly', 'secure', 'samesite', 'max-age'].includes(name.toLowerCase())) {
                        cookieMap[name] = value;
                    }
                }
            });
        };

        if (currentCookies) {
            parseCookieStr(currentCookies);
        }

        if (Array.isArray(setCookieHeaders)) {
            setCookieHeaders.forEach(parseCookieStr);
        } else {
            parseCookieStr(setCookieHeaders);
        }

        return Object.entries(cookieMap)
            .map(([name, value]) => `${name}=${value}`)
            .join('; ');
    };

    before(async () => {
        cleanUp();
        testStorage = new Cache(testStoragePath);
        setStorage(testStorage);

        originalGetSigningKey = client.getSigningKey;
        const keys = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
        });
        publicKey = keys.publicKey;
        privateKey = keys.privateKey;

        client.getSigningKey = (kid, cb) => {
            cb(null, {
                getPublicKey: () => publicKey
            });
        };

        testToken = jwt.sign(
            { email: testLoginEmail },
            privateKey,
            { algorithm: 'RS256', audience: MAIN_CONFIG.cf_audience }
        );

        const testConfig = {
            port: 3001,
            issuer: 'http://127.0.0.1:3001',
            env_production: false,
            use_ssl: false,
            cf_team_domain: 'hlavacek',
            cf_audience: 'test-audience'
        };

        const result = await initializeApp({
            config: testConfig,
            keysPath: testKeysPath,
            cookieSecretsPath: testCookieSecretsPath,
            adapter: PersistentAdapter,
            clients: testClients
        });
        app = result.app;
        provider = result.provider;

        provider.on('server_error', (ctx, err) => {
            console.error('DEBUG OIDC Server Error:', err);
        });
    });

    after(() => {
        cleanUp();
        client.getSigningKey = originalGetSigningKey;
        
        setTimeout(() => {
            process.exit(process.exitCode || 0);
        }, 100);
    });

    beforeEach(() => {
        if (testStorage) {
            testStorage.cacheMap = {};
            testStorage.saveCache();
        }
    });

    test('GET / should render index and return 200', async () => {
        const response = await request(app)
            .get('/')
            .set('Cf-Access-Jwt-Assertion', testToken)
            .expect(200);

        assert.ok(response.text.includes('OICD Cloudflare proxy'));
        assert.ok(response.text.includes(testLoginEmail));
    });

    test('Production HTTPS Redirect and Policy Enforcement', async () => {
        const prodKeysPath = path.join('data', 'test-prod-keys.json');
        const prodCookieSecretsPath = path.join('data', 'test-prod-cookie-secrets.json');

        const { app: prodApp } = await initializeApp({
            config: {
                port: 3003,
                issuer: 'http://127.0.0.1:3003',
                env_production: true,
                use_ssl: false,
                cf_team_domain: 'hlavacek',
                cf_audience: 'test-audience'
            },
            keysPath: prodKeysPath,
            cookieSecretsPath: prodCookieSecretsPath,
            clients: testClients
        });

        try {
            const responseRedirect = await request(prodApp)
                .get('/')
                .set('Cf-Access-Jwt-Assertion', testToken)
                .set('x-forwarded-proto', 'http')
                .expect(302);
            assert.ok(responseRedirect.headers.location.startsWith('https://'));

            const responseOk = await request(prodApp)
                .get('/')
                .set('Cf-Access-Jwt-Assertion', testToken)
                .set('x-forwarded-proto', 'https')
                .expect(200);
            assert.ok(responseOk.text.includes('OICD Cloudflare proxy'));

            await request(prodApp)
                .post('/protected/interaction/uid/login')
                .set('Cf-Access-Jwt-Assertion', testToken)
                .set('x-forwarded-proto', 'http')
                .expect(400);
        } finally {
            [prodKeysPath, prodCookieSecretsPath].forEach(file => {
                if (fs.existsSync(file)) {
                    try { fs.unlinkSync(file); } catch (err) {}
                }
            });
        }
    });

    test('Discovery endpoint /.well-known/openid-configuration returns valid metadata', async () => {
        const response = await request(app)
            .get('/.well-known/openid-configuration')
            .expect(200)
            .expect('content-type', /json/);

        const body = response.body;
        assert.strictEqual(body.issuer, 'http://127.0.0.1:3001');
        assert.ok(body.authorization_endpoint.includes('/protected/auth'));
        assert.ok(body.token_endpoint.includes('/token'));
        assert.ok(body.userinfo_endpoint.includes('/me'));
    });

    test('JWKs endpoint returns public keys', async () => {
        const response = await request(app)
            .get('/jwks')
            .expect(200)
            .expect('content-type', /json/);

        assert.ok(Array.isArray(response.body.keys));
        assert.strictEqual(response.body.keys.length, 2);
    });

    test('Full End-to-End OIDC Authorization Code Flow', async () => {
        const authUrl = '/protected/auth' +
            '?client_id=395328' +
            '&redirect_uri=https://git.hlavacek.win/user/oauth2/CFA/callback' +
            '&response_type=code' +
            '&scope=openid%20email%20profile' +
            '&state=my-state';

        let res = await request(app)
            .get(authUrl)
            .set('Cf-Access-Jwt-Assertion', testToken);
        assert.ok(res.status === 302 || res.status === 303, `Expected redirect (302/303), got ${res.status}`);

        let cookies = mergeCookies('', res.headers['set-cookie']);
        let redirectUrl = res.headers.location;
        assert.ok(redirectUrl.includes('/protected/interaction/'));
        const uid = redirectUrl.split('/').pop();

        res = await request(app)
            .get(`/protected/interaction/${uid}`)
            .set('Cf-Access-Jwt-Assertion', testToken)
            .set('Cookie', cookies)
            .expect(200);
        assert.ok(res.text.includes('Sign-in'));

        res = await request(app)
            .post(`/protected/interaction/${uid}/login`)
            .set('Cf-Access-Jwt-Assertion', testToken)
            .set('Cookie', cookies)
            .type('form')
            .send({ login: testLoginEmail });
        assert.ok(res.status === 302 || res.status === 303, `Expected redirect (302/303), got ${res.status}`);

        cookies = mergeCookies(cookies, res.headers['set-cookie']);

        redirectUrl = res.headers.location;
        res = await request(app)
            .get(getPath(redirectUrl))
            .set('Cf-Access-Jwt-Assertion', testToken)
            .set('Cookie', cookies);
        assert.ok(res.status === 302 || res.status === 303, `Expected redirect (302/303), got ${res.status}`);
        
        cookies = mergeCookies(cookies, res.headers['set-cookie']);

        redirectUrl = res.headers.location;
        assert.ok(redirectUrl.includes('/protected/interaction/'));
        const newUid = redirectUrl.split('/').pop();
        
        res = await request(app)
            .get(getPath(redirectUrl))
            .set('Cf-Access-Jwt-Assertion', testToken)
            .set('Cookie', cookies)
            .expect(200);
        assert.ok(res.text.includes('Authorize'));

        res = await request(app)
            .post(`/protected/interaction/${newUid}/confirm`)
            .set('Cf-Access-Jwt-Assertion', testToken)
            .set('Cookie', cookies)
            .type('form')
            .send({});
        assert.ok(res.status === 302 || res.status === 303, `Expected redirect (302/303), got ${res.status}`);

        cookies = mergeCookies(cookies, res.headers['set-cookie']);

        redirectUrl = res.headers.location;
        res = await request(app)
            .get(getPath(redirectUrl))
            .set('Cf-Access-Jwt-Assertion', testToken)
            .set('Cookie', cookies);
        assert.ok(res.status === 302 || res.status === 303, `Expected redirect (302/303), got ${res.status}`);

        const callbackUrl = new URL(res.headers.location);
        assert.strictEqual(callbackUrl.origin + callbackUrl.pathname, 'https://git.hlavacek.win/user/oauth2/CFA/callback');
        
        const code = callbackUrl.searchParams.get('code');
        const returnedState = callbackUrl.searchParams.get('state');
        assert.ok(code);
        assert.strictEqual(returnedState, 'my-state');

        res = await request(app)
            .post('/token')
            .auth('395328', 'a00378deddbf1b2d344b91c7abed8c0def825fa233c3f11071fdb7ee')
            .type('form')
            .send({
                grant_type: 'authorization_code',
                code,
                redirect_uri: 'https://git.hlavacek.win/user/oauth2/CFA/callback'
            })
            .expect(200);

        const { access_token, id_token, token_type } = res.body;
        assert.ok(access_token);
        assert.ok(id_token);
        assert.strictEqual(token_type, 'Bearer');

        res = await request(app)
            .get('/me')
            .set('Authorization', `Bearer ${access_token}`)
            .expect(200);

        assert.strictEqual(res.body.sub, testSub);
        assert.strictEqual(res.body.email, testProfileEmail);
        if (testName) {
            assert.strictEqual(res.body.name, testName);
        }
    });

    test('GET /protected/interaction/:uid/abort should return access_denied', async () => {
        const authUrl = '/protected/auth' +
            '?client_id=395328' +
            '&redirect_uri=https://git.hlavacek.win/user/oauth2/CFA/callback' +
            '&response_type=code' +
            '&scope=openid' +
            '&state=my-state';

        let res = await request(app)
            .get(authUrl)
            .set('Cf-Access-Jwt-Assertion', testToken);
        assert.ok(res.status === 302 || res.status === 303, `Expected redirect (302/303), got ${res.status}`);
        
        let cookies = mergeCookies('', res.headers['set-cookie']);
        const uid = res.headers.location.split('/').pop();

        res = await request(app)
            .get(`/protected/interaction/${uid}/abort`)
            .set('Cf-Access-Jwt-Assertion', testToken)
            .set('Cookie', cookies);
        assert.ok(res.status === 302 || res.status === 303, `Expected redirect (302/303), got ${res.status}`);

        cookies = mergeCookies(cookies, res.headers['set-cookie']);

        res = await request(app)
            .get(getPath(res.headers.location))
            .set('Cf-Access-Jwt-Assertion', testToken)
            .set('Cookie', cookies);
        assert.ok(res.status === 302 || res.status === 303, `Expected redirect (302/303), got ${res.status}`);

        const callbackUrl = new URL(res.headers.location);
        assert.strictEqual(callbackUrl.searchParams.get('error'), 'access_denied');
        assert.strictEqual(callbackUrl.searchParams.get('error_description'), 'End-User aborted interaction');
    });
});

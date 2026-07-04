import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { CookieSecretManager } from '../../util/generateCookieKeys.js';

describe('generateCookieKeys CookieSecretManager Unit Tests', () => {
    const testSecretsPath = path.join('data', 'test-cookie-secrets.json');

    const cleanUp = () => {
        if (fs.existsSync(testSecretsPath)) {
            try {
                fs.unlinkSync(testSecretsPath);
            } catch (err) {}
        }
    };

    beforeEach(cleanUp);
    afterEach(cleanUp);

    test('should generate cookie secrets of standard length', () => {
        const manager = new CookieSecretManager(testSecretsPath);
        const secret = manager.generateCookieSecret();
        // 32 bytes in hex = 64 characters
        assert.strictEqual(secret.length, 64);
    });

    test('should generate a list of secrets', () => {
        const manager = new CookieSecretManager(testSecretsPath);
        const secrets = manager.generateCookieSecrets(3);
        assert.strictEqual(secrets.length, 3);
        assert.strictEqual(secrets[0].length, 64);
        assert.notStrictEqual(secrets[0], secrets[1]);
    });

    test('should cache and return generated secrets', () => {
        const manager = new CookieSecretManager(testSecretsPath);
        
        // 1. First retrieval generates and saves
        const result1 = manager.getCookies();
        assert.ok(Array.isArray(result1.keys));
        assert.strictEqual(result1.keys.length, 5);

        // 2. Second retrieval should return the same cached keys
        const manager2 = new CookieSecretManager(testSecretsPath);
        const result2 = manager2.getCookies();
        assert.deepEqual(result1.keys, result2.keys);
    });
});

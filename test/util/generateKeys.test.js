import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { KeyManager } from '../../util/generateKeys.js';

describe('generateKeys KeyManager Unit Tests', () => {
    const testKeysPath = path.join('data', 'test-keys.json');

    const cleanUp = () => {
        if (fs.existsSync(testKeysPath)) {
            try {
                fs.unlinkSync(testKeysPath);
            } catch (err) {}
        }
    };

    beforeEach(cleanUp);
    afterEach(cleanUp);

    test('should generate RSA and EC key pairs', async () => {
        const manager = new KeyManager();
        const rsaKey = await manager.generateRSAKeyPair();
        const ecKey = await manager.generateECKeyPair();

        assert.strictEqual(rsaKey.kty, 'RSA');
        assert.strictEqual(ecKey.kty, 'EC');
    });

    test('should save keys to file and load them back', async () => {
        const manager = new KeyManager();
        const keys = await manager.generateAndReturnKeys();
        
        await manager.saveKeysToFile([keys.rsaKey, keys.ecKey], testKeysPath);
        assert.ok(fs.existsSync(testKeysPath));

        const loadedKeys = await manager.loadKeysFromFile(testKeysPath);
        assert.strictEqual(loadedKeys.keys.length, 2);
        
        const keyTypes = loadedKeys.keys.map(k => k.kty);
        assert.ok(keyTypes.includes('RSA'));
        assert.ok(keyTypes.includes('EC'));
    });

    test('should load keys if file exists, or generate and save them if file does not exist', async () => {
        const manager = new KeyManager();
        
        // 1. Should generate since it doesn't exist
        const result1 = await manager.loadKeysOrGenerateAndSave(testKeysPath);
        assert.ok(fs.existsSync(testKeysPath));
        assert.strictEqual(result1.keys.length, 2);

        // 2. Should load existing keys instead of generating new ones
        const manager2 = new KeyManager();
        const result2 = await manager2.loadKeysOrGenerateAndSave(testKeysPath);
        
        // Assert loaded keys match keys in the file (meaning they match result1's keys)
        assert.deepEqual(result1.keys, result2.keys);
    });
});

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import PersistentAdapter, { setStorage } from '../../util/persistentAdapter.js';
import { Cache } from '../../util/jsonKVStore.js';

describe('persistentAdapter PersistentAdapter Unit Tests', () => {
    const testStoragePath = path.join('data', 'test-persistent.json');
    let testStorage;

    const cleanUp = () => {
        if (fs.existsSync(testStoragePath)) {
            try {
                fs.unlinkSync(testStoragePath);
            } catch (err) {}
        }
    };

    beforeEach(() => {
        cleanUp();
        testStorage = new Cache(testStoragePath);
        setStorage(testStorage);
    });

    afterEach(cleanUp);

    test('should upsert and find model data', async () => {
        const adapter = new PersistentAdapter('Session');
        const payload = { uid: 'uid123', foo: 'bar' };
        
        await adapter.upsert('sess123', payload, 3600);

        const found = await adapter.find('sess123');
        assert.deepEqual(found, payload);
    });

    test('should find session by uid', async () => {
        const adapter = new PersistentAdapter('Session');
        const payload = { uid: 'uid_special', foo: 'session-details' };

        await adapter.upsert('sess_id', payload, 3600);

        const found = await adapter.findByUid('uid_special');
        assert.deepEqual(found, payload);
    });

    test('should consume authorization code', async () => {
        const adapter = new PersistentAdapter('AuthorizationCode');
        const payload = { grantId: 'grant123', foo: 'code' };

        await adapter.upsert('code123', payload, 3600);
        await adapter.consume('code123');

        const found = await adapter.find('code123');
        assert.ok(found.consumed);
        assert.ok(typeof found.consumed === 'number');
    });

    test('should destroy entry', async () => {
        const adapter = new PersistentAdapter('AccessToken');
        await adapter.upsert('token123', { token: 'abc' }, 3600);
        
        assert.ok(await adapter.find('token123'));
        
        await adapter.destroy('token123');
        assert.strictEqual(await adapter.find('token123'), null);
    });

    test('should handle user code for device flow', async () => {
        const adapter = new PersistentAdapter('DeviceCode');
        const payload = { userCode: 'CODE-1234', deviceId: 'dev456' };

        await adapter.upsert('device123', payload, 3600);

        const found = await adapter.findByUserCode('CODE-1234');
        assert.deepEqual(found, payload);
    });

    test('should revoke by grantId', async () => {
        // Upsert multiple tokens with same grantId
        const tokenAdapter = new PersistentAdapter('AccessToken');
        const codeAdapter = new PersistentAdapter('AuthorizationCode');

        await tokenAdapter.upsert('access_token_id', { grantId: 'my_grant' }, 3600);
        await codeAdapter.upsert('auth_code_id', { grantId: 'my_grant' }, 3600);

        assert.ok(await tokenAdapter.find('access_token_id'));
        assert.ok(await codeAdapter.find('auth_code_id'));

        // Revoke them
        await tokenAdapter.revokeByGrantId('my_grant');

        assert.strictEqual(await tokenAdapter.find('access_token_id'), null);
        assert.strictEqual(await codeAdapter.find('auth_code_id'), null);
    });
});

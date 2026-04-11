import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Cache } from '../util/jsonKVStore.js';
import PersistentAdapter, { setStorage } from '../util/persistentAdapter.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('PersistentAdapter', () => {
  let tmpDir;
  let testStorage;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'adapter-test-'));
    testStorage = new Cache(path.join(tmpDir, 'test-persistent.json'));
    setStorage(testStorage);
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should upsert and find data', async () => {
    const adapter = new PersistentAdapter('TestModel');
    await adapter.upsert('id1', { data: 'test' }, 3600);
    const result = await adapter.find('id1');
    expect(result).toEqual({ data: 'test' });
  });

  it('should return null for non-existent data', async () => {
    const adapter = new PersistentAdapter('TestModel');
    const result = await adapter.find('nonexistent');
    expect(result).toBeNull();
  });

  it('should destroy data', async () => {
    const adapter = new PersistentAdapter('TestModel');
    await adapter.upsert('to-delete', { data: 'delete-me' }, 3600);
    await adapter.destroy('to-delete');
    const result = await adapter.find('to-delete');
    expect(result).toBeNull();
  });

  it('should handle Session model with uid lookup', async () => {
    const adapter = new PersistentAdapter('Session');
    await adapter.upsert('session1', { uid: 'user1', data: 'session-data' }, 3600);
    const result = await adapter.findByUid('user1');
    expect(result).toEqual({ uid: 'user1', data: 'session-data' });
  });

  it('should handle grant-based models', async () => {
    const adapter = new PersistentAdapter('AccessToken');
    await adapter.upsert('token1', { grantId: 'grant1', data: 'token-data' }, 3600);
    const result = await adapter.find('token1');
    expect(result).toEqual({ grantId: 'grant1', data: 'token-data' });
  });

  it('should revoke by grant ID', async () => {
    const adapter = new PersistentAdapter('AccessToken');
    await adapter.upsert('token-revoke', { grantId: 'grant-revoke', data: 'revoke-me' }, 3600);
    await adapter.revokeByGrantId('grant-revoke');
    const result = await adapter.find('token-revoke');
    expect(result).toBeNull();
  });

  it('should handle userCode lookup', async () => {
    const adapter = new PersistentAdapter('DeviceCode');
    await adapter.upsert('device1', { userCode: 'ABC123', data: 'device-data' }, 3600);
    const result = await adapter.findByUserCode('ABC123');
    expect(result).toEqual({ userCode: 'ABC123', data: 'device-data' });
  });

  it('should consume data', async () => {
    const adapter = new PersistentAdapter('AuthorizationCode');
    await adapter.upsert('code1', { data: 'code-data' }, 3600);
    await adapter.consume('code1');
    const result = await adapter.find('code1');
    expect(result).toHaveProperty('consumed');
    expect(typeof result.consumed).toBe('number');
  });
});

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { KeyManager } from '../util/generateKeys.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('KeyManager', () => {
  let tmpDir;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'keys-test-'));
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should generate RSA key pair', async () => {
    const manager = new KeyManager();
    const key = await manager.generateRSAKeyPair();
    expect(key).toBeDefined();
    expect(key.kty).toBe('RSA');
  });

  it('should generate EC key pair', async () => {
    const manager = new KeyManager();
    const key = await manager.generateECKeyPair();
    expect(key).toBeDefined();
    expect(key.kty).toBe('EC');
  });

  it('should save and load keys to/from file', async () => {
    const manager = new KeyManager();
    const rsaKey = await manager.generateRSAKeyPair();
    const ecKey = await manager.generateECKeyPair();

    const keysFile = path.join(tmpDir, 'test-keys.json');
    await manager.saveKeysToFile([rsaKey, ecKey], keysFile);

    const loaded = await manager.loadKeysFromFile(keysFile);
    expect(loaded).toBeDefined();
    expect(loaded.keys).toHaveLength(2);
  });

  it('should throw when saving empty keys', async () => {
    const manager = new KeyManager();
    const keysFile = path.join(tmpDir, 'empty-keys.json');
    await expect(manager.saveKeysToFile([], keysFile)).rejects.toThrow('No keys provided');
  });

  it('should generate and save keys when file does not exist', async () => {
    const manager = new KeyManager();
    const keysFile = path.join(tmpDir, 'new-keys.json');
    const result = await manager.loadKeysOrGenerateAndSave(keysFile);
    expect(result).toBeDefined();
    expect(fs.existsSync(keysFile)).toBe(true);
  });

  it('should load existing keys from file', async () => {
    const manager = new KeyManager();
    const keysFile = path.join(tmpDir, 'existing-keys.json');

    // First generate
    await manager.loadKeysOrGenerateAndSave(keysFile);

    // Then load
    const manager2 = new KeyManager();
    const result = await manager2.loadKeysOrGenerateAndSave(keysFile);
    expect(result).toBeDefined();
    expect(result.keys).toHaveLength(2);
  });
});

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { CookieSecretManager } from '../util/generateCookieKeys.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('CookieSecretManager', () => {
  let tmpDir;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cookie-test-'));
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should generate cookie secrets', () => {
    const manager = new CookieSecretManager(path.join(tmpDir, 'cookies1.json'));
    const secrets = manager.generateCookieSecrets(3);
    expect(secrets).toHaveLength(3);
    secrets.forEach(secret => {
      expect(typeof secret).toBe('string');
      expect(secret.length).toBe(64); // 32 bytes hex = 64 chars
    });
  });

  it('should return unique secrets', () => {
    const manager = new CookieSecretManager(path.join(tmpDir, 'cookies2.json'));
    const secrets = manager.generateCookieSecrets(5);
    const unique = new Set(secrets);
    expect(unique.size).toBe(5);
  });

  it('should get cookies and cache them', () => {
    const file = path.join(tmpDir, 'cookies3.json');
    const manager = new CookieSecretManager(file);
    const cookies1 = manager.getCookies();
    expect(cookies1.keys).toHaveLength(5);

    // Should return same keys on second call
    const cookies2 = manager.getCookies();
    expect(cookies2.keys).toEqual(cookies1.keys);
  });

  it('should persist cookies across instances', () => {
    const file = path.join(tmpDir, 'cookies4.json');
    const manager1 = new CookieSecretManager(file);
    const cookies1 = manager1.getCookies();

    const manager2 = new CookieSecretManager(file);
    const cookies2 = manager2.getCookies();
    expect(cookies2.keys).toEqual(cookies1.keys);
  });
});

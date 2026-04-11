import { describe, it, expect, beforeAll } from 'vitest';
import { Cache } from '../util/jsonKVStore.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('Cache (jsonKVStore)', () => {
  let tmpDir;
  let cacheFile;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cache-test-'));
  });

  function createCache(name = 'test.json') {
    cacheFile = path.join(tmpDir, name);
    return new Cache(cacheFile);
  }

  it('should set and get values', () => {
    const cache = createCache('basic.json');
    cache.set('key1', 'value1');
    expect(cache.get('key1')).toBe('value1');
  });

  it('should return null for non-existent keys', () => {
    const cache = createCache('nonexist.json');
    expect(cache.get('missing')).toBeNull();
  });

  it('should delete values', () => {
    const cache = createCache('delete.json');
    cache.set('key1', 'value1');
    expect(cache.delete('key1')).toBe(true);
    expect(cache.get('key1')).toBeNull();
  });

  it('should return false when deleting non-existent key', () => {
    const cache = createCache('delnone.json');
    expect(cache.delete('missing')).toBe(false);
  });

  it('should handle expiration', async () => {
    const cache = createCache('expire.json');
    cache.set('expiring', 'value', 1); // 1 second expiration
    expect(cache.get('expiring')).toBe('value');

    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 1100));
    expect(cache.get('expiring')).toBeNull();
  });

  it('should persist to file', () => {
    const file = path.join(tmpDir, 'persist.json');
    const cache1 = new Cache(file);
    cache1.set('persistent', 'data');

    const cache2 = new Cache(file);
    expect(cache2.get('persistent')).toBe('data');
  });

  it('should handle complex values', () => {
    const cache = createCache('complex.json');
    const complexValue = { nested: { array: [1, 2, 3], obj: { a: 'b' } } };
    cache.set('complex', complexValue);
    expect(cache.get('complex')).toEqual(complexValue);
  });

  it('should return all keys', () => {
    const cache = createCache('keys.json');
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('c', 3);
    expect(cache.getKeys()).toEqual(expect.arrayContaining(['a', 'b', 'c']));
  });

  it('should overwrite existing values', () => {
    const cache = createCache('overwrite.json');
    cache.set('key', 'old');
    cache.set('key', 'new');
    expect(cache.get('key')).toBe('new');
  });
});

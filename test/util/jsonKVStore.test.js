import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Cache } from '../../util/jsonKVStore.js';

describe('jsonKVStore Cache Unit Tests', () => {
    const testCachePath = path.join('data', 'test-kv-store.json');

    // Clean up before and after each test
    const cleanUp = () => {
        if (fs.existsSync(testCachePath)) {
            try {
                fs.unlinkSync(testCachePath);
            } catch (err) {
                // ignore
            }
        }
        // Ensure parent directory exists
        const dir = path.dirname(testCachePath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    };

    beforeEach(cleanUp);
    afterEach(cleanUp);

    test('should initialize an empty cache when file does not exist', () => {
        const cache = new Cache(testCachePath);
        assert.deepEqual(cache.getKeys(), []);
    });

    test('should set and get a value', () => {
        const cache = new Cache(testCachePath);
        cache.set('foo', 'bar');
        assert.strictEqual(cache.get('foo'), 'bar');
    });

    test('should persist values to the JSON file', () => {
        const cache = new Cache(testCachePath);
        cache.set('foo', 'bar');
        
        // Load in a separate cache instance
        const cache2 = new Cache(testCachePath);
        assert.strictEqual(cache2.get('foo'), 'bar');
    });

    test('should return null for expired entries and remove them', () => {
        const cache = new Cache(testCachePath);
        
        let now = Date.now();
        const originalNow = Date.now;
        // Mock Date.now
        Date.now = () => now;

        try {
            // Expiration in 1 second
            cache.set('foo', 'bar', 1);
            assert.strictEqual(cache.get('foo'), 'bar');

            // Fast-forward time by 2 seconds
            now += 2000;

            assert.strictEqual(cache.get('foo'), null);
            
            // Re-read file to verify it was removed from persistence as well
            const cache2 = new Cache(testCachePath);
            assert.strictEqual(cache2.get('foo'), null);
        } finally {
            // Restore Date.now
            Date.now = originalNow;
        }
    });

    test('should delete an entry and save cache', () => {
        const cache = new Cache(testCachePath);
        cache.set('foo', 'bar');
        assert.strictEqual(cache.delete('foo'), true);
        assert.strictEqual(cache.get('foo'), null);
        assert.strictEqual(cache.delete('foo'), false);
        
        const cache2 = new Cache(testCachePath);
        assert.strictEqual(cache2.get('foo'), null);
    });
    
    test('should return list of keys', () => {
        const cache = new Cache(testCachePath);
        cache.set('a', 1);
        cache.set('b', 2);
        assert.deepEqual(cache.getKeys().sort(), ['a', 'b']);
    });
});

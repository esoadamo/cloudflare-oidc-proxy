import { describe, it, expect } from 'vitest';
import { ACCOUNTS, ACCOUNT_MAP } from '../config/accounts.js';

describe('AccountService', () => {
  // Import dynamically to avoid side effects
  let AccountService;

  beforeAll(async () => {
    const mod = await import('../util/accountService.js');
    AccountService = mod.default;
  });

  describe('getAccountById', () => {
    it('should find account by valid ID', () => {
      const account = AccountService.getAccountById('account1');
      expect(account).toBeDefined();
      expect(account.accountId).toBe('account1');
      expect(account.profile.email).toBe('email@example.com');
    });

    it('should throw for non-existent account ID', () => {
      expect(() => AccountService.getAccountById('nonexistent')).toThrow();
    });
  });

  describe('assertVerifiedUser', () => {
    it('should pass for /token path without verification', () => {
      const req = { path: '/token', user: null };
      expect(() => AccountService.assertVerifiedUser(req, 'any@email.com')).not.toThrow();
    });

    it('should pass for /me path without verification', () => {
      const req = { path: '/me', user: null };
      expect(() => AccountService.assertVerifiedUser(req, 'any@email.com')).not.toThrow();
    });

    it('should pass when emails match', () => {
      const req = { path: '/protected/test', user: { email: 'user@example.com' } };
      expect(() => AccountService.assertVerifiedUser(req, 'user@example.com')).not.toThrow();
    });

    it('should throw when emails do not match', () => {
      const req = { path: '/protected/test', user: { email: 'user@example.com' } };
      expect(() => AccountService.assertVerifiedUser(req, 'other@example.com')).toThrow();
    });

    it('should throw when user is null', () => {
      const req = { path: '/protected/test', user: null };
      expect(() => AccountService.assertVerifiedUser(req, 'user@example.com')).toThrow();
    });

    it('should throw when user is undefined', () => {
      const req = { path: '/protected/test' };
      expect(() => AccountService.assertVerifiedUser(req, 'user@example.com')).toThrow();
    });

    it('should throw when expected is empty', () => {
      const req = { path: '/protected/test', user: { email: 'user@example.com' } };
      expect(() => AccountService.assertVerifiedUser(req, '')).toThrow();
    });
  });

  describe('findByLogin', () => {
    it('should find account by mapped email', async () => {
      const req = { path: '/protected/test', user: { email: 'email@example.com' } };
      const account = await AccountService.findByLogin(req, 'email@example.com');
      expect(account).toBeDefined();
      expect(account.accountId).toBe('account1');
    });

    it('should throw for unmapped email', async () => {
      const req = { path: '/protected/test', user: { email: 'unknown@example.com' } };
      await expect(AccountService.findByLogin(req, 'unknown@example.com')).rejects.toThrow();
    });
  });

  describe('claims', () => {
    it('should return account profile as claims', async () => {
      const account = AccountService.getAccountById('account1');
      const claims = await account.claims('id_token', ['openid', 'email']);
      expect(claims).toBeDefined();
      expect(claims.email).toBe('email@example.com');
      expect(claims.sub).toBe('account1');
    });
  });
});

import { test, describe } from 'node:test';
import assert from 'node:assert';
import AccountService from '../../util/accountService.js';
import { ACCOUNTS, ACCOUNT_MAP } from '../../config/accounts.js';

describe('accountService AccountService Unit Tests', () => {
    const testAccount = ACCOUNTS[0];
    const testEmail = testAccount.email;
    const testSub = testAccount.sub;

    const entry = Object.entries(ACCOUNT_MAP).find(([localId, emails]) => emails && emails.length > 0);
    const testMappedLocalId = entry ? entry[0] : testSub;
    const testMappedEmail = entry ? entry[1][0] : testEmail;

    test('getAccountById should find valid user account', () => {
        const account = AccountService.getAccountById(testSub);
        assert.ok(account);
        assert.strictEqual(account.accountId, testSub);
        assert.strictEqual(account.profile.email, testEmail);
    });

    test('getAccountById should throw on invalid user account', () => {
        assert.throws(() => {
            AccountService.getAccountById('nonexistent');
        });
    });

    test('assertVerifiedUser should bypass check for /token and /me routes', () => {
        AccountService.assertVerifiedUser({ path: '/token' }, testEmail);
        AccountService.assertVerifiedUser({ path: '/me' }, testEmail);
    });

    test('assertVerifiedUser should pass when req.user.email matches expected email', () => {
        const req = {
            path: '/protected/auth',
            user: { email: testEmail }
        };
        AccountService.assertVerifiedUser(req, testEmail);
    });

    test('assertVerifiedUser should throw when req.user is missing or email mismatches', () => {
        const reqNoUser = { path: '/protected/auth' };
        assert.throws(() => {
            AccountService.assertVerifiedUser(reqNoUser, testEmail);
        });

        const reqWrongUser = {
            path: '/protected/auth',
            user: { email: 'wrong@example.com' }
        };
        assert.throws(() => {
            AccountService.assertVerifiedUser(reqWrongUser, testEmail);
        });
    });

    test('findByLogin should locate account by pre-verified email mapping', async () => {
        const req = {
            path: '/protected/interaction/uid/login',
            user: { email: testMappedEmail }
        };
        
        const account = await AccountService.findByLogin(req, testMappedEmail);
        assert.ok(account);
        assert.strictEqual(account.accountId, testMappedLocalId);
    });

    test('findByLogin should throw on unmapped email', async () => {
        const req = {
            path: '/protected/interaction/uid/login',
            user: { email: 'unknown@example.com' }
        };

        await assert.rejects(async () => {
            await AccountService.findByLogin(req, 'unknown@example.com');
        });
    });
});

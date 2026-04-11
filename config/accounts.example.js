/**
 * @typedef {{
 *     sub: string,
 *     accountId: string,
 *     email: string,
 *     email_verified: boolean,
 *     name: string,
 *     locale: string,
 *     name: string
 * }} AccountBasic
 *
 * @typedef {AccountBasic & {
 *  address: {
 *    country: string,
 *    formatted: string,
 *    locality: string,
 *    postal_code: string,
 *    region: string,
 *    street_address: string,
 *  },
 *  birthdate: string,
 *  gender: 'male' | 'female',
 *  middle_name: string,
 *  family_name: string,
 *  given_name: string,
 *  nickname: string,
 *  phone_number: string,
 *  phone_number_verified: boolean,
 *  picture: string,
 *  preferred_username: string,
 *  profile: string,
 *  updated_at: number,
 *  website: string,
 *  zoneinfo: string
 * }} AccountFull
 *
 * @typedef {AccountBasic || AccountFull} AccountLocalData
 */

import { strict as assert } from 'assert';

/**
 * @type {AccountLocalData[]}
 */
export const ACCOUNTS = [
    {
        sub: 'account1',
        email: 'email@example.com',
        email_verified: true,
        name: 'Test User',
        locale: 'en-US',
    }
];

/**
 * Maps local account ID to multiple Cloudflare-provided emails
 * @type {{[account_id: string]: string[]}}
 */
export const ACCOUNT_MAP = {
    "account1": ['email@example.com', 'email.A@example.com', 'email.B@example.com']
} ;

Object.keys(ACCOUNT_MAP).forEach((localId) => assert(ACCOUNTS.find(account => account.sub === localId), `${localId} is specified in map but not in accounts`));

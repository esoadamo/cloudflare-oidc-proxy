import jose from 'node-jose';
import { promises as fs } from 'fs';

export class KeyManager {
    constructor() {
        this.rsaKeyStore = jose.JWK.createKeyStore();
        this.ecKeyStore = jose.JWK.createKeyStore();
    }

    async generateRSAKeyPair() {
        const key = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
        await this.rsaKeyStore.add(key);
        return key;
    }

    async generateECKeyPair() {
        const key = await jose.JWK.createKey('EC', 'P-256', { alg: 'ES256', use: 'sig' });
        await this.ecKeyStore.add(key);
        return key;
    }

    async saveKeysToFile(keys, filename) {
        if (!keys || keys.length === 0) {
            throw new Error('No keys provided to save.');
        }

        const keyArray = Array.isArray(keys) ? keys : [keys];
        const keySet = jose.JWK.createKeyStore();

        for (const key of keyArray) {
            await keySet.add(key);
        }

        const keySetJSON = await keySet.toJSON(true);
        await fs.writeFile(filename, JSON.stringify(keySetJSON, null, 2), 'utf-8');
    }

    async loadKeysFromFile(filename) {
        try {
            const fileContent = await fs.readFile(filename, 'utf-8');
            return JSON.parse(fileContent);
        } catch (error) {
            throw error;
        }
    }

    async loadKeysOrGenerateAndSave(filename, generateKeyPairFunction = this.generateAndReturnKeys.bind(this)) {
        try {
            // Try to load keys from the file
            return await this.loadKeysFromFile(filename);
        } catch (loadError) {
            // If the file doesn't exist, generate keys, save them, and then load again
            console.log(`Generating and saving keys to ${filename}`);
            const keys = await generateKeyPairFunction();
            if (!keys.rsaKey || !keys.ecKey) {
                throw new Error('Generated keys are invalid.');
            }
            await this.saveKeysToFile([keys.rsaKey, keys.ecKey], filename);
            return await this.loadKeysFromFile(filename);
        }
    }

    async generateAndReturnKeys() {
        const rsaKey = await this.generateRSAKeyPair();
        const ecKey = await this.generateECKeyPair();

        return {
            rsaKey,
            ecKey,
        };
    }
}

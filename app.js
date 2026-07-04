import * as path from 'node:path';
import * as url from 'node:url';

import { dirname } from 'desm';
import express from 'express';
import helmet from 'helmet';
import Provider from 'oidc-provider';

import AccountService from './util/accountService.js';
import configuration from './util/configuration.js';
import routes from './util/routes.js';
import { addUserInfo } from "./util/verifyJWT.js";
import PersistentAdapter from "./util/persistentAdapter.js";
import { KeyManager } from "./util/generateKeys.js";
import { CookieSecretManager } from "./util/generateCookieKeys.js";
import { MAIN_CONFIG } from "./config/main.js";

const __dirname = dirname(import.meta.url);

/**
 * Initializes and configures the Express application and the OIDC Provider.
 * Allows overriding configurations and dependencies for unit/integration testing.
 */
export async function initializeApp(options = {}) {
    const config = options.config || MAIN_CONFIG;
    const oidcConfig = { ...configuration };

    const app = express();

    if (config.env_production) {
        const directives = helmet.contentSecurityPolicy.getDefaultDirectives();
        delete directives['form-action'];
        app.use(helmet({
            contentSecurityPolicy: {
                useDefaults: false,
                directives,
            },
        }));
    }

    app.set('views', options.viewsPath || path.join(__dirname, 'views'));
    app.set('view engine', 'ejs');

    oidcConfig.findAccount = options.findAccount || AccountService.findAccount;

    if (options.clients) {
        oidcConfig.clients = options.clients;
    }

    if (options.jwks) {
        oidcConfig.jwks = options.jwks;
    } else {
        const keyManager = new KeyManager();
        oidcConfig.jwks = await keyManager.loadKeysOrGenerateAndSave(options.keysPath || path.join('data', 'keys.json'));
    }

    if (options.cookies) {
        oidcConfig.cookies = options.cookies;
    } else {
        oidcConfig.cookies = new CookieSecretManager(options.cookieSecretsPath || path.join('data', 'cookie_secrets.json')).getCookies();
    }

    const provider = new Provider(config.issuer, {
        adapter: options.adapter || PersistentAdapter,
        ...oidcConfig
    });

    if (config.env_production) {
        app.enable('trust proxy');
        provider.proxy = true;

        app.use((req, res, next) => {
            if (req.secure) {
                next();
            } else if (req.method === 'GET' || req.method === 'HEAD') {
                res.redirect(url.format({
                    protocol: 'https',
                    host: req.hostname,
                    pathname: req.originalUrl,
                }));
            } else {
                res.status(400).json({
                    error: 'invalid_request',
                    error_description: 'do yourself a favor and only use https',
                });
            }
        });
    }

    app.use(options.addUserInfo || addUserInfo);
    routes(app, provider);
    app.use(provider.callback());

    return { app, provider };
}

// Adapted from https://github.com/panva/node-oidc-provider/blob/main/example/express.js

/* eslint-disable no-console */
import 'dotenv/config';
import https from 'https';
import fs from 'fs';
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

const app = express();

if (MAIN_CONFIG.env_production) {
    const directives = helmet.contentSecurityPolicy.getDefaultDirectives();
    delete directives['form-action'];
    app.use(helmet({
        contentSecurityPolicy: {
            useDefaults: false,
            directives,
        },
    }));
}

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

async function main() {
    let server;
    try {
        configuration.findAccount = AccountService.findAccount;
        configuration.jwks = await (new KeyManager()).loadKeysOrGenerateAndSave(path.join('data', 'keys.json'));
        configuration.cookies = new CookieSecretManager(path.join('data', 'cookie_secrets.json')).getCookies();
        const provider = new Provider(MAIN_CONFIG.issuer, {adapter: PersistentAdapter, ...configuration });
        const port = MAIN_CONFIG.port;

        if (MAIN_CONFIG.env_production) {
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

        // noinspection JSCheckFunctionSignatures
        app.use(addUserInfo)
        routes(app, provider);
        app.use(provider.callback());

        if (MAIN_CONFIG.use_ssl) {
            server = https.createServer({
                key: fs.readFileSync('key.pem'),
                cert: fs.readFileSync('cert.pem')
            }, app).listen(port,  '',() => {
                console.log(`application is listening on port https://localhost:${port}, check its ${MAIN_CONFIG.issuer}/.well-known/openid-configuration`);
            });
        } else {
            server = app.listen(port, () => {
                console.log(`Application is listening on port http://localhost:${port}, check its ${MAIN_CONFIG.issuer}/.well-known/openid-configuration`);
            });
        }
    } catch (err) {
        if (server?.listening) server.close();
        console.error(err);
        process.exitCode = 1;
    }
}

main().then(() => console.log("Application start initialized"));

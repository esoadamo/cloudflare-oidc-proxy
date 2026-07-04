// Adapted from https://github.com/panva/node-oidc-provider/blob/main/example/express.js

/* eslint-disable no-console */
import 'dotenv/config';
import https from 'https';
import fs from 'fs';

import { initializeApp } from './app.js';
import { MAIN_CONFIG } from './config/main.js';

async function main() {
    let server;
    try {
        const { app } = await initializeApp();
        const port = MAIN_CONFIG.port;

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

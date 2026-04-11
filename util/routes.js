// Adapted from https://github.com/panva/node-oidc-provider/blob/main/example/routes/express.js

/* eslint-disable no-console, camelcase, no-unused-vars */
import { strict as assert } from 'node:assert';
import * as querystring from 'node:querystring';
import { inspect } from 'node:util';

import isEmpty from 'lodash/isEmpty.js';
import { urlencoded } from 'express'; // eslint-disable-line import/no-unresolved

import AccountService from './accountService.js';
import { errors } from 'oidc-provider';

const body = urlencoded({ extended: false });

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const keys = new Set();
const debug = (obj) => querystring.stringify(Object.entries(obj).reduce((acc, [key, value]) => {
  keys.add(key);
  if (isEmpty(value)) return acc;
  acc[key] = escapeHtml(inspect(value, { depth: null }));
  return acc;
}, {}), '<br/>', ': ', {
  encodeURIComponent(value) { return keys.has(value) ? `<strong>${escapeHtml(value)}</strong>` : value; },
});
const { SessionNotFound } = errors;
export default (app, provider) => {
  app.use((req, res, next) => {
    const orig = res.render;
    // you'll probably want to use a full blown render engine capable of layouts
    res.render = (view, locals) => {
      app.render(view, locals, (err, html) => {
        if (err) throw err;
        orig.call(res, '_layout', {
          ...locals,
          body: html,
        });
      });
    };
    next();
  });

  function setNoCache(req, res, next) {
    res.set('cache-control', 'no-store');
    next();
  }

  app.get('/', setNoCache, async (req, res, next) => {
    return res.render('index', {
      title: 'OICD Cloudflare proxy',
      uid: req?.user?.email,
      client: '',
      session: undefined,
      dbg: {
        params: JSON.stringify(req.headers)
      },
    });
  });

  app.get('/protected/interaction/:uid', setNoCache, async (req, res, next) => {
    try {
      const {
        uid, prompt, params, session,
      } = await provider.interactionDetails(req, res);

      const client = await provider.Client.find(params.client_id);

      switch (prompt.name) {
        case 'login': {
          return res.render('login', {
            client,
            uid,
            details: prompt.details,
            params,
            title: 'Sign-in',
            user: req?.user?.email,
            session: session ? debug(session) : undefined,
            dbg: {
              params: debug(params),
              prompt: debug(prompt),
            },
          });
        }
        case 'consent': {
          return res.render('interaction', {
            client,
            uid,
            details: prompt.details,
            params,
            title: 'Authorize',
            user: req?.user?.email,
            session: session ? debug(session) : undefined,
            dbg: {
              params: debug(params),
              prompt: debug(prompt),
            },
          });
        }
        default:
          return undefined;
      }
    } catch (err) {
      return next(err);
    }
  });

  app.post('/protected/interaction/:uid/login', setNoCache, body, async (req, res, next) => {
    try {
      const { prompt: { name } } = await provider.interactionDetails(req, res);
      assert.equal(name, 'login');
      const account = await AccountService.findByLogin(req, req.body.login);

      const result = {
        login: {
          accountId: account.accountId,
        },
      };

      await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
      next(err);
    }
  });

  app.post('/protected/interaction/:uid/confirm', setNoCache, body, async (req, res, next) => {
    try {
      const interactionDetails = await provider.interactionDetails(req, res);
      const { prompt: { name, details }, params, session: { accountId } } = interactionDetails;
      assert.equal(name, 'consent');

      let { grantId } = interactionDetails;
      let grant;

      if (grantId) {
        // we'll be modifying existing grant in existing session
        grant = await provider.Grant.find(grantId);
      } else {
        // we're establishing a new grant
        grant = new provider.Grant({
          accountId,
          clientId: params.client_id,
        });
      }

      if (details.missingOIDCScope) {
        grant.addOIDCScope(details.missingOIDCScope.join(' '));
      }
      if (details.missingOIDCClaims) {
        grant.addOIDCClaims(details.missingOIDCClaims);
      }
      if (details.missingResourceScopes) {
        for (const [indicator, scopes] of Object.entries(details.missingResourceScopes)) {
          grant.addResourceScope(indicator, scopes.join(' '));
        }
      }

      grantId = await grant.save();

      const consent = {};
      if (!interactionDetails.grantId) {
        // we don't have to pass grantId to consent, we're just modifying existing one
        consent.grantId = grantId;
      }

      const result = { consent };
      await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
    } catch (err) {
      next(err);
    }
  });

  app.get('/protected/interaction/:uid/abort', setNoCache, async (req, res, next) => {
    try {
      const result = {
        error: 'access_denied',
        error_description: 'End-User aborted interaction',
      };
      await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
      next(err);
    }
  });

  app.use((err, req, res, next) => {
    if (err instanceof SessionNotFound) {
      // handle interaction expired / session not found error
    }
    next(err);
  });
};

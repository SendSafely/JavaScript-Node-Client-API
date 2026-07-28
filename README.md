
# SendSafely JavaScript API for Node.js

The SendSafely JavaScript API for Node.js lets you integrate SendSafely secure data transfer capabilities directly into your Node.js application. 

## Requirements

- **Node.js**: v24.14.1 or higher *(required starting from SDK v4.0.1)*
- **npm**: v11.10.0 or higher

Please ensure you are on Node v24.14.1 or later to maintain compatibility with the SDK. If your application runs behind a corporate proxy, see [Proxy configuration](#proxy-configuration) below.

## Quickstart
The example below shows you how to install the package and use it as a CommonJS module.

Install with npm
```console
npm install @sendsafely/sendsafely
```

Include the SendSafely class to start making your API calls.

```javascript
var SendSafely = require('@sendsafely/sendsafely');
//var sendSafely = new SendSafely("https://demo.sendsafely.com", "exAPIkeyxyz", "exAPIsecretxyz");
var sendSafely = new SendSafely("https://ORGANIZATION_HOST", "API_KEY", "API_SECRET");

sendSafely.verifyCredentials(function(email)  {
	console.log("Connected to SendSafely as user "  +  email);
});

```

*You will need to generate your own API_KEY and API_SECRET from the API Keys section of your Profile page when logged into your SendSafely portal.*

## OAuth 2.1 Bearer authentication (opt-in)

> **NOTE:** OAuth 2.1 Bearer authentication is not available for use yet — it is
> planned for a future release. Please continue to use the API key/secret
> constructor until OAuth support is officially released.

As an alternative to the HMAC API Key/Secret scheme, you can authenticate `/api/v2.0` calls with an OAuth 2.1 Bearer access token. The HMAC constructor above is unchanged; OAuth is a second, opt-in strategy.

```javascript
var SendSafely = require('@sendsafely/sendsafely');
var sendSafely = SendSafely.withBearerToken("https://ORGANIZATION_HOST", accessToken);

// When you have obtained a fresh token (your code owns the OAuth flow and refresh):
sendSafely.setAccessToken(newAccessToken);
```

- The token's `aud`/`tenant_host` MUST match the host passed to `withBearerToken`. The URL must be `https://` (bearer tokens are sent on every request and must never travel in cleartext). The only exception is `http://localhost` / `http://127.0.0.1`, permitted for local development and testing — never point a real token at a plaintext URL.
- Requires `ALLOW_OAUTH_AS` enabled for the organization (default off); otherwise the request falls through to HMAC and fails authentication.
- The SDK does **not** auto-refresh. On expiry it raises `OAUTH_TOKEN_INVALID`; your code obtains a fresh token, calls `setAccessToken()`, and re-invokes.
- v1 limitations: trusted-device key operations (`generateKeyPair`/`generateRsaKeyPair`/`getKeycode`/`removePublicKey`/`syncKeycodes`) and white-label tenants are not OAuth-eligible — use an HMAC API key for those.
- Upload and download failures under OAuth surface as a generic transfer error in v1 (not a typed `OAUTH_*` error), because file transfers use pre-signed storage URLs that don't carry the access token. Token problems still surface as typed `OAUTH_*` errors on the preceding `/api/v2.0` call.
- Typed errors (delivered via the `sendsafely.error` event as the `code` argument): `OAUTH_TOKEN_INVALID` (401), `OAUTH_INSUFFICIENT_SCOPE` (403 with a `WWW-Authenticate: Bearer ... insufficient_scope` challenge), `OAUTH_TEMPORARILY_UNAVAILABLE` (503 with `Retry-After`). A 403 permission denial or a 503 without the OAuth challenge evidence is surfaced with its raw status, exactly as in HMAC mode. Callers branch on the code:

```javascript
sendSafely.on('sendsafely.error', function (code, message) {
  if (code === 'OAUTH_TOKEN_INVALID') {
    // obtain a fresh token, then sendSafely.setAccessToken(newToken) and re-invoke
  }
});
```

  These typed codes are only raised in Bearer mode; an HMAC client's 401/403/503 responses are surfaced exactly as before. The SDK does not parse or expose the raw `WWW-Authenticate` challenge (scope, resource_metadata) — obtaining a correctly-scoped token is the OAuth client's responsibility.

## Proxy configuration

The SDK uses the Node.js built-in `fetch` for all HTTP requests. By default Node does not read the `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables, so to route SDK traffic through a corporate proxy you need to opt in. Start your application with proxy support enabled:

```console
NODE_USE_ENV_PROXY=1 node app.js
```

or pass the equivalent flag:

```console
node --use-env-proxy app.js
```

With this enabled, Node honors `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` for the SDK's requests. This support is available in Node v24.5.0 and later.

If you are upgrading from an earlier SDK version, note that previous releases picked up these proxy variables automatically. Starting with this release you must enable the setting above.

## Examples
Please refer to our [Developer Website](https://sendsafely.github.io) to familiarize yourself with the core SendSafely API and common operations. See our [examples](https://github.com/SendSafely/JavaScript-Node-Client-API/tree/master/examples/CreateNewPackage) in GitHub for working examples of how to use the SendSafely JavaScript API for Node.js.  

## Support
For support, please contact support@sendsafely.com. 



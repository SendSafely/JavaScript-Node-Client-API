const { hmacSha256Hex } = require('./crypto-utils');

// Existing behavior. bodyString = JSON.stringify(messageData) or '' — identical concat to
// SendSafely.js and FetchRequest.js, guaranteeing byte-for-byte HMAC parity.
// Credentials are captured in the closure ONLY — never assigned to `this` — so the API
// secret is not exposed as an enumerable property (no leak via logs / JSON.stringify).
function HmacAuthStrategy(apiKey, apiKeySecret, requestAPI) {
  this.getHeaders = function (apiPrefix, urlPath, timestamp, bodyString) {
    const msg = apiKey + apiPrefix + urlPath.split('?')[0] + timestamp + (bodyString || '');
    return {
      'ss-api-key': apiKey,
      'ss-request-timestamp': timestamp,
      'ss-request-signature': hmacSha256Hex(apiKeySecret, msg),
      'ss-request-api': requestAPI,
    };
  };
  this.isOAuth = function () { return false; };
}

// OAuth Bearer (static token). Token is a cached STRING held in closure (sync read);
// no ss-* headers, no signature. Caller owns refresh and replaces via setToken().
function BearerAuthStrategy(token, requestAPI) {
  this.getHeaders = function () {
    return { 'Authorization': 'Bearer ' + token, 'ss-request-api': requestAPI };
  };
  this.setToken = function (t) { token = t; };   // backs ss.setAccessToken()
  this.isOAuth = function () { return true; };
}

// Anonymous dropzone auth. No signature and no secret — a dropzone is identified
// solely by its id, sent as the ss-api-key header (mirrors AnonymousRequest.sendRequest).
// Carrying it as a strategy lets the shared upload path call strategy.getHeaders()
// uniformly instead of special-casing AnonymousRequest (which otherwise has no
// strategy, crashing the ec2Proxy upload-failover path).
function AnonymousAuthStrategy(dropzoneId, requestAPI) {
  this.getHeaders = function () {
    return { 'ss-api-key': dropzoneId, 'ss-request-api': requestAPI };
  };
  this.isOAuth = function () { return false; };
}

module.exports = { HmacAuthStrategy, BearerAuthStrategy, AnonymousAuthStrategy };

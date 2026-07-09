const pkg = require('../package.json');

const SDK_VERSION = pkg.version;
const SDK_VERSION_HEADER = 'ss-sdk-version';
const SDK_VERSION_VALUE = 'sendsafely-node/' + SDK_VERSION;
const CLIENT_VERSION_HEADER = 'ss-client-version';

// PROCESS-WIDE setting. Calling setClientVersion twice changes the value
// observed by every SendSafely instance — including ones already mid-request.
// Intended for one-time application-startup configuration (e.g. a partner
// SDK identifying itself in server-side telemetry). Per-instance client
// identifiers are explicitly not supported here; if a multi-tenant caller
// needs per-request attribution, set ss-client-version on the request
// headers directly rather than through this hook.
let clientVersion = null;

function setClientVersion(version) {
    clientVersion = version;
}

// Mutates the given headers object in place. Callers must pass a non-null
// object — keeps the contract unambiguous (no return value, no defensive
// branches).
function applyVersionHeaders(headers) {
    headers[SDK_VERSION_HEADER] = SDK_VERSION_VALUE;
    if (clientVersion) {
        headers[CLIENT_VERSION_HEADER] = clientVersion;
    }
}

module.exports = {
    SDK_VERSION,
    SDK_VERSION_HEADER,
    SDK_VERSION_VALUE,
    CLIENT_VERSION_HEADER,
    setClientVersion,
    applyVersionHeaders,
};

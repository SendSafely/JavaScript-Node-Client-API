const pkg = require('../package.json');

const SDK_VERSION = pkg.version;
const SDK_VERSION_HEADER = 'ss-sdk-version';
const SDK_VERSION_VALUE = 'sendsafely-node/' + SDK_VERSION;
const CLIENT_VERSION_HEADER = 'ss-client-version';

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

// XHR variant for paths where headers are set imperatively rather than
// passed as an object (e.g. AnonymousRequest.getHTTPObjForFileUpload).
function applyVersionHeadersToXhr(xhr) {
    xhr.setRequestHeader(SDK_VERSION_HEADER, SDK_VERSION_VALUE);
    if (clientVersion) {
        xhr.setRequestHeader(CLIENT_VERSION_HEADER, clientVersion);
    }
}

module.exports = {
    SDK_VERSION,
    SDK_VERSION_HEADER,
    SDK_VERSION_VALUE,
    CLIENT_VERSION_HEADER,
    setClientVersion,
    applyVersionHeaders,
    applyVersionHeadersToXhr,
};

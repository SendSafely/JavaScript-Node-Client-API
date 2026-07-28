const URL = require('url').URL;
const Version = require('./Version');

function FetchRequest(param) {
    if(!param.hasOwnProperty('signedRequest')) {
        if(typeof param !== 'object') {
            throw new Error('FetchRequest: Invalid parameters');
        }
        if(!param.hasOwnProperty('url')) {
            throw new Error('FetchRequest: url is missing');
        }
        if(!param.hasOwnProperty('strategy')) {
            throw new Error('FetchRequest: strategy is missing');
        }
    }

    let myself = this;
    myself.url = param.url; // scheme + domain + port for signed request, full url for non signed request
    // Dropzone endpoints live under /drop-zone/v2.0, not /api/v2.0 — callers that proxy
    // for an AnonymousRequest (ec2Proxy upload failover) must pass its prefix through.
    myself.apiPrefix = param.hasOwnProperty('apiPrefix') ? param.apiPrefix : '/api/v2.0';
    myself.strategy = param.strategy; // HmacAuthStrategy | BearerAuthStrategy
    myself.requestAPI = param.hasOwnProperty('requestAPI') ? param.requestAPI: 'NODE_API';
    myself.options = {};

    myself.sendRequest = function (url, options) {
        if (options && options.timeout != null && options.signal == null) {
            options = Object.assign({}, options, { signal: AbortSignal.timeout(options.timeout) });
        }
        return fetch(url, options);
    }

    myself.sendSignedRequest = function (endpoint, data) {
        buildHttpsOptions(endpoint, data);
        return fetch(myself.url + myself.apiPrefix + endpoint.url, myself.options);
    };

    let buildHttpsOptions = function(endpoint, data) {
        if(typeof endpoint !== 'object') {
            throw new Error('FetchRequest: Invalid endpoint parameters');
        }
        if(!endpoint.hasOwnProperty('url')) {
            throw new Error('FetchRequest: url is missing');
        }
        if(!endpoint.hasOwnProperty('HTTPMethod')) {
            throw new Error('FetchRequest: HTTPMethod is missing');
        }
        if(!endpoint.hasOwnProperty('mimetype')) {
            throw new Error('FetchRequest: mimetype is missing');
        }

        let timestamp = dateString();
        let bodyString = endpoint.hasOwnProperty('messageData')
            ? JSON.stringify(endpoint.messageData)
            : (data !== '' && data !== null ? JSON.stringify(data) : '');
        let headers = myself.strategy.getHeaders(myself.apiPrefix, endpoint.url, timestamp, bodyString);
        headers['Content-Type'] = endpoint.mimetype;
        Version.applyVersionHeaders(headers);

        let options = {
            headers: headers,
            method: endpoint.HTTPMethod,
        }

        if(data !== null) {
            if(endpoint.mimetype.includes('multipart/form-data')) {
                options.headers['Content-Length'] = Buffer.from(data).length;
                options.body = data;
            } else {
                options.body = JSON.stringify(data);
            }
        }

        myself.options = options;
    }


    let dateString = function() {
        let time = new Date().toISOString();
        return time.substr(0, 19) + "+0000";
    }
}

module.exports = {FetchRequest};

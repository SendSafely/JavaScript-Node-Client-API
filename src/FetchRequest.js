const fetch = require('make-fetch-happen');
const sjcl = require("sjcl");
const URL = require('url').URL;

function FetchRequest(param) {
    if(!param.hasOwnProperty('signedRequest')) {
        if(typeof param !== 'object') {
            throw new Error('FetchRequest: Invalid parameters');
        }
        if(!param.hasOwnProperty('url')) {
            throw new Error('FetchRequest: url is missing');
        }
        if(!param.hasOwnProperty('apiKey')) {
            throw new Error('FetchRequest: apiKey is missing');
        }
        if(!param.hasOwnProperty('apiKeySecret')) {
            throw new Error('FetchRequest: apiKeySecret is missing');
        }
    }

    let myself = this;
    myself.url = param.url; // scheme + domain + port for signed request, full url for non signed request
    myself.apiPrefix = '/api/v2.0';
    myself.apiKey = param.apiKey;
    myself.apiKeySecret = param.apiKeySecret;
    myself.requestAPI = param.hasOwnProperty('requestAPI') ? param.requestAPI: 'NODE_API';
    myself.options = {};

    myself.sendRequest = function (url, options) {
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
        let signature = myself.apiKey + myself.apiPrefix + endpoint.url.split("?")[0] + timestamp;
        if(endpoint.hasOwnProperty('messageData')) {
            signature += JSON.stringify(endpoint.messageData);
        } else if(data !== '' && data !== null) {
            signature += JSON.stringify(data);
        }
        signature = signMessage(signature);

        let method = endpoint.HTTPMethod;
        let headers = {
            'Content-Type': endpoint.mimetype,
            'ss-api-key':myself.apiKey,
            'ss-request-timestamp': timestamp,
            'ss-request-signature': signature,
            'ss-request-api': myself.requestAPI,
        };

        let options = {
            headers: headers,
            method: method,
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
    
    let signMessage = function(messageString) {
        let hmacFunction = new sjcl.misc.hmac(sjcl.codec.utf8String.toBits(myself.apiKeySecret), sjcl.hash.sha256);// Key, Hash
        return sjcl.codec.hex.fromBits(hmacFunction.encrypt(messageString));
    }
}

module.exports = {FetchRequest};
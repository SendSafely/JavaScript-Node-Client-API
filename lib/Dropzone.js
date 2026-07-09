const URL = require('url').URL;
const httpClient = require('./http');
const Version = require('./Version');

/**
 * @param eventHandler
 * @param {string} url
 * @param {string} dropzoneId
 * @param {string} requestAPI
 * @constructor
 */
function AnonymousRequest(eventHandler, url, dropzoneId, requestAPI) {
	const myself = this;

	this.apiPrefix = '/drop-zone/v2.0';
	this.url = url;
	this.dropzoneId = dropzoneId;
	this.eventHandler = eventHandler;
	this.requestAPI = requestAPI;

	this.sendRequest = function (requestType, messageData, a_sync) {
        const headers = {
            'ss-api-key': myself.dropzoneId,
            'ss-request-api' : myself.requestAPI
        };
        Version.applyVersionHeaders(headers);

		return httpClient.ajax({
			url: myself.url + myself.apiPrefix + requestType.url,
			type: requestType.HTTPMethod,
			timeout: 25000,
			data: messageData == null ? null : JSON.stringify(messageData),
			contentType: requestType.mimetype,
			headers: headers
		});
	};

	this.getHTTPSOptionForFileUpload = function (uri, method, messageData, boundary, isEC2Proxy) {
		let headers = {
			'Content-Type': 'multipart/form-data; boundary=' + boundary,
			'ss-api-key': myself.dropzoneId,
			'ss-request-api' : myself.requestAPI
		};
		let url = new URL(myself.url + myself.apiPrefix + uri);

		if (!isEC2Proxy) {
			headers = {};
			url = new URL(uri);
		} else {
			Version.applyVersionHeaders(headers);
		}

		return {
			hostname: url.hostname,
			port: url.port,
			path: url.pathname + url.search,
			headers: headers,
			method: method,
		};
	};

	this.processAjaxData = function (ajax, success_callback) {
		ajax.fail(function (xhr, status, error) {
			myself.eventHandler.raiseError(this.NETWORK_ERROR, error.message);
		})
			.done(function (data) {
				if (typeof data == 'string') {
					data = JSON.parse(data);
				}
				if (data.response === 'SUCCESS') {
					if (success_callback !== undefined) {
						success_callback(data);
					}
				} else {
					myself.eventHandler.raiseError(data.response, data.message);
				}
			});
	};

	this.extend = function (a, b) {
		for (const key in b) {
			if (b.hasOwnProperty(key)) {
				a[key] = b[key];
			}
		}
		return a;
	};
}


module.exports = {AnonymousRequest};

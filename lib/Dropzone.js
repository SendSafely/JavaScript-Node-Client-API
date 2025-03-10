const URL = require('url').URL;
const Window = require('./window');
const window = new Window();
const $ = require('jquery')(window);
const XMLHttpRequest = require('xmlhttprequest').XMLHttpRequest;

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

		if (typeof a_sync === 'undefined') {
			a_sync = true;
		}

		return $.ajax({
			url: myself.url + myself.apiPrefix + requestType.url,
			type: requestType.HTTPMethod,
			timeout: 25000,
			data: messageData == null ? null : JSON.stringify(messageData),
			contentType: requestType.mimetype,
			headers: {
				'ss-api-key': myself.dropzoneId,
				'ss-request-api' : myself.requestAPI
			},
			crossDomain: true,
			async: a_sync,
			retryCount: 2, //Need to Implement.
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
		}

		return {
			hostname: url.hostname,
			port: url.port,
			path: url.pathname + url.search,
			headers: headers,
			method: method,
		};
	};

	this.getHTTPObjForFileUpload = function (uri, messageData, boundary, a_sync) {
		const xhr = new XMLHttpRequest();
		const url = myself.url + myself.apiPrefix + uri;

		xhr.open('POST', url, a_sync);

		xhr.setRequestHeader('Content-Type', 'multipart/form-data; boundary=' + boundary);
		xhr.setRequestHeader('ss-api-key', myself.dropzoneId);
		xhr.setRequestHeader('ss-request-api', myself.requestAPI);

		return xhr;
	};

	/**
	 * Function used to deal with Errors, and callbacks for AJAX Requests.
	 * Progress callback cannot be done when async is false.
	 * @ignore
	 * @param {promise} ajax AJAX Promise
	 * @param {function} error_callback Function is called when there is an error with the function or when there is an
	 *     error in the response.
	 * @param {function} success_callback Function is called when data is received from the server with no errors.
	 * @param {function} progress_callback Function is called when the data is being uploaded.
	 */
	this.processAjaxData = function (ajax, success_callback) {
		ajax.fail(function (xhr, status, error) {
			// Wrap the error to a format we recognize.
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

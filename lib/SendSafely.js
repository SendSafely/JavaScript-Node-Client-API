const URL = require('url').URL;
const { pbkdf2Sha256Hex, randomKeycode } = require('./crypto-utils');
const fs = require('fs');
const path = require("path");
const openpgpOps = require('./openpgp-ops');
const httpClient = require('./http');
const {AnonymousRequest} = require('./Dropzone');
const {FileUtil, buildDownloadPath} = require('./FileUtil');
const {FetchRequest} = require('./FetchRequest');
const Version = require('./Version');
const { HmacAuthStrategy, BearerAuthStrategy } = require('./AuthStrategy');

const UNHANDLED_EXCEPTION = "UNHANDLED_EXCEPTION";

// HTML-escape replacement for jQuery's $('<div/>').text(x).html() idiom that
// the worker-era listener used to neutralize file names before handing them
// to consumer statusCb. Returns "" for null/undefined to match jQuery's
// behavior on those inputs.
function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Invoke a consumer callback; if it throws synchronously, rethrow
// asynchronously to match jQuery 3's deferred-handler semantics
// rather than corrupting the surrounding promise chain.
function _invokeCallbackSafely(fn /* , ...args */) {
    if (typeof fn !== 'function') return;
    var args = Array.prototype.slice.call(arguments, 1);
    try { fn.apply(null, args); }
    catch (e) { setImmediate(function () { throw e; }); }
}

/**
 * @description The only constructor for the library.
 * @param {String} url The SendSafely host/url that the API will connect to.
 * @param {String} apiKey The API Key that will be used to authenticate to SendSafely.
 * @param {String} apiSecret The API Secret that will be used to authenticate to SendSafely.
 * @returns {constructor}
 */
function SendSafely(url, apiKeyId, apiKeySecret, requestAPI, _opts){
	/**
	 * @namespace SendSafely
	 */
  var myself = this;

  this.async = true;
  this.NETWORK_ERROR = "NETWORK_ERROR";
  this.NOT_INITIALIZED_ERROR = "API_NOT_INITIALIZED";
  this.apiKeyId = apiKeyId;
  this.apiKeySecret = apiKeySecret;
  this.systemName = "";
  this.uploadAPI = undefined;
  this.url = url;
  this.requestAPI = (requestAPI === undefined) ? "NODE_API" : requestAPI;
  // Auth strategy: a pre-built strategy (e.g. Bearer, via SendSafely.withBearerToken) when
  // supplied, otherwise the default HMAC strategy. All signing/credential handling funnels
  // through this; the named SDK methods are unaware of which scheme is in use.
  this.strategy = (_opts && _opts.strategy) || new HmacAuthStrategy(apiKeyId, apiKeySecret, this.requestAPI);
  this.wrapperRequest = new FetchRequest({url: url, strategy: this.strategy, requestAPI: this.requestAPI});

  this.eventHandler = new EventHandler(myself);
  this.executor = new Executor(myself.eventHandler);

  // Replace the cached access token (Bearer mode); no-op for HMAC.
  this.setAccessToken = function (t) {
    if (typeof myself.strategy.setToken === 'function') myself.strategy.setToken(t);
  };

  if (apiKeyId !== null && apiKeySecret === null){
  	this.request = new AnonymousRequest(myself.eventHandler, url, apiKeyId, myself.requestAPI);
  } else {
    this.request = new SignedRequest(myself.eventHandler, url, this.strategy, myself.requestAPI);
  }

	//Main API functions
	//Functions
	/**
	 * Function to verify the version of the application against the server.
	 * @ignore
	 * @param {string} api_identifier An identifier describing the API. If none is supplied, the default API one will be used.
	 * @param {function} finished The callback that handles the response.
	 * @throws {SendSafely#error} Raised if an error happens. Code contains a response code originating from the server. Message is a more descriptive error message.
	 */
  this.verifyVersion = function (api_identifier, finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    myself.executor.run(function() {
      new VerifyVersion(myself.eventHandler, myself.request).execute(api_identifier, myself.async, finished);
    }, 'Verify Version Failed');
  };

  /**
	 * A helper function to parse out links from a String of text. Returns a list of links found in the provided text.
	 * @param {String} text The text to be parsed.
	 * @returns {List}
	 */
  this.parseLinks = function(text) {
    try {
      return new ParseSendSafelyLinks().execute(text);
    } catch (err) {
      myself.executor.handleError(err, "Failed to parse links");
    }
  };

  this.versionUpdated = function(host, versionInfo, finished) {
    myself.executor.run(function() {
      new AddVersionInfo(myself.eventHandler, myself.request).execute(host, versionInfo, myself.async, finished);
    }, 'Update Version Failed');
  };

	/**
	 * Verifies the API Key and API Secret with the server. Returns the email address of the user that owns the API key.
	 * @param {function} finished function (user)
     * @fires {sendsafely#error}
	 * @returns {promise}
	 */
	this.verifyCredentials = function(finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    new VerifyCredentials(myself.eventHandler, myself.request).execute(myself.async, finished);
	};

	/**
	 * Returns profile information related to the authenticated API user.
	 * @param {function} finished function (user)
	 * @param {function} customErrorEvent Optional custom error event (to replace user.information.failed).
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.getUserInformation = function (finished, customErrorEvent) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    var handler = new GetUserInformation(myself.eventHandler, myself.request);

    handler.customErrorEvent = customErrorEvent;
    handler.execute(myself.async, finished);
  };

	/**
	 * Deletes a file from a package. 
	 * @param {String} packageId The unique package id of the package for the delete file operation.
	 * @param {String} fileId The unique file id of the file to delete.
	 * @param {function} finished Optional callback function.
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
	this.deleteFile = function (packageId, fileId, finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    myself.executor.run(function() {
      if(myself.uploadHandler !== undefined) {
        myself.uploadHandler.abort(fileId);
      }

      new DeleteFile(myself.eventHandler, myself.request).execute(packageId, fileId, myself.async, finished);
    }, 'Deleting file failed');
	};

    this.deleteFileWithDirectory = function (packageId, fileId, directoryId, finished) {

        try { this.checkAPIInitialized();}
        catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

        myself.executor.run(function() {
            if(myself.uploadHandler !== undefined) {
                myself.uploadHandler.abort(fileId);
            }

            new DeleteFileWithDirectory(myself.eventHandler, myself.request).execute(packageId, fileId, directoryId, myself.async, finished);
        }, 'Deleting file failed');
    };

	/**
	 * Removes a recipient from a given package.
	 * @param {String} packageId The unique package id of the package for the remove recipient operation.
	 * @param {String} recipientId The unique recipient id of the recipient to remove from the package.
	 * @param {function} finished optional callback function.
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
	this.removeRecipient = function (packageId, recipientId, finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    new RemoveRecipient(myself.eventHandler, myself.request).execute(packageId, recipientId, myself.async, finished);
	};

	/**
	 * Retrieves organization-level information about the SendSafely enterprise account that the currently authenticated user belongs to. 
	 * @param {function} finished function(host, systemName, allowUndisclosedRecipients, headerColor, linkColor, messageEncryption)
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
	this.enterpriseInfo = function (finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    new GetEnterpriseInformation(myself.eventHandler, myself.request).execute(myself.async, finished);
	};

	/**
	 * Adds a recipient to a given package.
	 * @param {String} packageId The unique packageId that you are adding the recipient to.
	 * @param {String} email The recipient email to be added.
	 * @param {String} keyCode keyCode value of the package adding the recipient to.
	 * @param {function} finished function (<a href="#Recipient">Recipient</a>)
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
	this.addRecipient = function (packageId, email, keyCode, finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    var handler = new AddRecipient(myself.eventHandler, myself.request);

    handler.execute(packageId, email, keyCode, myself.async, finished);
	};

	this.addRecipientWithSMS = function (packageId, email, keycode, phonenumber, countryCode, finished) {
	  try { this.checkAPIInitialized();}
	  catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}
      myself.executor.run(function() {
    	new AddRecipientWithSMS(myself.eventHandler, myself.request).execute(packageId, email, phonenumber, countryCode, myself.async, finished);
  	  }, 'Failed to add recipient');
	};

	/**
	 * Adds a list of recipients to a given package.
	 * @property notes A recipient object list describing the newly added recipients.
	 * @param {String} packageId The unique package id of the package for the add recipient operation.
	 * @param {String} emails The recipient email to be added.
	 * @param {String} keyCode keyCode value of the package adding the recipient to.
	 * @param {function} finished function (<a href="#Recipient">Recipient</a>)
	 * @param {function} customErrorEvent Optional custom error event (to replace recipients.add.failed).
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.addRecipients = function (packageId, emails, keycode, finished, customEvent) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    var handler = new AddRecipients(myself.eventHandler, myself.request);

    if(customEvent != undefined) {
      handler.customErrorEvent = customEvent
    }

    handler.execute(packageId, emails, keycode, myself.async, finished);
  };

	/**
	 * Adds a phone number to a recipient for SMS verification .
	 * @param {String} packageId The unique packageId that you are updating.
	 * @param {String} recipientId The recipientId to which the phone number will be added.
	 * @param {String} phonenumber A phone number to be used for SMS verification.
	 * @param {String} countryCode A country code associated with the phone number.
	 * @param {function} finished function ()
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
	this.addRecipientPhonenumber = function (packageId, recipientId, phonenumber, countryCode, finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    new AddRecipientPhonenumber(myself.eventHandler, myself.request).execute(packageId, recipientId, phonenumber, countryCode, myself.async, finished);
	};

  this.uploadKeycode = function(packageId, publicKeys, keyCode, callback) {
    var handler = new EncryptAndUploadKeycodes(myself.eventHandler, myself.request);
    handler.execute(packageId, publicKeys, keyCode, myself.async, callback);
  };

  this.getPublicKeys = function(packageId, callback) {
    var getPublicKeysHandler = new GetPublicKeys(myself.eventHandler, myself.request);
    getPublicKeysHandler.execute(packageId, myself.async, callback);
  };

	/**
	 * Finalizes the package so it can be delivered to the recipients. Returns the Secure Link needed for recipients to access the package. 
	 * @param {String} packageId The unique packageId that is being finalized.
	 * @param {String} packageCode The package code used to create the secure link.
	 * @param {String} keycode The keycode used to encrypt the message and files.
	 * @param {function} finished function(url)
	 * @fires {sendsafely#error}
	 * @returns {String}
	 */
	this.finalizePackage = function (packageId, packageCode, keyCode, finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    myself.unbind('keycodes.uploaded');
    myself.executor.run(function() {
        myself.on('keycodes.uploaded', function() {
          myself.unbind('keycodes.uploaded');
            var handler = new FinalizePackage(myself.eventHandler, myself.request);
            handler.notifyRecipients = myself.shouldNotifyRecipients();
            handler.readOnlyPdf = myself.readOnlyPdf;
            handler.execute(packageId, packageCode, keyCode, myself.async, finished);
        });

        myself.unbind('received.publickeys');
        myself.on('received.publickeys', function(publickeys) {
		
	      myself.uploadKeycode(packageId, publickeys, keyCode, function() {
	        myself.eventHandler.raise('keycodes.uploaded', {});
	      });		
        });

      var getPublicKeysHandler = new GetPublicKeys(myself.eventHandler, myself.request);
      getPublicKeysHandler.execute(packageId, myself.async, function(publicKeys) {
        myself.eventHandler.raise('received.publickeys', publicKeys);
      });
    }, 'Failed to finalize package');
	};

  /**
	 * Finalizes a package without any recipients being specified. Returns the Secure Link needed for recipients to access the package. 
	 * @param {String} packageId The unique packageId that is being finalized.
	 * @param {String} packageCode The package code used to create the secure link.
	 * @param {String} keycode The keycode used to encrypt the message and files.
	 * @param {String} password A password that will be required in order to access the package. Leave as undefined if no password should be required.
	 * @param {function} finished function (url)
	 * @fires {sendsafely#error}
	 * @returns {String}
	 */
  this.finalizeUndisclosedPackage = function (packageId, packageCode, keyCode, password, finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    var handler = new FinalizePackage(myself.eventHandler, myself.request);
    handler.undisclosedRecipients = true;
    handler.password = password;
    handler.execute(packageId, packageCode, keyCode, myself.async, finished);
  };

  this.shouldNotifyRecipients = function() {
        var notifyRecipients = (myself.notifyRecipients === undefined) ? false : myself.notifyRecipients;
        return notifyRecipients;
  };
    
	/**
	 * @ignore
	 * Syncs a message with the server.
	 * @param {String} packageId The unique packageId that you are adding the message to.
	 * @param {String} message The message to be uploaded.
	 * @param {function} finished function ()
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.saveMessage = function (packageId, message, finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    var handler = new SaveMessage(myself.eventHandler, myself.request);

    if(myself.uploadAPI != undefined) {
      handler.uploadAPI = myself.uploadAPI;
    }

    handler.execute(packageId, message, myself.async, finished);
  };

  /**
	 * @ignore
	 * Deletes a temporary package.
	 * @param {String} packageId The packageId to be deleted.
	 * @param {function} finished function ()
	 * @fires {sendsafely#error}
	 */
	this.deleteTempPackage = function (packageId, finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    new DeleteTempPackage(myself.eventHandler, myself.request).execute(packageId, myself.async, finished);
	};

  /**
   * Permanently deletes a package.
   * @param {string} The packageId to be deleted.
   * @event sendsafely.error function(code, message) Raised if an error happens. Code contains a response code originating from the server. Message is a more descriptive error message.
   * @returns {void}
   */
  this.deletePackage = function (packageId, finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    new DeletePackage(myself.eventHandler, myself.request).execute(packageId, myself.async, finished);
  };

  this.renameDirectory = function (packageId, directoryId, directoryName, finished) {
    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}
    new UpdateDirectoryName(myself.eventHandler, myself.request).execute(packageId, directoryId, directoryName,myself.async, finished);
  };

  this.getDirectory = function (packageId, directoryId, directoryIndex, fileIndex, sortField, sortOrder, finished) {
    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    new GetDirectory(myself.eventHandler, myself.request).execute(packageId, directoryId, directoryIndex, fileIndex, sortField, sortOrder, myself.async, finished);
  };

  this.deleteDirectory = function (packageId, directoryId, finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    myself.executor.run(function() {
      if(myself.uploadHandler !== undefined || myself.uploadHandler1 !== undefined) {
        if(myself.uploadHandler !== undefined)
          myself.uploadHandler.abort(directoryId);
        else
          myself.uploadHandler1.abort(directoryId);
      }

      new DeleteDirectory(myself.eventHandler, myself.request).execute(packageId, directoryId, myself.async, finished);
    }, 'Deleting Directory failed');
  };

  /**
	 * Fetch the latest metadata for a specific package using a PackageId.
	 * @param {String} packageId The packageId of the package.
	 * @param {function} finished function (<a href="#PackageInformation">PackageInformation</a>)
	 * @fires {sendsafely#error}
	 * @fires {package.information#failed}
	 * @returns {void}
	 */
	this.packageInformation = function (packageId, finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    new GetPackageInformation(myself.eventHandler, myself.request).execute(packageId, myself.async, finished);
	};

	/**
	 * Fetch the latest metadata for a specific package using a Secure Link.
	 * @param {String} link The Secure Link for the package.
	 * @param {function} finished function (<a href="#PackageInformation">PackageInformation</a>)
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.packageInformationFromLink = function (link, finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    new GetPackageInformation(myself.eventHandler, myself.request).executeFromLink(link, myself.async, finished);
  };

    this.getActivePackages = function(rowIndex, finished){
        try { this.checkAPIInitialized();}
        catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}
        new GetSentPackages(myself.eventHandler, myself.request).execute(rowIndex, "", myself.async, finished);
    }

    this.getReceivedPackages = function(rowIndex, finished){
        try { this.checkAPIInitialized();}
        catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}
        new GetReceivedPackages(myself.eventHandler, myself.request).execute(rowIndex, "", myself.async, finished);
    }

    this.getArchivedPackages = function (rowIndex, finished) {
        try { this.checkAPIInitialized();}
        catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}
        new GetArchivedPackages(myself.eventHandler, myself.request).execute(rowIndex, "", myself.async, finished);
    }

  this.getActivityLog = function(packageId, rowIndex, finished){
    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}
    var postData = {};
    postData['rowIndex'] = rowIndex==undefined?0:rowIndex;
    new GetPackageActivityLog(myself.eventHandler, myself.request).execute(packageId, postData, "", myself.async, finished);
  }

  this.getRecipient = function (packageId, recipientId, finished) {
    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    new GetRecipient(myself.eventHandler, myself.request).execute(packageId, recipientId, myself.async, finished);
  };

  this.getFileInformation = function (packageId, directoryId, fileId, finished) {
    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    new GetFileFromDirectory(myself.eventHandler, myself.request).execute(packageId, directoryId, fileId, myself.async, finished);
  };

  this.updateRecipientRole = function (packageId, recipientId, roleName, finished) {
    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    new UpdateRole(myself.eventHandler, myself.request).execute(packageId, recipientId, roleName, myself.async, finished);
  };

	/**
	 * Update the package expiration (days). Setting the life to 0 means the package will not expire.  
	 * @param {String} packageId The packageId to update.
	 * @param {int} data Json object containing a life parameter (integer). For example, {life:15}. int value must be a valid number between 0 and 365.
	 * @param {function} finished function (<a href="#PackageInformation">PackageInformation</a>)
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
	this.updatePackage = function (packageId, data, finished){

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

		new UpdatePackage(myself.eventHandler, myself.request).execute(packageId, data, myself.async, finished);
	};
	
  this.updateFile = function (packageId, fileId, fileName, finished) {
    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}
    new UpdateFileName(myself.eventHandler, myself.request).execute(packageId, fileId, fileName, myself.async, finished);
  };

	/**
	 * Adds a secure message to the package. If a message already exists it will be overwritten. 
	 * @param packageId {String} The packageId that you are adding the message to.
	 * @param keyCode {String} The keycode for the package.
	 * @param serverSecret {String} The server secret associated with the package.
	 * @param message {String} The message to be encrypted (text).
	 * @param finished {function} function ()
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.encryptAndUploadMessage = function (packageId, keyCode, serverSecret, message, finished) {

    try { this.checkAPIInitialized();}
    catch (err) {failureCb(this.NOT_INITIALIZED_ERROR, err.message); return;}

    new EncryptMessage(myself.eventHandler).execute(message, packageId, keyCode, serverSecret, function(encryptedMessage) {
      new SaveMessage(myself.eventHandler, myself.request).execute(packageId, encryptedMessage, myself.async, finished);
    });
  };

	/**
	 * Adds a list of files to the package. Files will be encrypted and uploaded to the server and stored in the root directory of the package. 
	 * @param {String} packageId The packageId that you are adding the file to.
	 * @param {String} keyCode The key code associated with the package.
	 * @param {String} serverSecret The server secret associated with the package.
	 * @param {List<absoluteFilePath>} An array of absolute file path to files that are being uploaded or an array of <File> (Deprecated) that are being uploaded.
	 * @param {String} uploadType Optional Leave blank (or specify 'NODE_API').
	 * @param {function} finished function (packageId, fileId, fileSize, fileName)
	 * @fires {sendsafely#progress}
	 * @fires {file.upload#error}
	 * @fires {sendsafely.files#attached}
	 * @returns {void}
	 */
  this.encryptAndUploadFiles = function(packageId, keyCode, serverSecret, files, uploadType, finished) {

    if(myself.uploadHandler === undefined) {
      myself.uploadHandler = new EncryptAndUploadFile(myself.eventHandler, myself.request);
    }

    if(myself.async != undefined) {
      myself.uploadHandler.async = myself.async;
    }

    myself.executor.run(function() {
      myself.uploadHandler.addFilesToDirectory(packageId, "", keyCode, serverSecret, files, uploadType, function(state, obj){
          },
          function(packageId, fileId, fileSize, fileName) {
            var event = {'fileId': fileId, 'packageId': packageId, 'keyCode': keyCode, 'fileSize': fileSize, 'fileName': fileName};
            myself.eventHandler.raise("sendsafely.files.uploaded", event);
            finished(packageId, fileId, fileSize, fileName);
          });
    }, 'File Upload Failed');
  };

	/**
	 * Adds a list of files to the package within a specific directory . Files will be encrypted and uploaded to the server. 
	 * @param {String} packageId The packageId that you are adding the file to.
	 * @param {String} keyCode The key code associated with the package.
	 * @param {String} serverSecret The server secret associated with the package.
	 * @param {List<absoluteFilePath>} An array of absolute file path to files that are being uploaded or an array of <File> (Deprecated) that are being uploaded.
	 * @param {String} uploadType Optional Leave blank (or specify 'NODE_API').
	 * @param {String} directoryId The directoryId of the directory that you want to add the files to.
	 * @param {function} finished function (packageId, fileId, fileSize, fileName)
	 * @fires {sendsafely#progress}
	 * @fires {file.upload#error}
	 * @fires {sendsafely.files#attached}
	 * @returns {void}
	 */
  this.encryptAndUploadFilesToDirectory = function(packageId, keyCode, serverSecret, files, uploadType, directoryId, finished) {

    if(myself.uploadHandler === undefined) {
      myself.uploadHandler = new EncryptAndUploadFile(myself.eventHandler, myself.request);
    }

    myself.executor.run(function() {
      myself.uploadHandler.addFilesToDirectory(packageId, directoryId, keyCode, serverSecret, files, uploadType, function(state, data) {
        myself.eventHandler.raise("sendsafely.status", {'state': state, 'data': data});
      }, finished);
    }, 'File Upload Failed');
  };

  // Trusted-device key operations hit the v1-deferred public-key path and are not available
  // under OAuth. When the active strategy is Bearer, raise a typed error and return true so the
  // caller can early-return; otherwise return false and the operation proceeds unchanged.
  // customErrorEvent must be the same custom event a real server failure of the operation
  // would raise (keycode.get.failed / publickey.add.failed) — EventHandler.raiseError routes
  // to a bound custom event in preference to sendsafely.error, so raising without it would
  // leave consumers listening on the operation's documented failure channel hearing nothing.
  var oauthBlocksTrustedDevice = function(customErrorEvent) {
    if(isOAuthStrategy(myself.strategy)){
      myself.eventHandler.raiseError('OAUTH_TRUSTED_DEVICE_UNSUPPORTED',
        'Trusted-device key operations are not available under OAuth in v1; use an HMAC API key.',
        customErrorEvent);
      return true;
    }
    return false;
  };

  /**
	 * Downloads and decrypts a keycode from the server for the given a packageId and Trusted Device key pair.
	 * @param privateKey {String} The private key portion of the Trusted Device key pair.
	 * @param publicKeyId {String} The public key id associated with the Trusted Device key pair.
	 * @param packageId {String} The package id you would like to obtain the keycode for.
	 * @param callback {function} function (keycode)
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.getKeycode = function(privateKey, publicKeyId, packageId, callback)
  {
    if(oauthBlocksTrustedDevice('keycode.get.failed')){ return; }
    var handler = new GetKeycode(myself.eventHandler, myself.request);
    handler.execute(privateKey, publicKeyId, packageId, myself.async, callback);
  };

  /**
	 * @ignore
	 * Generates a new Trusted Device key pair. The private key and public key returned. The public key is uploaded and stored on the SendSafely servers. The public key returned also includes an "id" parameter that used to uniquely identify the Trusted Device key. 
	 * @param description {String} Field used to describe or name the key pair (ie My Node Script Key).
	 * @param visible {String} (deprecated) visibility setting of the keypair (deprecated).
	 * @param callback {function} function (privateKey, publicKey).
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.generateKeyPair = function(description, visible, callback) {
    if(oauthBlocksTrustedDevice('publickey.add.failed')){ return; }

    var uploadFunction = function(privateKey, publicKey) {
      // Upload the public key.
      var handler = new AddPublicKey(myself.eventHandler, myself.request);
      handler.execute(publicKey, description, visible, myself.async, function(publicKey) {
        if(callback !== undefined) {
          callback(privateKey, publicKey);
        }
      });
    };

    myself.executor.run(function() {
      var generateKeyPairFunction = new GenerateKeyPair(myself.eventHandler);
      generateKeyPairFunction.execute(uploadFunction);
    });
  };

  /**
	 * Generates a new Trusted Device key pair. The private key and public key returned. The public key is uploaded and stored on the SendSafely servers. The public key returned also includes an "id" parameter that used to uniquely identify the Trusted Device key. 
	 * @param description {String} Field used to describe or name the key pair (ie My Node Script Key).
	 * @param callback {function} function (privateKey, publicKey).
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
    this.generateRsaKeyPair = function(description, callback) {
        if(oauthBlocksTrustedDevice('publickey.add.failed')){ return; }

        var uploadFunction = function(privateKey, publicKey) {
            // Upload the public key.
            var handler = new AddPublicKey(myself.eventHandler, myself.request);
            handler.execute(publicKey, description, "", myself.async, function(publicKey) {
                if(callback !== undefined) {
                    callback(privateKey, publicKey);
                }
            });
        };

        myself.executor.run(function() {
            var generateKeyPairFunction = new GenerateKeyPair(myself.eventHandler);
            generateKeyPairFunction.execute(uploadFunction);
        });
    };

  /**
	 * Revokes a Trusted Device key pair. Only call this function if the private key has been deleted and should never be used anymore (cannot be undone). 
	 * @param publicKeyId {String} The public key id to revoke.
	 * @param callback {function}
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.removePublicKey = function(publicKeyId, callback)
  {
    if(oauthBlocksTrustedDevice('public.key.delete.failed')){ return; }
    var handler = new RemovePublicKey(myself.eventHandler, myself.request);
    handler.execute(publicKeyId, myself.async, callback);
  };

  /**
	 * Downloads and decrypts an individual file from the root directory of a package.
	 * @param packageId {String} The packageId of the package containing the file.
	 * @param fileId {String} The fileId of the file to be downloaded. 
	 * @param keyCode {String} The keycode associated with the package.
   * @param config {Json} JSON configuration object required for file downloads over 2GB. To enable large file downloads, pass a JSON object with a path and/or fileName property. For example {path:'downloads', fileName:'example.txt'} results in the downloaded file being named "example.txt" to the "downloads" directory relative to the working directory. If the fileName property is omitted, the fileName returned from SendSafely will be used.
   * @fires {sendsafely#error}
	 * @fires {download#progress}
	 * @fires {file#decrypted}
	 * @fires {save#file}
   * @fires {file#saved}
	 * @returns {void}
	 */
  this.downloadFile = function(packageId, fileId, keyCode, config) {
    if(myself.downloadHandler === undefined) {
      myself.downloadHandler = new DownloadAndDecryptFile(myself.eventHandler, myself.request);
    }

    myself.executor.run(function() {
      myself.downloadHandler.addFile(packageId, fileId, keyCode, config);
    });
  };

  /**
   * Downloads and decrypts an individual file from a specific directory of the package.
   * @param packageId {String} The packageId of the package containing the file.
   * @param directoryId {String} The directoryId of the directory containing the file.
   * @param fileId {String} The fileId of the file to be downloaded.
   * @param keyCode {String} The keycode associated with the package.
   * @param config {Json} JSON configuration object required for file downloads over 2GB. To enable large file downloads, pass a JSON object with a path and/or fileName property. For example {path:'downloads', fileName:'example.txt'} results in the downloaded file being named "example.txt" to the "downloads" directory relative to the working directory. If the fileName property is omitted, the fileName returned from SendSafely will be used.
   * @fires {sendsafely#error}
   * @fires {download#progress}
   * @fires {file#decrypted}
   * @fires {save#file}
   * @fires {file#saved}
   * @returns {void}
   */
  this.downloadFileFromDirectory = function(packageId, directoryId, fileId, keyCode, config) {
    if(myself.downloadHandler === undefined) {
      myself.downloadHandler = new DownloadAndDecryptFile(myself.eventHandler, myself.request);
    }

    myself.executor.run(function() {
      myself.downloadHandler.addFileFromDirectory(packageId, directoryId, fileId, keyCode, config);
    });
  };

  /**
	 * Creates a new directory in the root folder of a Workspace. Only Workspace packages support this function.
	 * @param packageId {String} The package id of the package.
	 * @param directoryName {String} The name of the directory to be added to the workspace.
	 * @param finished {function} function ()
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.createDirectory = function (packageId, directoryName, finished) {
    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    new CreateDirectory(myself.eventHandler, myself.request).execute(packageId, directoryName, myself.async, finished);
  };

  /**
	 * Creates a new sub-directory in a Workspace. Only Workspace packages support this function.
	 * @param packageId {String} The package id of the package.
	 * @param directoryName {String} The name of the directory to be added to the workspace.
	 * @param directoryId {String} The directory id of parent directory in which to create this sub-directory. If creating a directory in the root directory of a Workspace, this will be the packageDirectoryId property of the Workspace Package. 
	 * @param finished {function} function ()
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.createSubdirectory = function (packageId, directoryName, directoryId, finished) {
    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}
    new CreateSubdirectory(myself.eventHandler, myself.request).execute(packageId, directoryName, directoryId, myself.async, finished);
  };

  /**
	 * Moves a directory from its current location to the specified destination directory in a Workspace package.
	 * @param packageId {String} The package id of the package.
	 * @param sourceDirectoryId {String} The directory id of the directory to move. The source directory and the target directory must belong to the same package. 
	 * @param targetDirectoryId {String} The directory id of the destination directory. The source directory and the target directory must belong to the same package. 
	 * @param finished {function} function ()
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.updateDirectory = function (packageId, sourceDirectoryId, targetDirectoryId, finished) {
    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}
    new UpdateDirectory(myself.eventHandler, myself.request).execute(packageId, sourceDirectoryId, targetDirectoryId,myself.async, finished);
  };

  this.copyFile = function(sourcePackageId, sourceFileId, sourceServerSecret, sourceKeycode, targetPackageId, targetDirectoryId, targetServerSecret, targetKeycode, finished){
    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    var messageEncryptor = new EncryptMessage(myself.eventHandler);
    var fileKey = sourceServerSecret + sourceKeycode;
    messageEncryptor.execute(fileKey, sourcePackageId, targetKeycode, targetServerSecret, function(encryptedMessage){
      var fileKey = encryptedMessage;
      new CopyFile(myself.eventHandler, myself.request).execute(sourcePackageId, sourceFileId, fileKey, targetPackageId, targetDirectoryId, targetServerSecret, targetKeycode, myself.async, finished);
    });

  };

  /**
	 * Utility function to check if the package has any ongoing uploads.
	 * @property notes Returns a boolean flag to determine if the package has any ongoing uploads.
	 * @returns {boolean}
	 */
  this.hasOngoingUploads = function() {

    if(myself.uploadHandler === undefined) {
      return false;
    }

    return myself.uploadHandler.encrypting > 0 || myself.uploadHandler.uploading > 0;
  };

	/**
	 * Create a new empty package. 
	 * @param finished {function} function (packageId, serverSecret, packageCode, keyCode)
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.createPackage = function (finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    myself.executor.run(function() {
      new CreatePackage(myself.eventHandler, myself.request).execute(myself.async, finished);
    }, 'Create Package Failed');
  };

	/**
	 * Create a new empty Workspace package. 
	 * @param finished {function} function (packageId, serverSecret, packageCode, keyCode)
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.createWorkspace = function (finished) {

    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    myself.executor.run(function() {
      new CreatePackage(myself.eventHandler, myself.request).setVdr(true).execute(myself.async, function (packageId, serverSecret, packageCode, keyCode) {
        myself.unbind('keycodes.uploaded');
        myself.on('keycodes.uploaded', () => finished(packageId, serverSecret, packageCode, keyCode));
        
        myself.unbind('received.publickeys');
        
        myself.on('received.publickeys', function (publickeys) {
          myself.uploadKeycode(packageId, publickeys, keyCode, function() {
            myself.eventHandler.raise('keycodes.uploaded', {});
          });		
        });
        
        myself.getPublicKeys(packageId, function (publicKeys) {
          myself.eventHandler.raise('received.publickeys', publicKeys);
        });
      });
    }, 'Create Package Failed');
  };

	/**
	 * @ignore
	 * Encrypt a new message. This function will only encrypt the message, not upload it to the server.
	 *
	 * @param packageId {String} The unique packageId that you are adding the message to
	 * @param keyCode {String} The keycode used to encrypt the message with
	 * @param serverSecret {String} The server secret used to encrypt the message with
	 * @param message {String} The message to be encrypted.
	 * @param finished {function} function (encryptedMessage)
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.encryptMessage = function(packageId, keyCode, serverSecret, message, finished) {
    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    var handler = new EncryptMessage(myself.eventHandler);
    handler.execute(message, packageId, keyCode, serverSecret, finished);

  };

	/**
	 * Decrypt the message from a package.
	 * @param packageId {String} The packageId that contains the message to be decrypted.
	 * @param keyCode {String} The keycode associated with the package.
	 * @param serverSecret {String} The server secret associated with the package.
	 * @param ciphertext {String} The ciphertext message to decrypt.
	 * @param finished {function} function(decryptedMessage)
	 * @fires {sendsafely#error}
	 * @returns {void}
	 */
  this.decryptMessage = function(packageId, keyCode, serverSecret, ciphertext, finished) {
    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}

    var handler = new DecryptMessage(myself.eventHandler);
    handler.execute(ciphertext, packageId, keyCode, serverSecret, finished);
  };

  /**
   * Gets a given package's message for use based on package id and checksum provided 
   * @param packageId {String} The package id of the package.
   * @param packageCode {String} The package code value for the given package
   * @param keyCode {String} The package key code value
   * @param finished {function} function ()
   * @fires {sendsafely#error}
   * @returns {void}
   */
  this.getPackageMessage = function (packageId, packageCode, keyCode, finished) {
    try { this.checkAPIInitialized();}
    catch (err) {myself.eventHandler.raiseError(myself.NOT_INITIALIZED_ERROR, err.message); return;}
    new GetPackageMessage(myself.eventHandler, myself.request).execute(packageId, packageCode, keyCode, myself.async, finished);
  };

  /*
   * INTERNAL FUNCTIONS BELOW THIS POINT
   */
  /**
	 * @ignore
	 */
  this.checkAPIInitialized = function() {
    if(isOAuthStrategy(myself.strategy)){ return; } // Bearer: no HMAC creds expected
    if(myself.apiKeySecret === undefined || myself.apiKeyId === undefined){
      throw "API not initialized - From API";
    }
  };

  /**
	 * @ignore
	 * @param privateKey
	 * @param publicKeyId
	 * @param callback
	 */
  this.syncKeycodes = function(privateKey, publicKeyId, callback)
  {
    if(oauthBlocksTrustedDevice('sync.keycodes.failed')){ return; }
    var handler = new SyncKeycodes(myself.eventHandler, myself.request);
    handler.execute(privateKey, publicKeyId, myself.async, callback);
  };

  /**
	 * @ignore
	 * @param log
	 * @param stacktrace
	 * @param systemInfo
	 */
  this.sendFeedback = function(log, stacktrace, systemInfo) {
    new FeedbackHandler(myself.eventHandler, myself.request).execute(log, stacktrace, systemInfo, myself.async);
  };

    this.sendSignedRequest = function (endpoint, HTTPMethod, mimeType, requestData, successCallback, customErrorEvent) {
        this.wrapperRequest.sendSignedRequest({
            url: endpoint,
            HTTPMethod: HTTPMethod.toUpperCase(),
            mimetype: mimeType
        }, requestData)
            .then(function (response) {
                if (response.status === 200) {
                    // Success
                    return response.json();
                }
                // HTTP request error — map to a typed OAuth code only in Bearer mode,
                // else surface the raw status exactly as before.
                var oauth = classifyOAuthError(response.status, isOAuthStrategy(myself.strategy), {
                    wwwAuthenticate: response.headers.get('www-authenticate'),
                    retryAfter: response.headers.get('retry-after')
                });
                myself.eventHandler.raiseError(
                    oauth ? oauth.error : response.status,
                    oauth ? oauth.message : response.error,
                    customErrorEvent);
                return null; // sentinel — stop the chain so the next .then doesn't deref undefined
            }).then(function (responseData) {
            if (responseData === null) { return; } // already handled above
            if (responseData.hasOwnProperty('response') && responseData.response.toUpperCase() === 'SUCCESS') {
                if (successCallback !== undefined) {
                    successCallback(responseData);
                }
            } else {
                // SendSafely server returned an error for the user
                myself.eventHandler.raiseError(responseData.response, responseData.message, customErrorEvent);
            }
        }).catch(function (error) {
            // catch errors thrown by fetch
            myself.eventHandler.raiseError(error.code, error.message, customErrorEvent);
        });
    }

}

//Other Functions

// True when the active auth strategy authenticates via OAuth Bearer. The strategy owns this
// knowledge (strategy.isOAuth()), so call sites don't depend on the concrete class. Null-safe:
// a missing strategy (e.g. AnonymousRequest, which carries none) is treated as not-OAuth.
function isOAuthStrategy(strategy) {
  return !!(strategy && typeof strategy.isOAuth === 'function' && strategy.isOAuth());
}

// Map an HTTP status to a typed OAuth error code, but only in Bearer mode so existing HMAC
// clients keep their raw 401/403/503 behavior unchanged. Status alone is not enough for
// 403/503: a 403 can be a plain permission denial (package access, not scope) and a 503 can
// come from a load balancer during a deploy — telling the caller "refresh the token" for
// those hides the real error. So classification requires the server's challenge evidence:
//   401 — always OAUTH_TOKEN_INVALID (the bearer token was the only credential sent);
//   403 — OAUTH_INSUFFICIENT_SCOPE only when the WWW-Authenticate Bearer challenge says
//         insufficient_scope (RFC 6750 §3.1); other 403s pass through unclassified;
//   503 — OAUTH_TEMPORARILY_UNAVAILABLE only with a Retry-After header (the fail-closed
//         introspection-outage response per the design doc); a bare LB 503 passes through.
// The raw challenge details (scope, resource_metadata) remain the OAuth client's concern
// and are intentionally not surfaced beyond this classification.
function classifyOAuthError(status, bearerMode, evidence) {
  if (!bearerMode) { return null; }
  evidence = evidence || {};
  if (status === 401) return { error: 'OAUTH_TOKEN_INVALID', message: 'Access token expired or invalid' };
  if (status === 403 && /insufficient_scope/i.test(evidence.wwwAuthenticate || '')) {
    return { error: 'OAUTH_INSUFFICIENT_SCOPE', message: 'Token lacks required scope' };
  }
  if (status === 503 && evidence.retryAfter != null && evidence.retryAfter !== '') {
    return { error: 'OAUTH_TEMPORARILY_UNAVAILABLE', message: 'OAuth service unavailable' };
  }
  return null;
}

function urlSafeBase64(base64String) {
	if( typeof base64String == "string"){
		base64String = base64String.replace(/\+/g, '-');
		base64String = base64String.replace(/\//g, '_');
		base64String = base64String.replace(/=/g, '');
		return base64String;
	}
}


function SignedRequest(eventHandler, url, strategy, requestAPI) {

  var myself = this;

  this.apiPrefix = '/api/v2.0';
  this.url = url;
  this.strategy = strategy;
  this.eventHandler = eventHandler;
  this.requestAPI = requestAPI;
  // No apiKey/apiKeySecret here: all signing now goes through strategy.getHeaders().

  this.sendRequest = function (requestType, messageData, a_sync){
    var timestamp = myself.dateString();
    var bodyString = (messageData != "" && messageData != null) ? JSON.stringify(messageData) : '';
    var headers = myself.strategy.getHeaders(myself.apiPrefix, requestType.url, timestamp, bodyString);
    Version.applyVersionHeaders(headers);

    if(typeof a_sync === "undefined"){
      a_sync = true;
    }

    return httpClient.ajax({
      url: myself.url + myself.apiPrefix + requestType.url,
      type: requestType.HTTPMethod,
      timeout: 25000,
      data: messageData == null ? null : JSON.stringify(messageData),
      contentType: requestType.mimetype,
      headers: headers
    })
  };

	/**
	 * Generates a ISO Timestamp to the nearest second
	 * @ignore
	 * @returns {string} ISO timestamp
	 */
  this.dateString = function() {
    var time = new Date().toISOString();
    return time.substr(0, 19) + "+0000"; //2014-01-14T22:24:00+0000
  };

 	/**
	 * Function used to deal with Errors, and callbacks for AJAX Requests.
	 * Progress callback cannot be done when async is false.
	 * @ignore
	 * @param {promise} ajax AJAX Promise
	 * @param {function} error_callback Function is called when there is an error with the function or when there is an error in the responce.
	 * @param {function} success_callback Function is called when data is receved from the server with no errors.
	 * @param {function} progress_callback Function is called when the data is being uploaded.
	 */
  this.processAjaxData = function(ajax, success_callback) {
    ajax.fail(function (xhr, status, error) {
      // Wrap the error to a format we recognize.
      //var data = {response: this.AJAX_ERROR, message: error.message};
      //myself.eventHandler.raise('sendsafely.error', {'error': this.NETWORK_ERROR, 'data': data});
      myself.eventHandler.raiseError(this.NETWORK_ERROR, error.message);
    })
    .done(function (data) {
      if(typeof data == "string"){
        data = JSON.parse(data);
      }
      if(data.response == "SUCCESS") {
        if(success_callback != undefined) {
          success_callback(data);
        }
      }
      else {
        myself.eventHandler.raiseError(data.response, data.message);
      }
    })
  };

  this.extend = function (a, b){
    for(var key in b)
      if(b.hasOwnProperty(key))
        a[key] = b[key];
    return a;
  }

}
function EventHandler(parent) {

  var myself = this;

  this.parent = parent;   // the SendSafely instance; lets the shared ResponseParser read .strategy
  this.eventlist = {};
  this.ERROR_EVENT = 'sendsafely.error';
  /**
	 * Raised if an error happens. Code contains a response code originating from the server. Message is a more descriptive error message
	 * @event sendsafely#error
	 * @type function
	 * @param code
	 * @param message
	 */

  // Inject into the parent
  if(parent !== undefined) {
    parent.on = function(eventStr, callback) {
      return myself.bind(eventStr, callback);
    };

    parent.unbind = function(eventStr, id) {
      myself.unbind(eventStr, id);
    };

    parent.isBound = function(eventStr) {
      return myself.isBound(eventStr);
    };
  }

  this.bind = function (event, callback) {
    var list = myself.getList(event);
    list.push(callback);

    myself.eventlist[event] = list;

    return list.length-1;
  };

  this.unbind = function (event, id) {
    var list = myself.getList(event);

    if(id === undefined) { // Thrash the whole list
      list = undefined;
    }
    else if(list.length > id) {
      list[id] = undefined;
    }

    myself.eventlist[event] = list;
  };

  this.isBound = function(event) {
    return myself.eventlist[event] !== undefined && myself.eventlist[event].length > 0;
  };

  this.raise = function(event, data) {
    if(myself.eventlist[event] !== undefined) {
      var length = myself.eventlist[event].length;
      var i = 0;
      while(i<length && myself.eventlist[event] !== undefined) {
        var callback = myself.eventlist[event][i];
        if(callback != undefined) {
          callback(data);
        }
        i++;
      }
    }
  };

  this.raiseError = function(code, message, customError) {
    if(customError !== undefined && myself.eventlist[customError] !== undefined) {
      myself.eventlist[customError].forEach(function(callback) {
        if(callback != undefined) {
          callback(code, message);
        }
      });
    } else {
      if(myself.eventlist[myself.ERROR_EVENT] !== undefined) {
        //var data = {'error': code, 'message': message};
        myself.eventlist[myself.ERROR_EVENT].forEach(function(callback) {
          if(callback !== undefined) {
            callback(code, message);
          }
        });
      }
    }
  };

  this.getList = function(event) {
    if(myself.eventlist[event] === undefined) {
      myself.eventlist[event] = [];
    }

    return myself.eventlist[event];
  };

}
function Executor(eventHandler) {

  this.eventHandler = eventHandler;

  var myself = this;

  this.run = function(cmd, errorMessage) {
    try {
      cmd();
    } catch(err) {
      myself.handleError(err, errorMessage);
    }
  };

  this.handleError = function(err, errorMessage) {
    myself.eventHandler.raiseError(UNHANDLED_EXCEPTION, {message: errorMessage, stacktrace: err});
    console.log(err);
    throw err;
  };

}
function ResponseParser(eventHandler) {

  this.eventHandler = eventHandler;
  this.defaultEventError = 'sendsafely.error';

  var myself = this;

	/**
	 * Function used to deal with Errors, and callbacks for AJAX Requests.
	 * Progress callback cannot be done when async is false.
	 * @ignore
	 * @param {promise} ajax AJAX Promise
	 * @param {function} error_callback Function is called when there is an error with the function or when there is an error in the responce.
	 * @param {function} success_callback Function is called when data is receved from the server with no errors.
	 * @param {function} progress_callback Function is called when the data is being uploaded.
	 */
  this.processAjaxData = function(ajax, success_callback, errorEvent) {
    ajax.fail(function (xhr, status, error) {
      // Map OAuth auth failures (401/403/503) to typed codes first — but only in Bearer
      // mode, so existing HMAC clients keep their NETWORK_ERROR behavior unchanged.
      // httpClient delivers the HTTP status on the error object (xhr is null), so read
      // error.status — not xhr.status.
      var parent = myself.eventHandler.parent;
      var oauth = classifyOAuthError(error && error.status, isOAuthStrategy(parent && parent.strategy), {
        wwwAuthenticate: error && error.wwwAuthenticate,
        retryAfter: error && error.retryAfter
      });
      if (oauth) {
        myself.raiseError(errorEvent, {'error': oauth.error, 'data': oauth});
        return;
      }
      // Wrap the error to a format we recognize.
      var data = {response: this.AJAX_ERROR, message: error.message};
      myself.raiseError(errorEvent, {'error': this.NETWORK_ERROR, 'data': data});
    }).done(function (data) {
          if(typeof data == "string"){
            data = JSON.parse(data);
          }
          if(data.response == "SUCCESS") {
            if(success_callback != undefined) {
              success_callback(data);
            }
          }
          else if(data.response == "TIMEOUT") {
            myself.eventHandler.raise('session.timeout', data.message);
          }
          else {
            myself.raiseError(errorEvent, {'error': data.response, 'data': data});
          }
        })
  };

	/**
	 * Function used to deal with Errors, and callbacks for AJAX Requests.
	 * Progress callback cannot be done when async is false.
	 *
	 * @param {promise} ajax AJAX Promise
	 * @param {function} error_callback Function is called when there is an error with the function or when there is an error in the responce.
	 * @param {function} success_callback Function is called when data is receved from the server with no errors.
	 * @param {function} progress_callback Function is called when the data is being uploaded.
	 */

	/**
	 * @ignore
	 */
  this.processAjaxDataRaw = function(ajax, callback, errorEvent) {
      ajax.fail(function (xhr, status, error) {
          var errorMessage;
          if(typeof error == "string"){
              errorMessage = error;
          } else {
              errorMessage = error.message;
          }
          // Same OAuth classification as processAjaxData: the raw callers (createFileID,
          // getUploadUrls, finalizePackage, getDownloadUrls) are /api/v2.0 calls, so a token
          // problem here must surface as a typed OAUTH_* error — that's the refresh contract
          // the README documents. The legacy callback below still runs unchanged so caller
          // failure paths (queue cleanup, operation-level events) behave exactly as before.
          var parent = myself.eventHandler.parent;
          var oauth = classifyOAuthError(error && error.status, isOAuthStrategy(parent && parent.strategy), {
              wwwAuthenticate: error && error.wwwAuthenticate,
              retryAfter: error && error.retryAfter
          });
          if (oauth) {
              myself.raiseError(errorEvent, {'error': oauth.error, 'data': oauth});
          }
          // Wrap the error to a format we recognize.
          var data = {response: "AJAX_ERROR", message: "A server error has occurred (" + errorMessage + "). Please try again."};
          callback(data);
      }).done(function (data) {
          if(typeof data == "string"){
              data = JSON.parse(data);
          }
          callback(data);
      })
  };

  this.raiseError = function(customEvent, data) {
    myself.eventHandler.raiseError(data.error, data.data.message, customEvent);

  };

};

function DefaultStorage(eventHandler, fileId, fileParts)
{
  var myself = this;
  this.SAVE_FILE_EVENT = "save.file";
  /**
   * The raw decrypted file. Use this event to save the file to the actual file system
   * @event save#file
   * @type {function}
   * @param {String} fileId
   * @param {Blob} file
  */
  this.eventHandler = eventHandler;
  this.file = undefined;
  this.fileFormat = 'ARRAY_BUFFER';
  this.fileParts = 0; //This is total file parts in the file
  this.partCounter = 0; //This is the total parts we've been sent by the parent process

  this.getFileFormat = function() {
    return myself.fileFormat;
  };
  
  this.store = function(fileId, part, data, callback)
  {	  
    if(myself.file === undefined) {
      myself.file = [Buffer.from(data)];
    } else {
    	myself.file.push(Buffer.from(data));
    }

    myself.partCounter++;
    
    if (myself.partCounter == myself.fileParts)
    {
      //were done
      callback({done:true});
    }
  };

  this.save = function(fileId)
  {
	  myself.file = Buffer.concat(myself.file);
	  myself.eventHandler.raise(myself.SAVE_FILE_EVENT, {fileId: fileId, file: myself.file});
  };

}

function WriteStreamStorage(eventHandler, fileWriteStream, config)
{
  var myself = this;
  this.FILE_SAVED_EVENT = "file.saved";
  /**
   * The raw decrypted file stream for large file downloads. Use this event to save the file to the actual file system using a write stream
   * @event file#saved
   * @type {function}
   * @param {String} fileId
   * @param {Json} config
   */
  this.eventHandler = eventHandler;
  this.fileWriteStream = fileWriteStream;
  this.config = config;
  this.file = undefined;
  this.fileFormat = 'ARRAY_BUFFER';
  this.fileParts = 0; //This is total file parts in the file
  this.partCounter = 0; //This is the total parts we've been sent by the parent process

  this.getFileFormat = function() {
    return myself.fileFormat;
  };
  
  this.store = function(fileId, part, data, callback)
  {	  
    myself.fileWriteStream.write(data);

    myself.partCounter++;
    
    if (myself.partCounter == myself.fileParts)
    {
      //were done
      callback({done:true});
    }
  };

  this.save = function(fileId)
  {
	  // end() only starts the flush. The file is complete on disk once its callback runs; on a
	  // failure the stream's error listener has already raised FAIL, so there is nothing to announce.
	  myself.fileWriteStream.end(function(err) {
	    if (!err) {
	      myself.eventHandler.raise(myself.FILE_SAVED_EVENT, {fileId: fileId, config: myself.config});
	    }
	  });
  };
}

function AddPublicKey (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/public-key/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'publickey.add.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (publicKey, description, visible, async, finished) {
    var response = myself.request.sendRequest(myself.endpoint, {'publicKey': publicKey, 'description': description}, async);
    myself.responseParser.processAjaxData(response, function (res) {
      var data = {};
      data.description = res.description;
      data.dateStr = res.dateStr;
      data.id = res.id;
      data.key = publicKey;
      data.visible = visible;
      finished(data);
    }, myself.customErrorEvent);
  }
}
function AddRecipient (eventHandler, request) {
  this.request = request;
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'recipient.add.failed';
  this.notifyRecipients = true;
  this.autoEnableSMS = false;

  var myself = this;

  this.execute = function (packageId, email, keycode, async, finished) {
    finished = (finished === undefined) ? function(){} : finished;

    var handler = new AddRecipients(myself.eventHandler, myself.request);
    handler.customErrorEvent = myself.customErrorEvent;
    handler.autoEnableSMS = myself.autoEnableSMS;
    handler.notifyRecipients = myself.notifyRecipients;
    handler.execute(packageId, [email], keycode, async, function(response) {
      var recipients = response.recipients;
      if(recipients.length > 0) {
        finished(recipients[0]);
      }
    });
  }
}
function AddRecipientPhonenumber(eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/recipient/{recipientId}/", "HTTPMethod" : "POST", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);
  this.customError = 'recipient.update.failed';

  var myself = this;

  this.execute = function (packageId, recipientId, phonenumber, countryCode, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{recipientId}", recipientId);

    var data = {"phoneNumber": phonenumber, "countrycode": countryCode};


    var response = myself.request.sendRequest(endpoint, data, async);
    myself.responseParser.processAjaxData(response, function(res) {
      finished(res.message);
    }, myself.customError);
  }
}
function AddRecipientWithSMS (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/recipient/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, email, phonenumber, countryCode, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);

    var data = {};
    data['email'] = email;
    data['phoneNumber'] = phonenumber;
    data['countryCode'] = countryCode;

    var response = myself.request.sendRequest(endpoint, data, async);
    myself.responseParser.processAjaxData(response, function (res) {
      var data = {};
      data.recipientId = res.recipientId;
      data.approvalRequired = res.approvalRequired;
      data.email = res.email;
      data.approvers = res.approvers;
      data.phonenumbers = res.phonenumbers;
      data.autoEnabledNumber = res.autoEnabledNumber;
      finished(data);
    });
  }
}
function AddRecipients (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/recipients/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'recipients.add.failed';
  this.autoEnableSMS = false;
  this.notifyRecipients = true;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, listOfEmails, keycode, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    var response = myself.request.sendRequest(endpoint, {'emails': listOfEmails, autoEnableSMS: myself.autoEnableSMS}, async);
    myself.responseParser.processAjaxData(response, function (res) {
      var response = {};
      response.recipients = [];
      for(var i = 0; i<res.recipients.length; i++) {
        var recipient = res.recipients[i];

        var data = {};
        data.response = recipient.response;
        data.message = recipient.message;
        data.recipientId = recipient.recipientId;
        data.approvalRequired = recipient.approvalRequired;
        data.email = recipient.email;
        data.phonenumbers = recipient.phonenumbers;
        data.autoEnabledNumber = recipient.autoEnabledNumber;
        data.fullName = recipient.fullName;
        data.roleName = recipient.roleName;
        response.recipients.push(data);

        if(recipient.recipientId !== undefined && keycode !== undefined && recipient.checkForPublicKeys !== undefined && recipient.checkForPublicKeys) {
          myself.getPublicKeys(packageId, recipient.recipientId, keycode, async);
        }
        else
        {
          // No keycodes need to be uploaded.
          // Raise this event in case the calling functions are waiting for it
          myself.eventHandler.raise('keycodes.uploaded', {});
        }
      }
      response.approvalRequired = res.approvalRequired;
      response.approvers = res.approvers;

      finished(response);
    }, myself.customErrorEvent);
  };

  this.getPublicKeys = function(packageId, recipientId, keycode, async) {
    if(!myself.eventHandler.isBound('received.publickeys')) {
      myself.eventHandler.bind('received.publickeys', function(publickeys) {
        myself.encryptAndUploadKeycode(packageId, publickeys, keycode, async);
      });
    }

    var handler = new GetRecipientPublicKeys(myself.eventHandler, myself.request);
    handler.execute(packageId, recipientId, async, function(publicKeys) {
      myself.eventHandler.raise('received.publickeys', publicKeys);
    });
  };

  this.encryptAndUploadKeycode = function(packageId, publicKeys, keycode, async) {
    var handler = new EncryptAndUploadKeycodes(myself.eventHandler, myself.request);
    handler.notifyRecipients = myself.notifyRecipients;
    handler.execute(packageId, publicKeys, keycode, async, function() {
      myself.eventHandler.raise('keycodes.uploaded', {});
    });
  }
}
function AddVersionInfo (eventHandler, request) {

  this.request = request;
  this.endpoint = {"url": "/config/version/info/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function(host, versionInfo, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);

    var info = buildVersionString(versionInfo);
    var data = {host: host, info: info};

    var response = myself.request.sendRequest(endpoint, data, async);
    myself.responseParser.processAjaxData(response, function(res) {
      callCallback(res.version, finished);
    });
  };

  function callCallback(version, callback) {
    if(callback !== undefined) {
      callback(version);
    }
  }

  function buildVersionString(versionInfo) {
    var infoStr = "";
    infoStr += "CE|";
    infoStr += versionInfo.userAgent + "|";
    infoStr += versionInfo.newVersion + "|";
    infoStr += versionInfo.oldVersion;
    return infoStr;
  }

}

function CreateDirectory (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/directory/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, directoryName, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    var postData = {};
    postData['directoryName'] = directoryName;
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    var response = myself.request.sendRequest(endpoint, postData, async);
    myself.responseParser.processAjaxData(response, function (res) {
      finished(response);
    }, myself.customError);
  }
}
function CreateFileId(eventHandler, request) {
  var myself = this;

  this.request = request;
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  this.endpoint = { "url": "/package/{packageId}/file/", "HTTPMethod" : "PUT", "mimetype": "application/json"};

  this.execute = function (packageId, data, fileName, parts, uploadType, async) {
    var endpoint = myself.request.extend({}, myself.endpoint);

    var postData = {};
    postData['filename'] = encodeURI(fileName);
    postData['uploadType'] = uploadType || myself.request.requestAPI;
    postData['parts'] = parts;
    postData['filesize'] = data.size;

    if(myself.directoryId !== undefined && myself.directoryId !== "") {
      postData['directoryId'] = myself.directoryId;
    }
    
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    return myself.request.sendRequest(endpoint, postData, async);
  }
}

function GetUploadUrls(eventHandler, request) {
  var myself = this;

  this.request = request;
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  this.endpoint = { "url": "/package/{packageId}/file/{fileId}/upload-urls/", "HTTPMethod" : "POST", "mimetype": "application/json"};

  this.execute = function (packageId, fileId, part, forceProxy, async) {
    var endpoint = myself.request.extend({}, myself.endpoint);

    var postData = {};
    postData['part'] = part;
    postData['forceProxy'] = forceProxy;

    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{fileId}", fileId);
    return myself.request.sendRequest(endpoint, postData, async);
  }
}

function GetDownloadUrls(eventHandler, request) {
  var myself = this;

  this.request = request;
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  this.endpoint = { "url": "/package/{packageId}/file/{fileId}/download-urls/", "HTTPMethod" : "POST", "mimetype": "application/json"};

  this.execute = function (packageId, fileId, directoryId, checksum, startSegment, endSegment, async) {
    var endpoint = myself.request.extend({}, myself.endpoint);

	if (directoryId) {
		endpoint.url ='/package/{packageId}/directory/{directoryId}/file/{fileId}/download-urls/';
		endpoint.url = endpoint.url.replace("{directoryId}", directoryId);
     }
	
    var postData = {};
    postData['checksum'] = checksum;
    postData['startSegment'] = startSegment;
    postData['endSegment'] = endSegment;	
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{fileId}", fileId);
    
    return myself.request.sendRequest(endpoint, postData, async);
  }
}

function MarkFileComplete(eventHandler, request) {

  var myself = this;

  this.request = request;
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  this.endpoint = { "url": "/package/{packageId}/file/{fileId}/upload-complete/", "HTTPMethod" : "POST", "mimetype": "application/json"};

  this.execute = function (packageId, directoryId, fileId, async, finished, failed, retryCounter) {
    var endpoint = myself.request.extend({}, myself.endpoint);

    var postData = {};
    postData['complete'] = true;
    if (directoryId !== undefined)
    {
      postData['directoryId'] = directoryId;
    }

    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{fileId}", fileId);


    myself.responseParser.processAjaxData(myself.request.sendRequest(endpoint, postData, async), function (resp) {

      if(resp.response === "SUCCESS" && resp.message === "true")
      {
        finished();
      }
      else
      {
        /*
        retryCounter++;
        if (retryCounter == 4)
        {
          failed();
        }
        else
        {
          setTimeout(function() {
            new MarkFileComplete(eventHandler, request).execute(packageId, fileId, async, finished, failed, retryCounter);
          }, retryCounter*1000);
        }
        */
        //Keep trying every 2 seconds until the file is done
        setTimeout(function() {
          new MarkFileComplete(eventHandler, request).execute(packageId, directoryId, fileId, async, finished, failed, retryCounter);
        }, 2000);
      }
    });
  }
}

function CopyFile(eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/file/{fileId}/copy", "HTTPMethod" : "POST", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);
  this.customError = 'copy.file.failed';

  var myself = this;
  this.execute = function (sourcePackageId, sourceFileId, fileKey, targetPackageId, targetDirectoryId, targetServerSecret, targetKeycode, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    var postData = {};
    postData['targetPackageId'] = targetPackageId;
    postData['targetDirectoryId'] = targetDirectoryId;
    postData['fileKey'] = fileKey;

    endpoint.url = endpoint.url.replace("{packageId}", sourcePackageId);
    endpoint.url = endpoint.url.replace("{fileId}", sourceFileId);

    var response = myself.request.sendRequest(endpoint, postData, async);
    myself.responseParser.processAjaxData(response, function (res) {
      finished(response);
    }, myself.customError);
  }

}

function CreatePackage(eventHandler, request) {
  var myself = this;
  var isVdr = false;
  this.CREATE_PACKAGE_FAILED = "create.package.failed";
  this.request = request;
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  this.endpoint = { "url": "/package/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.setVdr = function(vdrParam){
	isVdr = vdrParam;	
	return this;
  };
  this.execute = function (async, finished) {

    var response = myself.request.sendRequest(myself.endpoint, {vdr: isVdr}, async);
    myself.responseParser.processAjaxData(response, function(json) {

      function populateAndSendReturnData() {
        myself.createKeycode(function(keyCode) {
          var packageId = json.packageId;
          var serverSecret = json.serverSecret;
          var packageCode = json.packageCode;

          finished(packageId, serverSecret, packageCode, keyCode);
        });
      }

      populateAndSendReturnData();
    }, myself.CREATE_PACKAGE_FAILED);
  };

  this.createKeycode = function(callback) {
    callback(randomKeycode());
  };

}
function CreateSubdirectory (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/directory/{directoryId}/subdirectory", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, directoryName, parentDirectoryId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    var postData = {};
    postData['directoryName'] = directoryName;
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{directoryId}",parentDirectoryId);
    var response = myself.request.sendRequest(endpoint, postData, async);
    myself.responseParser.processAjaxData(response, function (res) {
      var json = JSON.stringify(response);
      finished(response);
    }, myself.customError);
  }
}
function DecryptKeycode (eventHandler) {
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'keycode.decrypt.failed';

  var myself = this;

  this.execute = function (privateKey, keyCode, callback) {
    seedRandomness(privateKey, keyCode, callback);
  };

  function seedRandomness(privateKey, keyCode, callback)
  {
    myself.eventHandler.raise('sendsafely.entropy.ready', {});
    decryptKeycode(privateKey, keyCode, callback);
  }

  function decryptKeycode(privateKey, keyCode, callback) {
    openpgpOps.decryptKeycode({ privateKey, keyCode }).then(
      function (decryptedKeycode) {
        _invokeCallbackSafely(callback, decryptedKeycode);
      },
      function (err) {
        const stack = (err && err.stack) ? err.stack : 'Stacktrace could not be extracted';
        myself.eventHandler.raiseError(stack, err.message, myself.customErrorEvent);
      }
    );
  }
}
function DecryptMessage (eventHandler) {
  
  var myself = this;

  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  this.execute = function (ciphertext, packageId, keyCode, serverSecret, callback) {
    openpgpOps.decryptMessage({
      serverSecret: urlSafeBase64(serverSecret),
      keycode: urlSafeBase64(keyCode),
      message: ciphertext
    }).then(
      function (plaintext) {
        _invokeCallbackSafely(callback, plaintext);
      },
      function (err) {
        // raise() is a no-op with no listener bound; keep the legacy
        // MESSAGE_DECRYPT_ERROR event for consumers that bind it, otherwise
        // fall back to the generic sendsafely.error channel (the documented
        // @fires contract of decryptMessage).
        if (eventHandler.isBound('MESSAGE_DECRYPT_ERROR')) {
          eventHandler.raise('MESSAGE_DECRYPT_ERROR', err.message);
        } else {
          eventHandler.raiseError('MESSAGE_DECRYPT_ERROR', err.message);
        }
      }
    );
  }
}
function DeleteDirectory (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/directory/{directoryId}/", "HTTPMethod" : "DELETE", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  this.errorEvent = 'file.delete.error';

  var myself = this;

  this.execute = function(packageId, directoryId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{directoryId}", directoryId);

    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function(response) {
      finished(response);
    }, myself.errorEvent);
  }
}
function DeleteFile (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/file/{fileId}/", "HTTPMethod" : "DELETE", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  this.errorEvent = 'file.delete.error';

  var myself = this;

  this.execute = function(packageId, fileId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{fileId}", fileId);

    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function() {
      finished();
    }, myself.errorEvent);
  }
}
function DeleteFileWithDirectory (eventHandler, request) {
	  this.request = request;
	  this.endpoint = { "url": "/package/{packageId}/directory/{directoryId}/file/{fileId}/", "HTTPMethod" : "DELETE", "mimetype": "application/json"};
	  this.eventHandler = eventHandler;
	  this.responseParser = new ResponseParser(eventHandler);

	  this.errorEvent = 'file.delete.error';

	  var myself = this;

	  this.execute = function(packageId, fileId, directoryId, async, finished) {
	    var endpoint = myself.request.extend({}, myself.endpoint);
	    endpoint.url = endpoint.url.replace("{directoryId}", directoryId);
	    endpoint.url = endpoint.url.replace("{packageId}", packageId);
	    endpoint.url = endpoint.url.replace("{fileId}", fileId);

	    var response = myself.request.sendRequest(endpoint, null, async);
	    myself.responseParser.processAjaxData(response, function(response) {
	      finished(response);
	    }, myself.errorEvent);
	  }
	}
function DeletePackage (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/", "HTTPMethod" : "DELETE", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);

    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {
      finished();
    });
  }
}
function DeleteTempPackage (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/temp/", "HTTPMethod" : "DELETE", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);

    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {
      if(finished != undefined) {finished();}
    });
  }
}
function DownloadAndDecryptFile (eventHandler, request) {
  var myself = this;
  this.endpoint = { "url": "/package/{packageId}/file/{fileId}/download/", "HTTPMethod" : "POST", "mimetype": "application/json"};
  this.PENDING_DOWNLOADS_CHANGED_EVENT = 'internal.download.pending.downloads';
  this.PENDING_DECRYPTION_CHANGED_EVENT = 'internal.download.pending.decryption';
  this.DOWNLOAD_PROGRESS_EVENT = 'internal.download.progress_{fileId}';
  this.DOWNLOAD_DONE_EVENT = 'internal.download.finished_{fileId}';
  this.FILE_DECRYPTED = 'file.decrypted';
  /**
	 * Raised when a file is decrypted and ready to be saved.
	 * @event file#decrypted
	 * @type {function}
	 * @param {String} fileId
	 */
  this.DOWNLOAD_PROGRESS = 'download.progress';
  /**
	 * Subscribe to this event to receive download progress.
	 * @event download#progress
	 * @type {function}
	 * @param {String} fileId
	 * @param {Number} progress
	 */
  this.states = {WAITING: 'WAITING', DOWNLOADING: 'DOWNLOADING', DOWNLOADED: 'DOWNLOADED', DECRYPTING: 'DECRYPTING'};
  this.MAX_CONCURRENT_DOWNLOADS = 1;
  this.MAX_CONCURRENT_DECRYPTIONS = 1;
  this.DOWNLOAD_API = 'NODE_API';
  this.eventHandler = eventHandler;
  this.request = request;
  this.pendingDownloads = [];
  this.progressMap = {};
  this.downloadUrls = {};
  this.ec2Proxy = false;
  this.responseParser = new ResponseParser(eventHandler);
  this.fileId;
  this.fileName;
  this.fileIndexes = [];
  this.fileWriteStream;

  myself.eventHandler.bind(myself.PENDING_DOWNLOADS_CHANGED_EVENT, startDownloads);
  myself.eventHandler.bind(myself.PENDING_DECRYPTION_CHANGED_EVENT, startDecrypting);

  function createFileWriteStreamIfInConfig(config, file) {
    if (config && (config.path || config.fileName)) {
      var downloadPath = buildDownloadPath(config, file);
      
      myself.fileWriteStream = fs.createWriteStream(downloadPath);
      myself.fileWriteStream.on('error', function(error) {
        myself.eventHandler.raiseError("FAIL", "Write stream error: " + error);
      });
    }
  }

  this.addFile = function(packageId, fileId, keyCode, config) {

    myself.getFileDetails(packageId, fileId, function(pkg, file) {
      createFileWriteStreamIfInConfig(config, file);
      
      config = buildConfig(config);
      // A zero-part file is still fetched as one part, so storage has to wait for exactly one
      config.storage.fileParts = file.parts == 0 ? 1 : file.parts;

      var checksum = createChecksum(keyCode, pkg.packageCode);
      if(file.parts == 0) {
        myself.pendingDownloads.push({'packageId':packageId, 'directoryId': null, 'fileId':fileId, 'fileSize': file.fileSize, 'keycode': keyCode, 'serverSecret': pkg.serverSecret, 'checksum':checksum, 'part':1, 'parts':file.parts, 'config': config, 'state': myself.states.WAITING});
      }
      for(var i = 1; i<=file.parts; i++) {
        myself.pendingDownloads.push({'packageId':packageId, 'directoryId': null, 'fileId':fileId, 'fileSize': file.fileSize, 'keycode': keyCode, 'serverSecret': pkg.serverSecret, 'checksum':checksum, 'part':i, 'parts':file.parts, 'config': config, 'state': myself.states.WAITING});
      }
      
      myself.progressMap[fileId] = 0;
      myself.eventHandler.raise(myself.PENDING_DOWNLOADS_CHANGED_EVENT, {});
    });
  };

  this.addFileFromDirectory = function(packageId, directoryId, fileId, keyCode, config) {
    new GetPackageInformation(myself.eventHandler, myself.request).execute(packageId, myself.async, function(pkg) {
      myself.getFileDetailsFromDirectory(pkg.packageId, directoryId, fileId, function(file){
        createFileWriteStreamIfInConfig(config, file);
      
        config = buildConfig(config);
        // A zero-part file is still fetched as one part, so storage has to wait for exactly one
        config.storage.fileParts = file.fileParts == 0 ? 1 : file.fileParts;

        var checksum = createChecksum(keyCode, pkg.packageCode);

        if(file.fileKey != "" && file.fileKey != undefined){
          var messageDecryptor = new DecryptMessage(myself.eventHandler);
          messageDecryptor.execute(file.fileKey, pkg.packageId, keyCode, pkg.serverSecret, function(decryptedFileKey){
            // fileKey = decryptedFileKey;
            if(file.fileParts == 0) {
              myself.pendingDownloads.push({'packageId':pkg.packageId, 'directoryId': directoryId, 'fileId':file.fileId, 'fileSize':file.fileSize, 'keycode': keyCode, 'serverSecret': pkg.serverSecret, 'checksum':checksum, 'part':1, 'parts':file.fileParts, 'config': config, 'state': myself.states.WAITING, 'fileName': file.fileName, 'fileKey': decryptedFileKey});
            }
            for(var i = 1; i<=file.fileParts; i++) {
              myself.pendingDownloads.push({'packageId':pkg.packageId, 'directoryId': directoryId, 'fileId':file.fileId, 'fileSize':file.fileSize, 'keycode': keyCode, 'serverSecret': pkg.serverSecret, 'checksum':checksum, 'part':i, 'parts':file.fileParts, 'config': config, 'state': myself.states.WAITING, 'fileName': file.fileName, 'fileKey': decryptedFileKey});
            }
            myself.progressMap[file.fileId] = 0;
            myself.eventHandler.raise(myself.PENDING_DOWNLOADS_CHANGED_EVENT, {});
          });
        }else{
          if(file.fileParts == 0) {
            myself.pendingDownloads.push({'packageId':pkg.packageId, 'directoryId': directoryId, 'fileId':file.fileId, 'fileSize':file.fileSize, 'keycode': keyCode, 'serverSecret': pkg.serverSecret, 'checksum':checksum, 'part':1, 'parts':file.fileParts, 'config': config, 'state': myself.states.WAITING, 'fileName': file.fileName, 'fileKey': file.fileKey});
          }
          for(var i = 1; i<=file.fileParts; i++) {
            myself.pendingDownloads.push({'packageId':pkg.packageId, 'directoryId': directoryId, 'fileId':file.fileId, 'fileSize':file.fileSize, 'keycode': keyCode, 'serverSecret': pkg.serverSecret, 'checksum':checksum, 'part':i, 'parts':file.fileParts, 'config': config, 'state': myself.states.WAITING, 'fileName': file.fileName, 'fileKey': file.fileKey});
          }
          myself.progressMap[file.fileId] = 0;
          myself.eventHandler.raise(myself.PENDING_DOWNLOADS_CHANGED_EVENT, {});
        }
      });
    });
  };


  this.getFileDetails = function(packageId, fileId, callback) {
    var packageInfoHandler = new GetPackageInformation(myself.eventHandler, myself.request);
    packageInfoHandler.execute(packageId, true, function(pkg) {
      var file = undefined;
      for(var i = 0; i<pkg.files.length; i++) {
        if(pkg.files[i].fileId === fileId) {
          file = pkg.files[i];
          break;
        }
      }
      if(file === undefined) {
        myself.eventHandler.raiseError("FAIL", "File " + fileId + " not found in package " + packageId);
        return;
      }
      callback(pkg, file);
    });
  };

  this.getFileDetailsFromDirectory = function(packageId, directoryId, fileId, callback) {
    var fileDetailsHandler = new GetFileFromDirectory(myself.eventHandler, myself.request);
    fileDetailsHandler.execute(packageId, directoryId, fileId, true, function(file) {
      callback(file);
    });
  };

  this.getFileFromDirectoryDetails = function(packageId, directoryId, fileId, callback) {
    var packageInfoHandler = new GetPackageInformation(myself.eventHandler, myself.request);
    packageInfoHandler.execute(packageId, true, function(pkg) {
      var fileInfoHandler = new GetFileFromDirectory(myself.eventHandler, myself.request);
      fileInfoHandler.execute(packageId, directoryId, fileId, true, function(file) {
        callback(pkg,file);
      });
    });
  };

  this.downloadFile = function (endpoint, requestBody, progressEvent, finishedEvent) {
	let requestData = JSON.stringify(requestBody);
    let request = new FetchRequest({signedRequest:false});
    let res = undefined;

    if (true || !myself.ec2Proxy) {
        requestData = null;
        request = request.sendRequest(endpoint, {method: 'GET'});
    } else {
        // download failover is not supported yet.
        request = new FetchRequest({url: myself.request.url, strategy: myself.request.strategy, requestAPI: myself.request.requestAPI, apiPrefix: myself.request.apiPrefix});
        request = request.sendSignedRequest({url: endpoint, HTTPMethod: 'POST', mimetype: 'application/json'}, requestData);
    }

    request.then(function(response) {
        res = response;
        if(isValidResponse(response)) {
            myself.eventHandler.raise(progressEvent, response.size);
            return response.arrayBuffer();
        } else {
            return response;
        }
    }).then(function(data){
        if(isValidResponse(res)) {
            let formattedResponse = new Uint8Array(data);
            myself.eventHandler.raise(finishedEvent, formattedResponse);
        } else {
            raiseDownloadError(data);
        }
    }).catch(function(error) {
      myself.eventHandler.raiseError("FAIL", (error && error.message) || String(error));
    });
    
    function isValidResponse(res) {
    	return res.status === 200 && (res.headers.has('content-type') && !res.headers.get['content-type']?.toLowerCase().includes('application/json'));
    }
    
    function raiseDownloadError(res) {
      // File downloads hit pre-signed storage URLs and carry NO Authorization header, so a
      // 401/403/503 here is a storage/transport failure (e.g. an expired pre-signed URL), never
      // an OAuth-token problem — OAuth-classifying it would misdirect callers into a pointless
      // token refresh. Token validity is already enforced on the preceding API call that issues
      // these URLs (via SignedRequest/ResponseParser), which surfaces OAUTH_* correctly. So this
      // path stays a transport-level FAIL regardless of the active auth strategy.
      let response = 'Response Code: ' + res.status + ', Response Text: ' + res.statusText;
    	myself.eventHandler.raiseError("FAIL", "Server returned an error: " + response);
    }
  };


  function startDownloads() {    
    var ongoingDownloads = countCurrentDownloads();
    var pendingDecryptions = countCurrentDecryptions();
    if(myself.pendingDownloads.length > 0 && ongoingDownloads < myself.MAX_CONCURRENT_DOWNLOADS && pendingDecryptions <= myself.MAX_CONCURRENT_DECRYPTIONS) {

      var fileObj = getFirsWithState(myself.states.WAITING);
      if(fileObj !== undefined) {
        downloadFile(fileObj);
      }
    }
  }


  function startDecrypting() {
	var pendingDecryptions = countCurrentDecryptions();
    if(myself.pendingDownloads.length > 0 && pendingDecryptions <= myself.MAX_CONCURRENT_DECRYPTIONS) {
      var fileObj = getFirsWithState(myself.states.DOWNLOADED);
      if(fileObj !== undefined) {
        decryptSegment(fileObj);
      }
    }
  }

  function decryptSegment(fileObj)
  {
    updateState(fileObj.fileId, fileObj.part, myself.states.DECRYPTING);
    const fileId = fileObj.fileId;
    const part = fileObj.part;
    const decryptionKey = fileObj.fileKey || generateDecryptionKey(fileObj.serverSecret, fileObj.keycode);
    // Two-arg .then() so partDecrypted's storage I/O throws don't get
    // mis-labeled as DECRYPT_ERROR (storage layer has its own error path).
    openpgpOps.decryptFilePart({ file: fileObj.encryptedData, decryptionKey }).then(
      function (decryptedData) {
        try { partDecrypted(fileId, part, decryptedData); }
        catch (e) { setImmediate(function () { throw e; }); }
      },
      function (err) {
        myself.eventHandler.raiseError('DECRYPT_ERROR', err.message);
        // Without cleanup the part stays in DECRYPTING state forever, holding
        // a decrypt slot and blocking every other pending file.
        abandonFile(fileId);
      }
    );
  }

  function partDecrypted(fileId, part, decryptedData)
  {	  
    var fileObject = getFileObject(fileId, part);
    fileObject.config.storage.store(fileId, part, decryptedData, function(result) {
      if (result !== undefined && result.done)
      {
        //if(part === fileObject.parts) {
        fileObject.config.storage.save(fileId);
        myself.eventHandler.raise(myself.FILE_DECRYPTED, {fileId: fileId});
        myself.fileWriteStream = null;
        //}
      }
    });

    removeFromList(fileId, part);
    myself.eventHandler.raise(myself.PENDING_DECRYPTION_CHANGED_EVENT, {});
    myself.eventHandler.raise(myself.PENDING_DOWNLOADS_CHANGED_EVENT, {});
  }

  function generateDecryptionKey(serverSecret, keycode)
  {
    return serverSecret + keycode;
  }

  function downloadFile(fileObject)
  {
    var fileId = fileObject.fileId;
    var part = fileObject.part;

    updateState(fileId, part, myself.states.DOWNLOADING);

    var progressEvent = myself.DOWNLOAD_PROGRESS_EVENT.replace("{fileId}", fileObject.fileId + '_' + part);
    var finishedEvent = myself.DOWNLOAD_DONE_EVENT.replace("{fileId}", fileObject.fileId + '_' + part);

    setupDownloadEvents(fileId, part, fileObject.fileSize, progressEvent, finishedEvent);

    var endpoint = myself.downloadUrls[fileId + "-" + part];
    var requestBody = createRequestBody(fileObject);

	if(endpoint === undefined) {
      getDownloadLinks(fileObject.packageId, fileObject.directoryId, fileId, fileObject.checksum, part, part+25, function() {
		endpoint = myself.downloadUrls[fileId + "-" + part];
        myself.downloadFile(endpoint, requestBody, progressEvent, finishedEvent);
      })
    } else {
      myself.downloadFile(endpoint, requestBody, progressEvent, finishedEvent);
    }
  }

  function getDownloadLinks(packageId, directoryId, fileId, checksum, startSegment,endSegment, callback) {
    myself.responseParser.processAjaxDataRaw(myself.getDownloadUrls(packageId, fileId, directoryId, checksum, startSegment, endSegment, true), function (result) { 	
		if (result.response === 'SUCCESS') {
            for(var i = 0; i<result.downloadUrls.length; i++) {
              var part = result.downloadUrls[i].part;
              var url = result.downloadUrls[i].url;
              myself.downloadUrls[fileId + "-" + part] = url;
            }
            callback();
         } else {
             myself.eventHandler.raiseError("FAIL", result.message);
         }
      });
  }
  
  this.getDownloadUrls = function(packageId, fileId, directoryId, checksum, startSegment, endSegment, async) {
	  return new GetDownloadUrls(myself.eventHandler, myself.request).execute(packageId, fileId, directoryId, checksum, startSegment, endSegment, async); 
  }

  function setupDownloadEvents(fileId, part, totalSize, progressEvent, finishedEvent)
  {
    myself.eventHandler.bind(progressEvent, function(newBytes) {
      myself.progressMap[fileId] += newBytes;
      var percent = (myself.progressMap[fileId]/totalSize);
      percent = percent*100;
      myself.eventHandler.raise(myself.DOWNLOAD_PROGRESS, {'fileId': fileId, 'percent': percent});
    });

    myself.eventHandler.bind(finishedEvent, function(data) {
      myself.eventHandler.unbind(progressEvent);
      myself.eventHandler.unbind(finishedEvent);
      partDownloaded(fileId, part, data);
    });
  }

  function partDownloaded(fileId, part, data)
  {
    updateState(fileId, part, myself.states.DOWNLOADED);
    var fileObject = getFileObject(fileId, part);
    fileObject.encryptedData = data;
    myself.eventHandler.raise(myself.PENDING_DECRYPTION_CHANGED_EVENT, {});
    myself.eventHandler.raise(myself.PENDING_DOWNLOADS_CHANGED_EVENT, {});
  }


  function createRequestBody(fileObject)
  {
    var postData = {};
    postData.checksum = fileObject.checksum;
    postData.part = fileObject.part;
    postData.api = myself.DOWNLOAD_API;

    if(fileObject.password !== undefined) {
      postData.password = fileObject.password;
    }
    return postData;
  }

  function getFirsWithState(state)
  {
    for(var i = 0; i<myself.pendingDownloads.length; i++) {
      if(myself.pendingDownloads[i].state === state) {
        return myself.pendingDownloads[i];
      }
    }
    return undefined;
  }

  // A part that fails to decrypt can never complete its file, so drop every
  // queued part for that file and re-raise the changed events to hand the
  // download/decrypt slots to other pending files.
  function abandonFile(fileId)
  {
    var failed = undefined;
    for(var i = myself.pendingDownloads.length - 1; i >= 0; i--) {
      if(myself.pendingDownloads[i].fileId === fileId) {
        failed = myself.pendingDownloads[i];
        myself.pendingDownloads.splice(i, 1);
      }
    }
    // All parts of a file share one storage object; end its write stream once
    // (a second end() would emit ERR_STREAM_ALREADY_FINISHED) to release the
    // file descriptor.
    if(failed !== undefined && failed.config.storage !== undefined && failed.config.storage.fileWriteStream !== undefined) {
      failed.config.storage.fileWriteStream.end();
    }
    myself.eventHandler.raise(myself.PENDING_DECRYPTION_CHANGED_EVENT, {});
    myself.eventHandler.raise(myself.PENDING_DOWNLOADS_CHANGED_EVENT, {});
  }

  function removeFromList(fileId, part)
  {
    for(var i = 0; i<myself.pendingDownloads.length; i++) {
      if(myself.pendingDownloads[i].fileId === fileId && myself.pendingDownloads[i].part === part) {
        myself.pendingDownloads.splice(i, 1);
        break;
      }
    }
  }

  function updateState(fileId, part, newState)
  {
    for(var i = 0; i<myself.pendingDownloads.length; i++) {
      if(myself.pendingDownloads[i].fileId === fileId && myself.pendingDownloads[i].part === part) {
        myself.pendingDownloads[i].state = newState;
      }
    }
  }

  function getFileObject(fileId, part)
  {
    for(var i = 0; i<myself.pendingDownloads.length; i++) {
      if(myself.pendingDownloads[i].fileId === fileId && myself.pendingDownloads[i].part === part) {
        return myself.pendingDownloads[i];
      }
    }

    // This should never happen
    return undefined;
  }

  function countCurrentDownloads()
  {
    var currentDownloads = 0;
    for(var i = 0; i<myself.pendingDownloads.length; i++) {
      if(myself.pendingDownloads[i].state === myself.states.DOWNLOADING) {
        currentDownloads++;
      }
    }
    return currentDownloads;
  }

  function countCurrentDecryptions()
  {
    var currentDecryptions = 0;
    for(var i = 0; i<myself.pendingDownloads.length; i++) {
      if(myself.pendingDownloads[i].state === myself.states.DECRYPTING) {
        currentDecryptions++;
      }
    }
    return currentDecryptions;
  }

  function buildConfig(config) {
    config = (config === undefined) ? {} : config;
    
    if (config.storage === undefined) {
      if (myself.fileWriteStream) {
        config.storage = new WriteStreamStorage(myself.eventHandler, myself.fileWriteStream, config);
      } else {
        config.storage = new DefaultStorage(myself.eventHandler);
      }
    }
	config.api = (config.api === undefined) ? myself.DOWNLOAD_API : config.api;
    return config;
  }

  function createChecksum(keyCode, packageCode) {
    return pbkdf2Sha256Hex(urlSafeBase64(keyCode), urlSafeBase64(packageCode), 1024, 32);
  }

}
function EncryptAndUploadFile (eventHandler, request) {

  var myself = this;

  this.PROGRESS_EVENT = 'sendsafely.progress';
  /**
	 * Subscribe to this event to receive upload progress.
	 * @event sendsafely#progress
	 * @param {String} fileId
	 * @param {Number} percent
	 */
  this.LIMIT_EXCEEDED_EVENT = 'limit.exceeded';
  this.DUPLICATE_FILE_EVENT = 'duplicate.file';
  this.UPLOAD_ABORT_EVENT = 'file.upload.cancel';
  this.UPLOAD_ERROR_EVENT = 'file.upload.error';
  /**
	 * Raised when an upload error occurs.
	 * @event file.upload#error
	 * @param {String} fileId
	 * @param {String} message
	 */
  this.SERVER_ERROR_EVENT = 'server.error';
  this.INVALID_FILE_NAME_EVENT = 'invalid.file.name';

  this.defaultFileName = 'Unknown File';

  this.addFileEndpoint = { "url": "/package/{packageId}/file/{fileId}/", "HTTPMethod" : "POST", "mimetype": "multipart/form-data"};
  this.addFileToDirectoryEndpoint = { "url": "/package/{packageId}/{directoryId}/file/{fileId}/", "HTTPMethod" : "POST", "mimetype": "multipart/form-data"};

  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  this.request = request;
  this.uploading = [];
  this.encrypting = [];
  this.encryptionKeyMapping = {};
  this.markedAsDeleted = {};
  this.uploadUrls = {};
  this.fileIdToTargetDirectory = {};
  this.ec2Proxy = false;
  this.SEGMENT_SIZE = 2621440;

  this.async = true;

  this.MAX_CONCURRENT_ENCRYPTIONS = 1;
  this.segmentsCurrentlyEncrypting = 0;

  this.progressTracker = {};
  this.ssLegacyUpload = false;

  this.addFiles = function (packageId, keyCode, serverSecret, files, uploadType, statusCb, finished) {
    myself.getFileIDs(packageId, undefined, keyCode, serverSecret, files, uploadType, statusCb, finished);
  };

  this.addFilesToDirectory = function (packageId, directoryId, keyCode, serverSecret, files, uploadType, statusCb, finished) {
    myself.getFileIDs(packageId, directoryId, keyCode, serverSecret, files, uploadType, statusCb, finished);
  };

  this.getFileIDs = function (packageId, directoryId, keyCode, serverSecret, filesPath, uploadType, statusCb, finished) {
      let files = [];
      myself.uploadType = uploadType;
      myself.addEncryptionKey(packageId, serverSecret, keyCode);
    function handleResponse(index, parts, files, fileUtil) {
      if (files[index] === undefined) {
        myself.eventHandler.raiseError(UNHANDLED_EXCEPTION, 'getFileIDs: file at index ' + index + ' is undefined');
        return;
      }
      var serverFilename = (files[index].name === undefined) ? myself.defaultFileName : files[index].name;
      myself.responseParser.processAjaxDataRaw(myself.createFileID(packageId, directoryId, files[index], serverFilename, parts, uploadType, myself.async), function (resp) {
        if(resp.response === "SUCCESS") {
          myself.progressTracker[resp.message] = {};
          myself.progressTracker[resp.message].totalSize = files[index].size;
          myself.progressTracker[resp.message].parts = {};

          files[index].part = 0;
          files[index].id = resp.message;
          myself.fileIdToTargetDirectory[resp.message]=directoryId;

          if( files[index].url === undefined ) {
            //Add to encrypting Queue
            var filename = (files[index].name === undefined) ? myself.defaultFileName : files[index].name;
            myself.encrypting.push({"packageId": packageId, "directoryId": directoryId, "file":files[index], "parts": parts, "part": 1, "name": filename, "fileStart": 0, "id": resp.message, "fileUtil": fileUtil});

            var type= (directoryId === undefined) ? undefined : "directory";
            //TODO: REVIEW
            var event = {'fileId': files[index].id === undefined?resp.message:files[index].id, 'filePart':files[index].part, "parts":parts, 'name': filename, 'size': files[index].size, 'packageId': packageId, 'type': type};
            myself.eventHandler.raise("sendsafely.files.attached", event);
            /**
			 * @event sendsafely.files#attached
			 * @param {String} fileId
			 * @param {String} name
			 * @param {Number} size
			 * @param {String} packageId
			 */
			statusCb("ATTACH", files[index]);

            if(myself.encrypting.length === 1){
              myself.uploadPart(statusCb, finished);
            }

          } else {
            myself.loadBlobFromUrl(packageId, directoryId, statusCb, finished, files[index], parts);
          }
        } else if (resp.response === "LIMIT_EXCEEDED") {
          myself.eventHandler.raise(myself.LIMIT_EXCEEDED_EVENT, {error: resp.message});
        } else if (resp.response === "DUPLICATE_FILE") {
          myself.eventHandler.raiseError('DUPLICATE_FILE', resp.message, myself.DUPLICATE_FILE_EVENT);
        } else if (resp.response === "TIMEOUT") {
          myself.eventHandler.raise('session.timeout', resp.message);
        } else if (resp.response === "INVALID_FILE_NAME"){
          myself.abort();
          myself.eventHandler.raise(myself.INVALID_FILE_NAME_EVENT, {error: resp.response, message: resp.message});
        } else if(resp.response === "INVALID_FILE_EXTENSION"){
	        myself.eventHandler.raise(myself.INVALID_FILE_NAME_EVENT, {error: resp.response, message: resp.message});
        } else {
          myself.eventHandler.raise(myself.SERVER_ERROR_EVENT, {error: resp.response, message: resp.message});
        }
      });
    }

      let _loop = function _loop(i, _p) {
          return _p.then(function (_) {
              return new Promise(function (resolve) {
                  let f = filesPath[i];

                  if(typeof f === 'object' && f.hasOwnProperty('size')) {
                      myself.ssLegacyUpload = true;
                      let parts = 1;
                      if(f.size > (myself.SEGMENT_SIZE/4)) {
                          parts = 1 + Math.ceil((f.size - (myself.SEGMENT_SIZE / 4)) / myself.SEGMENT_SIZE);
                      }
                      handleResponse(i, parts, filesPath, null);
                      resolve();
                  } else {
                      let fileUtil = new FileUtil({filePath: f, callback: function(){}});
                      fileUtil.init().then(function(file) {
                          files[i] = file;
                          handleResponse(i, file.totalParts, files, fileUtil);
                          resolve();
                      }).catch(function(err) {
                          // Surface the missing/unreadable file through the established per-file
                          // upload-error channel instead of crashing the host process, then resolve
                          // so the remaining files in the list continue uploading.
                          myself.eventHandler.raise(myself.UPLOAD_ERROR_EVENT, {error: 'FILE_NOT_FOUND', message: err.message});
                          resolve();
                      });
                  }
              });
          });
      };

      let p = Promise.resolve();
      for (let i = 0; i < filesPath.length; i++) {
          p = _loop(i, p);
      }
      // Defense in depth: a synchronous throw from the FileUtil constructor runs inside the
      // _loop promise executor and rejects the chain. Route it through the event system rather
      // than letting it escape as an unhandled rejection that could terminate the host process.
      p.catch(function(err) {
          myself.eventHandler.raiseError(UNHANDLED_EXCEPTION, 'getFileIDs: ' + (err && err.message));
      });
  };

  this.createFileID = function(packageId, directoryId, data, fileName, parts, uploadType, async) {
        var handler = new CreateFileId(myself.eventHandler, myself.request);
    	handler.directoryId = directoryId;
    	return handler.execute(packageId, data, fileName, parts, uploadType, async);
  };

  this.markFileComplete = function(packageId, fileId, async, finished, failed, retryCounter) {
    var directoryId = myself.fileIdToTargetDirectory[fileId];
    return new MarkFileComplete(myself.eventHandler, myself.request).execute(packageId, directoryId, fileId, async, finished, failed, retryCounter);
  };

  this.getUploadUrls = function(packageId, fileId, part, forceProxy, async) {
    return new GetUploadUrls(myself.eventHandler, myself.request).execute(packageId, fileId, part, forceProxy, async);
  };

  this.uploadPart = function (statusCb, finished) {
    if(myself.encrypting.length >= 1){
      var currentFile = myself.encrypting[0];

      if(myself.ssLegacyUpload) {
          while(myself.segmentsCurrentlyEncrypting < myself.MAX_CONCURRENT_ENCRYPTIONS) {
              let fileSegment;

              if(currentFile.part === 1) {
                  fileSegment = _slice(currentFile.file.data, 0, Math.min((myself.SEGMENT_SIZE/4), currentFile.file.size))
                  myself.encrypting[0].fileStart = Math.min(myself.SEGMENT_SIZE/4, myself.encrypting[0].file.size);
              } else if(currentFile.part <= currentFile.parts) {
                  fileSegment = _slice(currentFile.file.data, currentFile.fileStart, Math.min(currentFile.fileStart+(myself.SEGMENT_SIZE) , currentFile.file.size))
                  myself.encrypting[0].fileStart = Math.min(myself.encrypting[0].fileStart+(myself.SEGMENT_SIZE), myself.encrypting[0].file.size);
              } else {
                  myself.encrypting.shift();
                  return myself.uploadPart(statusCb, finished);
              }

              readFileSegmentAndUpload(fileSegment);
          }

      } else {
          if(!currentFile.fileUtil.eof) {
              currentFile.fileUtil.callback = readFileSegmentAndUpload;
              currentFile.fileUtil.read();
          }
      }

        function readFileSegmentAndUpload(fileSegment) {
            var fileObj = {};
            fileObj.fileSegment = myself.ssLegacyUpload? fileSegment : fileSegment.data;
            fileObj.id = currentFile.id;
            fileObj.part = currentFile.part;
            fileObj.parts = currentFile.parts;
            fileObj.name = currentFile.name;
            fileObj.directoryId = currentFile.directoryId;

            myself.encrypting[0].part++;
            myself.segmentsCurrentlyEncrypting++;

            var packageId = currentFile.packageId;
            var directoryId = currentFile.directoryId;
            myself.sendFileToWorker(fileObj, packageId, directoryId, currentFile.file.size, statusCb, finished, function(){
                if(myself.ssLegacyUpload) {
                    myself.uploadPart(statusCb, finished);
                } else {
                    if(myself.segmentsCurrentlyEncrypting < myself.MAX_CONCURRENT_ENCRYPTIONS && !fileSegment.complete) {
                        currentFile.fileUtil.read();
                    } else if(fileSegment.complete) {
                        myself.encrypting.shift();
                        return myself.uploadPart(statusCb, finished);
                    }
                }
            });
        }
    }
  };

  this.loadBlobFromUrl = function (packageId, directoryId, statusCb, finished, file, parts) {
    var url = file.url;
    // The inner try/catch around statusCb / eventHandler.raise already isolates
    // consumer-callback throws (rethrown via setImmediate), so a trailing .catch
    // here only fires on real network/body failures — including mid-body socket
    // drops where response.arrayBuffer() rejects after headers were received.
    fetch(url, { method: 'GET' })
      .then(function (response) {
        if (response.status !== 200) {
          // Drain body for socket release. Errors here are uninteresting —
          // status was already non-200 so we will raise BLOB_ERROR regardless.
          response.arrayBuffer().catch(function () { /* drain only */ });
          myself.eventHandler.raiseError('BLOB_ERROR', 'Failed to load blob');
          return;
        }
        return response.arrayBuffer().then(function (buf) {
          var formattedResponse = new Uint8Array(buf);
          var blob = new Blob([formattedResponse], { type: 'application/octet-stream' });
          blob.part = file.part;
          blob.id = file.id;
          blob.name = file.name;

          var filename = (file.name === undefined) ? "Unknown File" : file.name;

          myself.encrypting.push({"packageId": packageId, "directoryId": directoryId, "file": blob, "name": filename, "parts": parts, "part": 1, "fileStart": 0, "id": blob.id});

          var event = {'fileId': file.id, 'name': file.name, 'size': file.size, 'packageId': packageId};
          try {
            myself.eventHandler.raise("sendsafely.files.attached", event);
            statusCb("ATTACH", file);
          } catch (e) { setImmediate(function () { throw e; }); }

          if (myself.encrypting.length === 1) {
            myself.uploadPart(statusCb, finished);
          }
        });
      })
      .catch(function (err) {
        myself.eventHandler.raiseError('BLOB_ERROR', (err && err.message) || 'Failed to load blob');
      });
  };

  this.SendPart = function(requestType, messageData, boundary, filesize, encryptedFile, filename, uploadCb, a_sync, packageId, done_callback, progress_callback, retryIterator) {

    var fileId = messageData.fileId;
    var filePart = messageData.filePart;
    if (myself.uploadUrls[fileId] === undefined || myself.uploadUrls[fileId][filePart] === undefined)
    {
      myself.responseParser.processAjaxDataRaw(myself.getUploadUrls(packageId, fileId, filePart, myself.ec2Proxy, a_sync), function (resp) {
        if(resp.response === "SUCCESS")
        {
          if (myself.uploadUrls[fileId] === undefined)
          {
            myself.uploadUrls[fileId] = {};
          }
          for (var i = 0; i < resp.uploadUrls.length; i++)
          {
            myself.uploadUrls[fileId][resp.uploadUrls[i].part] = resp.uploadUrls[i].url;
          }
          return myself.SendPartToServer(requestType, messageData, boundary, filesize, encryptedFile, filename, uploadCb, a_sync, packageId, done_callback, progress_callback, retryIterator);
        } else if (resp.response === "TIMEOUT") {
          myself.eventHandler.raise('session.timeout', resp.message);
        } else {
          myself.eventHandler.raise(myself.SERVER_ERROR_EVENT, {error: resp.response, message: resp.message});
        }
      });
    }
    else
    {
      return myself.SendPartToServer(requestType, messageData, boundary, filesize, encryptedFile, filename, uploadCb, a_sync, packageId, done_callback, progress_callback, retryIterator);
    }
  };

  this.SendPartToServer = function(requestType, messageData, boundary, filesize, encryptedFile, filename, uploadCb, a_sync, packageId, done_callback, progress_callback, retryIterator) {
    let fileId = messageData.fileId;
    let filePart = messageData.filePart;
    let multipart = {fileId: fileId, uploadType: myself.uploadType || myself.request.requestAPI, filePart: filePart};
    let multiPartForm = createMultiPartForm(boundary, JSON.stringify(multipart), encryptedFile.file);
    let url = requestType.url;
    let method = 'POST';
    let contentLength = Buffer.from(multiPartForm.buffer).length;
    let request = new FetchRequest({url: myself.request.url, strategy: myself.request.strategy, requestAPI: myself.request.requestAPI, apiPrefix: myself.request.apiPrefix});
    let res = undefined;

    if (!myself.ec2Proxy) {
        url = myself.uploadUrls[fileId][filePart];
        method = "PUT";
        contentLength = Buffer.from(encryptedFile.file).length;
        request = new FetchRequest({signedRequest: false});
        request = request.sendRequest(url, {method: method, headers: {'Content-Length': contentLength}, body: Buffer.from(encryptedFile.file), timeout: 25000});
    } else {
        request = request.sendSignedRequest({url: url, HTTPMethod: method, mimetype: 'multipart/form-data; boundary=' + boundary, messageData: messageData}, multiPartForm.buffer);
    }

    request.then(function(response) {
        res = response;
        if(response.status !== 200) {
            throw new Error('retry');
        } else if (response.status === 200 && response.headers.has('content-type') && response.headers.get('content-type')?.toLowerCase().includes('application/json')) {
            return response.json();
        }
    }).then(function(responseData) {
        uploadCb({loaded: contentLength});
        let response = {response:"SERVER_ERROR", message: "A server error has occurred, please try again."};
        if(myself.ec2Proxy && responseData !== undefined){
            response = responseData;
        }
        if(myself.ec2Proxy && response.response === "LIMIT_EXCEEDED") {
            myself.eventHandler.raise(myself.LIMIT_EXCEEDED_EVENT, {error: response.message});
        } else if(myself.ec2Proxy && response.response === "AUTHENTICATION_FAILED") {
            myself.removeFileFromQueue(messageData.fileId);
            myself.eventHandler.raise(myself.UPLOAD_ERROR_EVENT, {error: 'AUTHENTICATION_FAILED', message: response.message});
        } else if( (myself.ec2Proxy && response.response === "SUCCESS") || (! myself.ec2Proxy && res.status === 200) ) {
            let discard = myself.uploading.shift();
            discard = null;

            if(encryptedFile.part === encryptedFile.parts) {
                if (! myself.ec2Proxy) {
                    let counter = 0;
                    myself.markFileComplete(packageId, fileId, a_sync, function() { done_callback(packageId, fileId, filesize, filename); }, function() { myself.eventHandler.raise(myself.SERVER_ERROR_EVENT, {error: "FILE_INCOMPLETE", message: "Your file did not upload completely. Please refresh and try again."});}, counter);
                } else {
                    done_callback(packageId, fileId, filesize, filename);
                }
            }
            if(myself.uploading.length !== 0){
                myself.nextUploadFile(done_callback, progress_callback);
            }
        } else {
            if(myself.markedAsDeleted[messageData.fileId] === undefined) {
                if(retryIterator === undefined) {retryIterator = 1;}
                if(retryIterator < 5) {
                    myself.SendPart(requestType, messageData, boundary, filesize, encryptedFile, filename, uploadCb, a_sync, packageId, done_callback, progress_callback, retryIterator+1)
                } else {
                    myself.removeFileFromQueue(messageData.fileId, messageData.fileId);
                    let error = res.status;
                    let message = res.statusText;
                    if(myself.ec2Proxy) {
                        error = response.response;
                        message = response.message;
                    }
                    myself.eventHandler.raise(myself.UPLOAD_ERROR_EVENT, {error: error, message: message});
                }
            }
        }
    }).catch(function(err) {
        if(retryIterator === undefined) {retryIterator = 1;}
        if(retryIterator < 5) {
            setTimeout(function() {
                myself.SendPart(requestType, messageData, boundary, filesize, encryptedFile, filename, uploadCb, a_sync, packageId, done_callback, progress_callback, retryIterator+1);
            }, retryIterator*1000);
        } else {
            //If we fail 5 times and are not using the proxy, flip the proxy switch and try again
            if (! myself.ec2Proxy ) {
                myself.ec2Proxy = true;
                retryIterator = 0;
                setTimeout(function() {
                    myself.SendPart(requestType, messageData, boundary, filesize, encryptedFile, filename, uploadCb, a_sync, packageId, done_callback, progress_callback, retryIterator+1);
                }, retryIterator*1000);
            } else {
                myself.removeFileFromQueue(messageData.fileId, messageData.fileId);
                myself.eventHandler.raise(myself.UPLOAD_ERROR_EVENT, {error: err.code, message: "A server error occurred - Please try again."});
            }
        }
    });
  }

  this.abort = function(fileId) {
    // Remove from queues.
    myself.removeFileFromQueue(fileId);
    myself.eventHandler.raise(myself.UPLOAD_ABORT_EVENT, {'fileId': fileId});
  };

  this.sendFileToWorker = function (fileObject, packageId, directoryId, fileSize, statusCb, done, nextCb) {
    var key = myself.getEncryptionKey(packageId);
    var encryptCtx = {
      serverSecret: urlSafeBase64(key.serverSecret),
      packageId: packageId,
      directoryId: directoryId,
      fileId: fileObject.id,
      keycode: urlSafeBase64(key.keyCode),
      file: fileObject.fileSegment,
      fileSize: fileObject.size,
      name: fileObject.name,
      totalFileSize: fileSize,
      filePart: fileObject.part,
      parts: fileObject.parts,
      id: fileObject.id,
      boundary: '------JSAPIFormDataBoundary' + Math.random().toString(36)
    };

    // Fire ENCRYPTION_STARTED before kicking off the encryption so the
    // consumer-visible event order matches the worker-era contract:
    // ENCRYPTION_STARTED → FILE_ENCRYPTED → FILE_UPLOADING.
    _invokeCallbackSafely(statusCb, 'ENCRYPTION_STARTED', {
      id: encryptCtx.fileId,
      name: escapeHtml(encryptCtx.name),
      part: encryptCtx.filePart,
      size: encryptCtx.totalFileSize
    });

    openpgpOps.encryptFilePart(encryptCtx).then(
      function (ciphertext) {
        // Guard: _handleEncryptionComplete invokes consumer statusCb; a throw
        // there must not be mis-reported as UPLOAD_ERROR (that code path is
        // reserved for actual crypto failures).
        try { myself._handleEncryptionComplete(encryptCtx, ciphertext, statusCb, nextCb, done); }
        catch (e) { setImmediate(function () { throw e; }); }
      },
      function (err) {
        // Drive the failure to a terminal state: the success path is the only
        // place the encryption slot is released, so without this cleanup one
        // failed part saturates the MAX_CONCURRENT_ENCRYPTIONS gate and every
        // subsequent upload on this instance stalls forever.
        myself.segmentsCurrentlyEncrypting--;
        myself.removeFileFromQueue(encryptCtx.fileId);
        if (myself.eventHandler.isBound(myself.UPLOAD_ERROR_EVENT)) {
          myself.eventHandler.raise(myself.UPLOAD_ERROR_EVENT, { error: err.message, message: err.stack });
        } else {
          // raise() is a no-op with no listener bound; fall back to the
          // generic sendsafely.error channel so the failure is never silent.
          myself.eventHandler.raiseError('UPLOAD_ERROR', err.message);
        }
        if (myself.encrypting.length >= 1) {
          myself.uploadPart(statusCb, done);
        }
      }
    );
  };

  // Parity replacement for the upload worker's post-encryption emissions.
  // Composed of two ordered phases:
  //   (1) emit FILE_ENCRYPTED + FILE_UPLOADING and enqueue the segment
  //   (2) schedule the next encryption via the throttled gate
  // The phase ordering is load-bearing: `nextCb` may synchronously start
  // another encryption, which must not observe a queue missing the segment
  // we just finished. Phase 1 must complete before Phase 2 runs.
  this._handleEncryptionComplete = function (encryptCtx, ciphertext, statusCb, nextCb, done) {
    myself._emitEncryptedAndEnqueue(encryptCtx, ciphertext, statusCb, done);
    myself._scheduleNextEncryption(nextCb);
  };

  // Phase 1: emit the post-encryption state events, build the multipart
  // descriptor, push onto `uploading`, and kick off the upload chain if this
  // is the first segment.
  this._emitEncryptedAndEnqueue = function (encryptCtx, ciphertext, statusCb, done) {
    // The old upload worker emitted FILE_ENCRYPTED without a filesize field
    // (uploadWorker.js:283), so the listener forwarded `size: undefined`.
    // Preserve that asymmetry — only ENCRYPTION_STARTED carries the size.
    statusCb('FILE_ENCRYPTED', {
      id: encryptCtx.fileId,
      name: escapeHtml(encryptCtx.name),
      part: encryptCtx.filePart,
      size: undefined
    });

    myself.segmentsCurrentlyEncrypting--;
    statusCb('FILE_UPLOADING', { id: encryptCtx.fileId, part: encryptCtx.filePart });

    var messageData = {
      fileId: encryptCtx.fileId,
      uploadType: myself.uploadType || myself.request.requestAPI,
      filePart: encryptCtx.filePart
    };

    if (myself.markedAsDeleted[encryptCtx.fileId] !== undefined) {
      // Marked as deleted, do nothing
    } else {
      var data = {
        packageId: encryptCtx.packageId,
        boundary: encryptCtx.boundary,
        name: encryptCtx.name,
        fileId: encryptCtx.fileId,
        id: encryptCtx.id,
        file: ciphertext,
        part: encryptCtx.filePart,
        parts: encryptCtx.parts,
        filesize: encryptCtx.totalFileSize
      };
      myself.uploading.push({
        packageId: data.packageId,
        boundary: data.boundary,
        name: data.name,
        messageData: messageData,
        file: data,
        in_progressCb: function (jqXHR) {
          myself.sendProgress(myself.PROGRESS_EVENT, data.fileId, myself.calculateProgress(data.fileId, data.part, jqXHR.loaded));
        }
      });
    }

    if (myself.uploading.length === 1) {
      myself.nextUploadFile(done);
    }
  };

  // Phase 2: throttled gate — defers `nextCb` while the upload backlog is
  // saturated (>5 in flight). MUST run after enqueue completes; running it
  // earlier could let `nextCb` start an encryption that observes the queue
  // before the just-finished segment was pushed.
  this._scheduleNextEncryption = function (nextCb) {
    function moveToNextWhenReady() {
      if (myself.uploading.length > 5) {
        setTimeout(moveToNextWhenReady, 3000);
      } else {
        nextCb();
      }
    }
    moveToNextWhenReady();
  };

  this.sendProgress = function (event, fileId, percent) {
    myself.eventHandler.raise(event, {'fileId': fileId, 'percent': percent});
  };

  this.calculateProgress = function(fileId, currentPart, uploadedBytes) {
    var partArray = myself.progressTracker[fileId].parts;
    partArray[currentPart] = uploadedBytes;

    var totalSize = myself.progressTracker[fileId].totalSize;

    var uploadedSoFar = 0;
    for (var part in partArray) {
      uploadedSoFar += partArray[part];
    }

    var percent = Math.min(100, (uploadedSoFar/totalSize) * 100);
    return percent;
  };

  this.removeFileFromQueue = function(fileId) {
    // Go through the file queue
    for(var i = 0; i < this.encrypting.length; i++) {
      if(myself.encrypting[i].id == fileId) {
        myself.encrypting.splice(i, 1);
        i--;
      }
    }

    for(var i = 0; i < this.uploading.length; i++) {
      if(myself.uploading[i].file.fileId == fileId) {
        myself.uploading.splice(i, 1);
        i--;
      }
    }

    myself.markedAsDeleted[fileId] = true;

  };

  this.nextUploadFile = function(done){
    if(myself.uploading.length >= 1){
      var args = myself.uploading[0];
      myself.addFile(args.packageId, args.directoryId, args.file.filesize, args.boundary, args.messageData, args.file, args.name, args.in_progressCb, true, done);
    }
  };

  this.addFile = function (packageId, directoryId, filesize, boundary, messageData, file, name, in_progressCb, async, done_callback) {
    var endpoint;
    if(directoryId === undefined) {
      endpoint = myself.request.extend({}, myself.addFileEndpoint);
    } else {
      endpoint = myself.request.extend({}, myself.addFileToDirectoryEndpoint);
      endpoint.url = endpoint.url.replace("{directoryId}", directoryId);
    }

    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{fileId}", messageData["fileId"]);

    return myself.SendPart(endpoint, messageData, boundary, filesize, file, name, in_progressCb, async, packageId, done_callback, in_progressCb);
  };

  function createMultiPartForm (boundary, messageData, file) {
    var multiPartFormPre = '';
    multiPartFormPre += '--' + boundary + '\r\nContent-Disposition: form-data; name="requestData"';
    multiPartFormPre += '\r\n\r\n' + messageData + '\r\n';

    multiPartFormPre += '--' + boundary + '\r\nContent-Disposition: form-data; name="textFile"';
    multiPartFormPre += '; filename="file.txt"\r\n';
    multiPartFormPre += 'Content-Type: application/octet-stream\r\n\r\n';

    var end = "\r\n--" + boundary + '--\r\n';

    var length = multiPartFormPre.length + file.length + end.length;

    var arrayToSend = new Uint8Array(length);
    for (var i = 0; i<multiPartFormPre.length; i++) {
      arrayToSend.set([multiPartFormPre.charCodeAt(i) & 0xff], i);
    }

    arrayToSend.set(file, multiPartFormPre.length);

    var endIndex = 0;
    for (var i = (multiPartFormPre.length + file.length); i<length; i++) {
      arrayToSend.set([end.charCodeAt(endIndex) & 0xff], i);
      endIndex++;
    }
    return arrayToSend;
  }
  
  function _slice(blob, start, end) {

    if(blob.content !== undefined) {
      blob = blob.content;
    }

    if (blob.webkitSlice) {
      return blob.webkitSlice(start, end);
    } else {
      return blob.slice(start, end);
    }
  }

  this.addEncryptionKey = function(packageId, serverSecret, keyCode) {
    if(myself.encryptionKeyMapping[packageId] === undefined) {
      myself.encryptionKeyMapping[packageId] = {serverSecret: serverSecret, keyCode: keyCode};
    }
  };

  this.getEncryptionKey = function (packageId) {
    return myself.encryptionKeyMapping[packageId];
  };
}

function EncryptAndUploadKeycodes(eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/link/{publicKeyId}/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'add.keycode.failed';
  this.responseParser = new ResponseParser(eventHandler);

  this.addedKeycodes = 0;
  this.failedKeycodes = 0;
  this.totalNumber = 0;
  this.notifyRecipients = true;

  this.callback = undefined;

  var myself = this;

  // Fires the consumer callback once every key has either uploaded
  // (addedKeycodes) or failed (failedKeycodes). Failures are surfaced
  // separately via the event-bus channels (sendsafely.error / customErrorEvent).
  function maybeComplete() {
    if (myself.addedKeycodes + myself.failedKeycodes === myself.totalNumber
        && myself.callback !== undefined) {
      myself.callback();
    }
  }

  this.execute = function (packageId, publicKeys, keyCode, async, callback) {
    publicKeys = format(publicKeys);

    myself.async = async;
    myself.callback = callback;
    myself.totalNumber = publicKeys.length;

    if(publicKeys.length === 0) {
      myself.eventHandler.raise('keycodes.uploaded', {});
      callback();
      return;
    }

    var _loop = function _loop(i, _p) {
    	_p = _p.then(function (_) {
		    return new Promise(function (resolve) {
		      return encryptKeycode(publicKeys[i], keyCode, function(publicKeyId, encryptedKeycode) {
	        	resolve();
	            uploadKeycode(packageId, publicKeyId, encryptedKeycode);
		      }, function (err) {
		        // Record the failure; the error event has already been raised
		        // by EncryptKeycode. Resolve so the remaining keys are still
		        // processed.
		        myself.failedKeycodes++;
		        maybeComplete();
		        resolve();
		      });
		    });
		});
    	p = _p;
	};
    	
	for (var i = 0, p = Promise.resolve(); i < publicKeys.length; i++) {
		  _loop(i, p);
	}
    	    
  };

  this.executeSync = function (packageId, privateKey, publicKey, keyCode, async, callback) {
    myself.async = async;
    myself.callback = callback;
    myself.totalNumber = 1;
    decryptAndEncryptKeycode(privateKey, publicKey, keyCode, function(publicKeyId, encryptedKeycode) {
    	uploadKeycode(packageId, publicKeyId, encryptedKeycode);
    });
  };

  function uploadKeycode(packageId, publicKeyId, encryptedKeycode) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{publicKeyId}", publicKeyId);
    var response = myself.request.sendRequest(endpoint, {'keycode': encryptedKeycode, notifyRecipients: myself.notifyRecipients}, myself.async);

    // Independent .fail / .done listeners count HTTP-level failures and
    // non-SUCCESS response bodies (TIMEOUT or server-reported error) as
    // failures. The counted guard ensures each response increments exactly
    // one counter (added or failed, never both).
    var counted = false;
    function countFailureOnce() {
      if (counted) return;
      counted = true;
      myself.failedKeycodes++;
      maybeComplete();
    }
    response.fail(function () { countFailureOnce(); });
    response.done(function (data) {
      var parsed = data;
      if (typeof parsed === 'string') {
        try { parsed = JSON.parse(parsed); }
        catch (e) { parsed = null; }
      }
      if (!parsed || parsed.response !== 'SUCCESS') {
        countFailureOnce();
      }
    });

    myself.responseParser.processAjaxData(response, function (res) {
      myself.addedKeycodes++;
      maybeComplete();
    }, myself.customErrorEvent);
  }

  function encryptKeycode(publicKey, keyCode, callback, errorCallback) {
    var handler = new EncryptKeycode(myself.eventHandler);
    handler.execute(publicKey, keyCode, callback, errorCallback);
  }

  function decryptAndEncryptKeycode(privateKey, publicKey, keyCode, callback) {
    openpgpOps.decryptKeycode({ privateKey, keyCode })
      .then(function (decryptedKeycode) {
        return openpgpOps.encryptKeycode({ publicKey: publicKey.key, keyCode: decryptedKeycode });
      })
      .then(
        function (encryptedKeyCode) {
          _invokeCallbackSafely(callback, publicKey.id, encryptedKeyCode);
        },
        function (err) {
          myself.eventHandler.raiseError('KEYCODE_ENCRYPT_ERROR', err.message, myself.customErrorEvent);
        }
      );
  }

  function format(publicKeys) {
    if(publicKeys.constructor === Array) {
      return publicKeys;
    } else {
      return [publicKeys];
    }
  }

}
function EncryptKeycode (eventHandler) {
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'keycode.encrypt.failed';

  var myself = this;

  this.execute = function (publicKey, keyCode, callback, errorCallback) {
    seedRandomness(publicKey, keyCode, callback, errorCallback);
  };

  function startWorker(publicKey, keyCode, callback, errorCallback)
  {
    openpgpOps.encryptKeycode({ publicKey: publicKey.key, keyCode: keyCode }).then(
      function (encryptedKeyCode) {
        _invokeCallbackSafely(callback, publicKey.id, encryptedKeyCode);
      },
      function (err) {
        // raiseError(code, message, customError): the custom event name goes
        // third so 'keycode.encrypt.failed' listeners fire when bound and the
        // generic sendsafely.error channel fires otherwise (same wiring as
        // decryptAndEncryptKeycode).
        myself.eventHandler.raiseError('KEYCODE_ENCRYPT_ERROR', err.message, myself.customErrorEvent);
        if (errorCallback !== undefined) {
          _invokeCallbackSafely(errorCallback, err);
        }
      }
    );
  }

  function seedRandomness(publicKey, keyCode, callback, errorCallback)
  {
    myself.eventHandler.raise('sendsafely.entropy.ready', {});
    startWorker(publicKey, keyCode, callback, errorCallback);
  }
}
function EncryptMessage (eventHandler) {
  
  var myself = this;

  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  this.execute = function (message, packageId, keyCode, serverSecret, callback) {
    var msg = (message === undefined) ? "" : message;
    openpgpOps.encryptMessage({
      serverSecret: urlSafeBase64(serverSecret),
      keycode: urlSafeBase64(keyCode),
      message: msg
    }).then(
      function (encryptedBase64) {
        _invokeCallbackSafely(callback, encryptedBase64);
      },
      function (err) {
        eventHandler.raiseError('MESSAGE_ENCRYPT_ERROR', err.message);
      }
    );
  }

}
function FeedbackHandler (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/feedback/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'feedback.add.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (log, stacktrace, systemInfo, async, finished) {
    finished = (finished === undefined) ? function(){} : finished;

    var postData = {};
    postData.javalog = log;
    postData.stacktrace = stacktrace;
    postData.systemInfo = systemInfo;

    var endpoint = myself.request.extend({}, myself.endpoint);
    var response = myself.request.sendRequest(endpoint, postData, async);
    myself.responseParser.processAjaxData(response, function () {
      if(finished !== undefined) {
        finished();
      }
    }, myself.customErrorEvent);
  }
}
function FinalizePackage(eventHandler, request) {
  var myself = this;

  this.FINALIZE_ERROR = 'finalization.error';

  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/finalize/", "HTTPMethod" : "POST", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);
  this.notifyRecipients = false;
  this.readOnlyPdf = false;
  this.undisclosedRecipients = false;
  this.password = undefined;

  this.execute = function (packageId, packageCode, keyCode, async, finished) {
    finalizePackage(packageId, packageCode, keyCode, async, finished);
  };

  this.createChecksumFalse = function(keyCode, packageCode) {
    return pbkdf2Sha256Hex(urlSafeBase64(keyCode), urlSafeBase64(packageCode), 1024, 32);
  };

  function finalizePackage(packageId, packageCode, keyCode, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);

    var data = {};
    data.checksum = myself.createChecksumFalse(keyCode, packageCode);
    data.undisclosedRecipients = myself.undisclosedRecipients;
    data.notifyRecipients = myself.notifyRecipients;
    data.readOnlyPdf = myself.readOnlyPdf;
    
    if(myself.unconfirmedSender != undefined){
    	data.unconfirmedSender = myself.unconfirmedSender;
    }

    if(myself.confirmedSenderToken != undefined){
      data.confirmedSenderToken = myself.confirmedSenderToken;
    }

    if(myself.password != undefined) {
      data.password = myself.password;
    }

    var response = myself.request.sendRequest(endpoint, data, async);
    myself.responseParser.processAjaxDataRaw(response, function (data) {
      if(data.response == "SUCCESS") {
        var url = data.message + "#keyCode=" + urlSafeBase64(keyCode);
        finished(url, data.recipients, data.approvers, data.message, data.needsLink);
      }
      else {
        if(data.response == 'PACKAGE_NEEDS_APPROVAL') {
          data.message = data.message + "#keyCode=" + urlSafeBase64(keyCode);
        };
        myself.eventHandler.raise(myself.FINALIZE_ERROR, data);
      }
    });
  }

}

function GenerateKeyPair(eventHandler) {

  var myself = this;

  this.FINALIZE_ERROR = 'key.generate.error';
  this.PROGRESS_EVENT = "key.generate.progress";
  this.eventHandler = eventHandler;
  this.NAME = "Trusted Browser";
  this.EMAIL = "no-reply@sendsafely.com";

  this.execute = function (callback) {
    seedRandomness(callback);
  };

  function seedRandomness(callback)
  {
    myself.eventHandler.raise('sendsafely.entropy.ready', {});
    startWorker(callback);
  }

  function startWorker(callback) {
    openpgpOps.generateKeyPair({ userStr: buildNameStr() }).then(
      function (result) {
        _invokeCallbackSafely(callback, result.privateKey, result.publicKey);
      },
      function (err) {
        myself.eventHandler.raiseError(myself.FINALIZE_ERROR, err.message);
      }
    );
  }

  function buildNameStr() {
    return myself.NAME + ' <' + myself.EMAIL + '>';
  }

}
function GetDirectory (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/directory/{directoryId}", "HTTPMethod" : "GET", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);
  this.customError = "directory.information.failed";

  var myself = this;

  this.execute = function (packageId, directoryId, directoryIndex, fileIndex, sortField, sortOrder, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{directoryId}", directoryId);
    directoryIndex = (directoryIndex==undefined)?0:directoryIndex;
    fileIndex = (fileIndex==undefined)?0:fileIndex;
    sortField = (sortField==undefined || "") ? "name" : sortField;
    sortOrder = (sortOrder==undefined || "") ? "asc" : sortOrder;
    endpoint.url = endpoint.url+"?directoryIndex="+directoryIndex+"&fileIndex="+fileIndex+"&sortField="+sortField+"&sortOrder="+sortOrder;
      
    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {
      var data = {};
      data = res;
      finished(data);
    }, myself.customError);
  }
}
function GetEnterpriseInformation (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/enterprise/", "HTTPMethod" : "GET", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (async, finished) {
    var response = myself.request.sendRequest(myself.endpoint, null, async);
    myself.responseParser.processAjaxData(response, function(res) {
      finished(res.host, res.systemName, res.allowUndisclosedRecipients, res.headerColor, res.linkColor, res.messageEncryption);
    });
  }
}
function GetFileFromDirectory (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/directory/{directoryId}/file/{fileId}/", "HTTPMethod" : "GET", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, directoryid, fileId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    if (directoryid === undefined || directoryid === null )
    {
      endpoint.url = endpoint.url.replace("/directory/{directoryId}", "");
    }
    else
    {
      endpoint.url = endpoint.url.replace("{directoryId}", directoryid);
    }
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{fileId}", fileId);
    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {
      var data = {};
      data.fileId = res.file.fileId;
      data.fileName = res.file.fileName;
      data.fileSize = res.file.fileSize;
      data.createdByEmail = res.file.createdByEmail;
      data.createdById = res.file.createdById;
      data.oldVersions = res.file.oldVersions;
      data.uploaded = res.file.uploaded;
      data.uploadedStr = res.file.uploadedStr;
      data.fileParts = res.file.fileParts;
      data.fileKey = res.file.fileKey;

      finished(data);
    }, myself.customError);
  }
}
function GetKeycode (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/link/{publicKeyId}/", "HTTPMethod" : "GET", "mimetype": "application/json"};
  this.multipleEndpoint = { "url": "/public-key/{publicKeyId}/links/", "HTTPMethod" : "POST", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'keycode.get.failed';
  this.keycodeDecrypted = 'keycode.decrypted';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (privateKey, publicKeyId, packageId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{publicKeyId}", publicKeyId);
    var response = myself.request.sendRequest(endpoint, undefined, async);
    myself.responseParser.processAjaxData(response, function (res) {
      // Decrypt the keycode..
      var handler = new DecryptKeycode(myself.eventHandler);
      handler.execute(privateKey, res.message, function(keycode) {
        finished(keycode);
      });
    }, myself.customErrorEvent);
  };

  this.executeMultiple = function (privateKey, packageIds, publicKeyId, async, finished) {
    var endpoint = myself.request.extend({}, myself.multipleEndpoint);

    endpoint.url = endpoint.url.replace("{publicKeyId}", publicKeyId);
    var response = myself.request.sendRequest(endpoint, {packageIds: packageIds}, async);
    myself.responseParser.processAjaxData(response, function (res) {
      // Decrypt the keycode..
      res.keycodes.forEach(function(keyCodeObj) {
        var packageId = keyCodeObj.packageId;
        var handler = new DecryptKeycode(myself.eventHandler);
        handler.execute(privateKey, keyCodeObj.keycode, function(keycode) {
          myself.eventHandler.raise(myself.keycodeDecrypted, {packageId: packageId, keyCode: keycode});
        });
      });

    }, myself.customErrorEvent);
  };
}
function GetPackageActivityLog (eventHandler, request) {
    this.request = request;
    this.endpoint = { "url": "/package/{packageId}/activityLog/", "HTTPMethod" : "POST", "mimetype": "application/json"};
    this.eventHandler = eventHandler;
    this.customErrorEvent = 'package.information.failed';
    /**
    * Raised if an error happens. Code contains a response code originating from the server. Message is a more descriptive error message
	  * @event package.information#failed
	  * @type function
	  * @param code
	  * @param  message
	  */
    this.responseParser = new ResponseParser(eventHandler);

    var myself = this;

    this.execute = function (packageId, postData, userId, async, finished) {
        var endpoint = myself.request.extend({}, myself.endpoint);
        endpoint.url = endpoint.url.replace("{packageId}", packageId);
        
        if (userId) {
        	endpoint.url = endpoint.url + "{userId}".replace("{userId}", userId);
        }
        
        var response = myself.request.sendRequest(endpoint, postData, async);
        myself.responseParser.processAjaxData(response, function (res) {
            var data = {};
            data = res
            finished(data);
        }, myself.customErrorEvent);
    };

}

function GetSentPackages (eventHandler, request) {
    this.request = request;
    this.endpoint = { "url": "/package/", "HTTPMethod" : "GET", "mimetype": "application/json"};
    this.eventHandler = eventHandler;
    this.customErrorEvent = 'package.information.failed';
    this.responseParser = new ResponseParser(eventHandler);
    var myself = this;
    this.execute = function (rowIndex, userId, async, finished) {
        var endpoint = myself.request.extend({}, myself.endpoint);
        if (userId && userId != "") {
        	endpoint.url = endpoint.url + "sent/{userId}".replace("{userId}", userId);
        }
        rowIndex = (rowIndex==undefined)?0:rowIndex;
        endpoint.url = endpoint.url+"?rowIndex="+rowIndex;
        var response = myself.request.sendRequest(endpoint, null, async);
        myself.responseParser.processAjaxData(response, function (res) {
            var data = {};
            data = res
            finished(data);
        }, myself.customErrorEvent);
    };
}

function GetReceivedPackages (eventHandler, request) {
    this.request = request;
    this.endpoint = { "url": "/package/received/", "HTTPMethod" : "GET", "mimetype": "application/json"};
    this.eventHandler = eventHandler;
    this.customErrorEvent = 'package.information.failed';
    this.responseParser = new ResponseParser(eventHandler);
    var myself = this;
    this.execute = function (rowIndex, userId, async, finished) {
        var endpoint = myself.request.extend({}, myself.endpoint);
        if (userId) {
        	endpoint.url = endpoint.url + "{userId}".replace("{userId}", userId);
        }
        rowIndex = (rowIndex==undefined)?0:rowIndex;
        endpoint.url = endpoint.url+"?rowIndex="+rowIndex;
        var response = myself.request.sendRequest(endpoint, null, async);
        myself.responseParser.processAjaxData(response, function (res) {
            var data = {};
            data = res
            finished(data);
        }, myself.customErrorEvent);
    };
}

function GetArchivedPackages (eventHandler, request) {
    this.request = request;
    this.endpoint = { "url": "/package/archived/", "HTTPMethod" : "GET", "mimetype": "application/json"};
    this.eventHandler = eventHandler;
    this.customErrorEvent = 'package.information.failed';
    this.responseParser = new ResponseParser(eventHandler);
    var myself = this;
    this.execute = function (rowIndex, userId, async, finished) {
        var endpoint = myself.request.extend({}, myself.endpoint);
        if (userId) {
        	endpoint.url = endpoint.url + "{userId}".replace("{userId}", userId);
        }
	    rowIndex = (rowIndex==undefined)?0:rowIndex;
        endpoint.url = endpoint.url+"?rowIndex="+rowIndex;
        var response = myself.request.sendRequest(endpoint, null, async);
        myself.responseParser.processAjaxData(response, function (res) {
            var data = {};
            data = res
            finished(data);
        }, myself.customErrorEvent);
    };
}

function GetPackageInformation (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/", "HTTPMethod" : "GET", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'package.information.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);

    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {
      var data = {};
      data.packageId = res.packageId;
      data.packageCode = res.packageCode;
      data.rootDirectoryId = res.rootDirectoryId;
      data.serverSecret = res.serverSecret;
      data.recipients = res.recipients;
      data.files = res.files;
      data.directories = res.directories;
      data.approverList = res.approverList;
      data.needsApproval = res.needsApproval;
      data.state = res.state;
      data.life = res.life;
      data.label = res.label;
      data.url = res.url;
      data.archived = res.isArchived;
      finished(data);
    }, myself.customErrorEvent);
  };

  this.executeFromLink = function(link, async, finished) {
    var packageCode = getParameterByName(link, "packageCode");
    var keyCode = getFragmentParameterByName(link, "keyCode");
	if(keyCode == ""){
		keyCode = getFragmentParameterByName(link, "keycode");
	}
    myself.execute(packageCode, async, function(data) {
      data.keyCode = keyCode;
      finished(data);
    });
  };

  function getParameterByName(link, name) {
    name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
    var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
        results = regex.exec(link);
    return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
  }

  function getFragmentParameterByName(link, name) {
    name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
    var regex = new RegExp("[\\?&#]" + name + "=([^&#]*)"),
        results = regex.exec(link);
    return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
  }
}
function GetPublicKeys (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/public-keys/", "HTTPMethod" : "GET", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'keycode.get.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {
      finished(res.publicKeys);
    }, myself.customErrorEvent);
  }
}
function GetRecipient (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/recipient/{recipientId}/", "HTTPMethod" : "GET", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, recipientId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{recipientId}", recipientId);
    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {
      var data = {};
      data.recipientId = res.recipientId;
      data.approvalRequired = res.approvalRequired;
      data.email = res.email;
      data.fullName = res.fullName;
      data.smsAuth = res.smsAuth;
      data.countryCode = res.phonenumbers!=undefined? res.phonenumbers[0].countryCode:undefined;
      data.phoneNumber = res.phonenumbers!=undefined?res.phonenumbers[0].phonenumber:undefined;
      data.roleName = res.roleName;
      finished(data);
    }, myself.customError);
  }
}
function GetRecipientPublicKeys (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/{recipientId}/public-keys/", "HTTPMethod" : "GET", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'keycode.get.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, recipientId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{recipientId}", recipientId);
    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {
      finished(res.publicKeys);
    }, myself.customErrorEvent);
  }
}
function GetUserInformation (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/user/", "HTTPMethod" : "GET", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'user.information.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);

    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function(res) {
      var userObj = {};
      userObj.firstName = res.firstName;
      userObj.lastName = res.lastName;
      userObj.clientKey = res.clientKey;
      userObj.email = res.email;
      userObj.id = res.id;
      userObj.betaUser = res.betaUser;
      userObj.packageLife = res.packageLife;
      userObj.publicKey = res.publicKey;
      finished(userObj);
    }, myself.customErrorEvent);
  }
}
function ParseSendSafelyLinks () {
  var myself = this;

  this.execute = function (text) {
    var regexString = "(https:\/\/[a-zA-Z\.]+\/receive\/\\?[A-Za-z0-9&=\-]+packageCode=[A-Za-z0-9\-_]+#keyCode=[A-Za-z0-9\-_]+)";

    var regex = new RegExp(regexString,"g");
    var matches = getMatches(text, regex);

    var links = [];
    if (matches === null)
    {
      return [];
    }

    for (var i = 0; i < matches.length; i++)
    {
      var link = matches[i];
      // indexOf is supported in IE9 and up + all other browsers. The JS API requires IE10 so we are fine.
      if(links.indexOf(link) < 0) {
        links.push(link);
      }
    }

    return links;
  };

  function getMatches(string, regex, index) {
    index || (index = 1); // default to the first capturing group
    var matches = [];
    var match;
    while (match = regex.exec(string)) {
      matches.push(match[index]);
    }
    return matches;
  }
}
function RemovePublicKey (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/public-key/{publicKeyId}/", "HTTPMethod" : "DELETE", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'public.key.delete.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (publicKeyId, async, finished) {
    finished = (finished !== undefined) ? finished : new function() {};
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{publicKeyId}", publicKeyId);
    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function () {
      finished();
    }, myself.customErrorEvent);
  }
}
function RemoveRecipient (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/recipient/{recipientId}/", "HTTPMethod" : "DELETE", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);
  this.customErrorEvent = 'recipient.remove.failed';

  var myself = this;

  this.execute = function (packageId, recipientId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{recipientId}", recipientId);

    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function(data) {
      if(finished !== undefined) {
        finished(data.approvalRequired);
      }
    }, myself.customErrorEvent);
  }
}
function SaveMessage (eventHandler, request) {

  this.UPLOAD_ERROR_EVENT = 'message.upload.error';

  this.request = request;
  this.uploadAPI = request.requestAPI;
  this.endpoint = { "url": "/package/{packageId}/message/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);
  var myself = this;

  this.execute = function (packageId, message, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);

    var postData = {};
    postData['message'] = message;
    postData['uploadType'] = myself.uploadAPI;

    var response = myself.request.sendRequest(endpoint, postData, async);
    myself.responseParser.processAjaxData(response, finished, myself.UPLOAD_ERROR_EVENT);
  }
}
function SyncKeycodes (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/sync/{publicKeyId}/", "HTTPMethod" : "GET", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'sync.keycodes.failed';
  this.responseParser = new ResponseParser(eventHandler);

  this.KEYCODE_SYNC_PROGRESS = 'sync.keycodes.progress';

  var myself = this;

  this.execute = function (privateKey, publicKeyId, async, callback) {
    callback = (callback === undefined) ? function(){} : callback;

    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{publicKeyId}", publicKeyId);
    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {

      if(res.keycodes.length === 0) {
        callback();
      }

      raiseProgressEvent(res.keycodes.length, 0);

      myself.eventHandler.raise('sendsafely.entropy.ready', {});
      encryptKeycodes(res, privateKey, callback);
    }, myself.customErrorEvent);
  };

  function encryptKeycodes(res, privateKey, callback) {
    var counter = 0;
    eventHandler.bind("add.keycode.failed", function() {
      counter = counter+1;
      if(counter === res.keycodes.length) {
        callback();
      }
      else
      {
        recurseCodes();
      }
    });

    //Use recursion to post keycodes synchronously, otherwise the browser will hang on too many threads
    function recurseCodes()
    {
      var handler = new EncryptAndUploadKeycodes(myself.eventHandler, myself.request);
      handler.notifyRecipients = false;
      handler.executeSync(res.keycodes[counter].packageId, privateKey, findPublicKey(res.keycodes[counter], res.publicKeys), res.keycodes[counter].keycode, myself.async, function() {
        //encryptedKeycodes = encryptedKeycodes+1;
        counter = counter+1;
        raiseProgressEvent(res.keycodes.length, counter);
        if(counter === res.keycodes.length) {
          callback();
        }
        else
        {
          recurseCodes();
        }
      });
    }
    if (res.keycodes.length > 0)
    {
      recurseCodes();
    }
  }

  function findPublicKey(keycode, publicKeys) {
    for(var i = 0; i<publicKeys.length; i++) {
      if(publicKeys[i].id === keycode.publicKeyId) {
        return publicKeys[i];
      }
    }

    return undefined;
  }

  function raiseProgressEvent(total, doneSoFar) {
    myself.eventHandler.raise(myself.KEYCODE_SYNC_PROGRESS, {total: total, completed: doneSoFar});
  }
}
function UpdateDirectory (eventHandler, request) {
  this.request = request;
  this.endpoint = {
    "url": "/package/{packageId}/move/{sourcedirectoryId}/{targetdirectoryId}/",
    "HTTPMethod": "POST",
    "mimetype": "application/json"
  };
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, sourceDirectoryId, targetDirectoryId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{sourcedirectoryId}", sourceDirectoryId);
    endpoint.url = endpoint.url.replace("{targetdirectoryId}", targetDirectoryId);

    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {
      var data = {};
      data.message = res.message;
      finished(data);
    }, myself.customError);
  }
}
function UpdateDirectoryName (eventHandler, request) {
    this.request = request;
    this.endpoint = {
        //TODO: Get the right endpoint here.
        "url": "/package/{packageId}/directory/{directoryId}",
        "HTTPMethod": "POST",
        "mimetype": "application/json"
    };
    this.eventHandler = eventHandler;
    this.customError = 'directoryName.failed';
    this.responseParser = new ResponseParser(eventHandler);

    var myself = this;

    this.execute = function (packageId, directoryId, directoryName, async, finished) {
        var endpoint = myself.request.extend({}, myself.endpoint);
        endpoint.url = endpoint.url.replace("{packageId}", packageId);
        endpoint.url = endpoint.url.replace("{directoryId}", directoryId);

        var postData = {};
        postData['directoryName'] = directoryName;
        var response = myself.request.sendRequest(endpoint, postData, async);
        myself.responseParser.processAjaxData(response, function (res) {
            var data = {};
            data.message = res.message;
            finished(data);
        }, myself.customError);
    }
}

function UpdateFileName (eventHandler, request) {
    this.request = request;
    this.endpoint = {
        "url": "/package/{packageId}/file/{fileId}",
        "HTTPMethod": "PATCH",
        "mimetype": "application/json"
    };
    this.eventHandler = eventHandler;
    this.customError = 'fileName.failed';
    this.responseParser = new ResponseParser(eventHandler);

    var myself = this;

    this.execute = function (packageId, fileId , fileName, async, finished) {
        var endpoint = myself.request.extend({}, myself.endpoint);
        endpoint.url = endpoint.url.replace("{packageId}", packageId);
        endpoint.url = endpoint.url.replace("{fileId}", fileId);

        var postData = {};
        postData['fileName'] = fileName;
        var response = myself.request.sendRequest(endpoint, postData, async);
        myself.responseParser.processAjaxData(response, function (res) {
            //var data = {};
            //data.message = res.message;
            finished(res);
        }, myself.customError);
    }
}

function UpdatePackage (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/", "HTTPMethod" : "POST", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, data, async, finished){
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);

    if(data.life !== undefined) {
      // Verify that the life is a number
      if(!isInt(data.life)) {
        myself.eventHandler.raiseError("FAIL", "You did not provide a valid number of days", 'sendsafely.error');
        return;
      }
    }

    var response = myself.request.sendRequest(endpoint, data, async);
    myself.responseParser.processAjaxData(response, finished);
  };
}

function isInt(value) {
  return !isNaN(value) &&
      parseInt(Number(value)) == value &&
      !isNaN(parseInt(value, 10));
}
function UpdateRole (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/recipient/{recipientId}/", "HTTPMethod" : "POST", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customError = 'roles.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, recipientId, roleName, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{recipientId}", recipientId);

    var data = {};
    data.roleName = roleName;

    var response = myself.request.sendRequest(endpoint, data, async);
    myself.responseParser.processAjaxData(response, function (res) {
      var data = {};
      data.message = res.message;
      data.response = res.response;
      data.roleName = res.roleName;
      finished(data);
    }, myself.customError);
  }
}
function VerifyCredentials (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/config/verify-credentials/", "HTTPMethod" : "GET", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (async, finished) {
    var response = myself.request.sendRequest(myself.endpoint, null, async);
    myself.responseParser.processAjaxData(response, function(res) {
      finished(res.message);
    });
  }


}
function VerifyVersion (eventHandler, request) {
  this.VERSION_NUMBER = 0.1;

  this.request = request;
  this.endpoint = {"url": "/config/version/{api}/{versionNo}/", "HTTPMethod" : "GET", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function(api_identifier, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{versionNo}", myself.VERSION_NUMBER);
    endpoint.url = endpoint.url.replace("{api}", (api_identifier == undefined) ? "NODE_API" : api_identifier);

    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function(res) {
      finished(res.version);
    });
  }

}

function GetPackageMessage (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": '/package/{packageId}/message/{checksum}', "HTTPMethod" : "GET", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'package.message.failed';
  this.responseParser = new ResponseParser(eventHandler);
  var myself = this;
  this.execute = function (packageId, packageCode, keyCode, async, finished) {
    var checksum = createChecksum(keyCode, packageCode);
    if (packageId === undefined) {
      throw new Error("Unable to get package message without package ID");
    } else if (checksum === undefined) {
      throw new Error("Unable to get package message without checksum");
    } else {
      var endpoint = myself.request.extend({}, myself.endpoint);
      endpoint.url = endpoint.url.replace("{packageId}", packageId);
      endpoint.url = endpoint.url.replace("{checksum}", checksum);
      var response = myself.request.sendRequest(endpoint, null, async);
      myself.responseParser.processAjaxData(response, function (res) {
        var data = {};
        data.message = res.message;
        finished(data);
      }, myself.customErrorEvent);
    }
  }

  function createChecksum(keyCode, packageCode) {
    return pbkdf2Sha256Hex(urlSafeBase64(keyCode), urlSafeBase64(packageCode), 1024, 32);
  }
}

SendSafely.SDK_VERSION = Version.SDK_VERSION;
SendSafely.SDK_VERSION_HEADER = Version.SDK_VERSION_HEADER;
SendSafely.SDK_VERSION_VALUE = Version.SDK_VERSION_VALUE;
SendSafely.CLIENT_VERSION_HEADER = Version.CLIENT_VERSION_HEADER;

/**
 * Sets the value sent in the `ss-client-version` header on every subsequent
 * request, so an integration (e.g. SendSafely MCP) can identify itself in
 * server-side telemetry alongside the SDK's own `ss-sdk-version` header.
 * Process-global; call once at startup. Pass `null` to clear.
 * @param {string|null} version Integration-supplied version string, e.g. `"SendSafely MCP/0.1.0"`.
 * @returns {void}
 */
SendSafely.setClientVersion = Version.setClientVersion;

SendSafely.SendSafelyDropzone = function SendSafelyDropzone(url, dropzoneId) {
	const myself = new SendSafely(url, dropzoneId, null);
	myself.notifyRecipients = false;

	myself.setUnconfirmedSender = function(email){
		myself.unconfirmedSender = email;
	}

	return myself
};

/**
 * NOTE: OAuth 2.1 Bearer authentication is not available for use just yet — it is
 * planned for a future release. Please continue to use the HMAC API key/secret
 * constructor until OAuth support is officially released.
 *
 * Constructs a SendSafely client that authenticates /api/v2.0 calls with an OAuth 2.1
 * Bearer access token instead of an HMAC API key/secret. Additive to the positional
 * `new SendSafely(url, apiKeyId, apiKeySecret)` constructor, which is unchanged.
 *
 * The caller owns the OAuth flow and token refresh; the SDK only attaches the supplied
 * token and never stores a refresh token. On expiry the SDK raises OAUTH_TOKEN_INVALID;
 * the caller obtains a fresh token, calls `setAccessToken(token)`, and re-invokes.
 * @param {string} url The SendSafely host the token's aud/tenant_host must match.
 * @param {string} token A pre-obtained OAuth 2.1 access token (JWT).
 * @param {string} [requestAPI] Optional ss-request-api identifier.
 * @returns {SendSafely}
 */
SendSafely.withBearerToken = function (url, token, requestAPI) {
	// Bearer tokens are the full credential and are sent on every request — never in cleartext.
	// localhost/127.0.0.1 are exempt for local development and testing only (documented in
	// README and SendSafely.d.ts); never point a real token at a plaintext URL.
	const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/i.test(url);
	if (!/^https:\/\//i.test(url) && !isLocal) {
		throw new Error('withBearerToken requires an https:// URL — bearer tokens must not be sent in cleartext.');
	}
	if (typeof token !== 'string' || token.length === 0) {
		throw new Error('withBearerToken requires a non-empty access token string.');
	}
	const strategy = new BearerAuthStrategy(token, requestAPI || 'NODE_API');
	return new SendSafely(url, null, undefined, requestAPI, { strategy });
};

module.exports = SendSafely;
// Not part of the public API: exposed so the credential-free tests can drive the download path.
module.exports.WriteStreamStorage = WriteStreamStorage;
module.exports.DownloadAndDecryptFile = DownloadAndDecryptFile;

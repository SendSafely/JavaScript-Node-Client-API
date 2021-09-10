const URL = require('url').URL;
const Window = require('window');
const window = new Window();
const self = window;
const sjcl = require("sjcl");
const crypto = require("crypto");
const https = require('https');
const fs = require('fs');
const openpgp = require('openpgp');
const $ = require("jquery")(window);
var XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
const path = require("path");
const {AnonymousRequest} = require('./Dropzone');

eval(fs.readFileSync(__dirname + '/uploadWorker.js').toString());
eval(fs.readFileSync(__dirname + '/keyGeneratorWorker.js').toString());
var eventListenerTracker = {};

/**
 * @description The only constructor for the library.
 * @param {String} url The SendSafely host/url that the API will connect to.
 * @param {String} apiKey The API Key that will be used to authenticate to SendSafely.
 * @param {String} apiSecret The API Secret that will be used to authenticate to SendSafely.
 * @returns {constructor}
 */
function SendSafely(url, apiKeyId, apiKeySecret, requestAPI){
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
  this.serverWorkerURI = undefined;
  this.keyGeneratorURI = undefined;
  this.uploadAPI = undefined;
  this.url = url;
  this.requestAPI = (requestAPI === undefined) ? "NODE_API" : requestAPI;
  
  sjcl.codec.utf8String.fromBits = function(a) {
    var b = "",
      c = sjcl.bitArray.bitLength(a),
      d,
      e;
    for (d = 0; d < c / 8; d++)
      0 === (d & 3) && (e = a[d / 4]),
      b += String.fromCharCode(e >>> 8 >>> 8 >>> 8),
      e <<= 8;

    return decodeURIComponent(encodeURIComponent(b));
  }
  

  sjcl.random.setDefaultParanoia(6);
  //sjcl.random.startCollectors();
  var buf = crypto.randomBytes(1024 / 8) // 128 bytes
  buf = new Uint32Array(new Uint8Array(buf).buffer)
  sjcl.random.addEntropy(buf, 1024, "crypto.randomBytes");
  sjcl.random.addEventListener("seeded", function () {
    sjcl.random.stopCollectors();
  });

  this.eventHandler = new EventHandler(myself);
  this.executor = new Executor(myself.eventHandler);
  
  if (apiKeyId !== null && apiKeySecret === null){
  	this.request = new AnonymousRequest(myself.eventHandler, url, apiKeyId, myself.requestAPI);
  } else {
    this.request = new SignedRequest(myself.eventHandler, url, apiKeyId, apiKeySecret, myself.requestAPI);
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
    handler.serverWorkerURI = myself.keyGeneratorURI;
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
        var notifyRecipients = (myself.notifyRecipients === undefined) ? true : myself.notifyRecipients;
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
	 * @param {List<file>} files  An array of files that are being uploaded.
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

    if(myself.serverWorkerURI != undefined) {
      myself.uploadHandler.serverWorkerURI = myself.serverWorkerURI;
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
	 * @param {List<file>} files  An array of files that are being uploaded.
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
      myself.uploadHandler.serverWorkerURI = myself.serverWorkerURI;
    }

    myself.executor.run(function() {
      myself.uploadHandler.addFilesToDirectory(packageId, directoryId, keyCode, serverSecret, files, uploadType, function(state, data) {
        myself.eventHandler.raise("sendsafely.status", {'state': state, 'data': data});
      }, finished);
    }, 'File Upload Failed');
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
    var handler = new GetKeycode(myself.eventHandler, myself.request);
    handler.serverWorkerURI = myself.keyGeneratorURI;
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
      generateKeyPairFunction.serverWorkerURI = myself.keyGeneratorURI;
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
            generateKeyPairFunction.serverWorkerURI = myself.keyGeneratorURI;
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
      myself.downloadHandler = new DownloadAndDecryptFile(myself.eventHandler, myself.request, myself.serverWorkerURI);
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
      myself.downloadHandler = new DownloadAndDecryptFile(myself.eventHandler, myself.request, myself.serverWorkerURI);
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
    messageEncryptor.serverWorkerURI = myself.serverWorkerURI;
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
    handler.serverWorkerURI = myself.serverWorkerURI;
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
    handler.serverWorkerURI = myself.serverWorkerURI;
    handler.execute(ciphertext, packageId, keyCode, serverSecret, finished);
  };

  /*
   * INTERNAL FUNCTIONS BELOW THIS POINT
   */
  /**
	 * @ignore
	 */
  this.checkAPIInitialized = function() {
    if(typeof sjcl === "undefined"){
      throw "SJCL is not defined";
    }
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
    var handler = new SyncKeycodes(myself.eventHandler, myself.request);
    handler.serverWorkerURI = myself.keyGeneratorURI;
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

}

//Other Functions
function urlSafeBase64(base64String) {
	if( typeof base64String == "string"){
		base64String = base64String.replace(/\+/g, '-');
		base64String = base64String.replace(/\//g, '_');
		base64String = base64String.replace(/=/g, '');
		return base64String;
	}
}

function urlunSafeBase64(base64String) {
	if( typeof base64String == "string"){
		base64String = base64String.replace(/-/g, '+');
		base64String = base64String.replace(/_/g, '/');
		return base64String;
	}
}

function SignedRequest(eventHandler, url, apiKey, apiKeySecret, requestAPI) {

  var myself = this;

  this.apiPrefix = '/api/v2.0';
  this.url = url;
  this.apiKey = apiKey;
  this.apiKeySecret = apiKeySecret;
  this.eventHandler = eventHandler;
  this.requestAPI = requestAPI;

  this.sendRequest = function (requestType, messageData, a_sync){
    var timestamp = myself.dateString();
    var messageString = myself.apiKey + myself.apiPrefix + requestType.url.split("?")[0] + timestamp
    if (messageData != "" && messageData != null)
      messageString += JSON.stringify(messageData);
    var signature = this.signMessage(messageString);

    if(typeof a_sync === "undefined"){
      a_sync = true;
    }

    return $.ajax({
      url: myself.url + myself.apiPrefix + requestType.url,
      type: requestType.HTTPMethod,
      timeout: 25000,
      data: messageData == null ? null : JSON.stringify(messageData),
      contentType: requestType.mimetype,
      headers: { 	'ss-api-key': myself.apiKey,
        'ss-request-timestamp': timestamp,
        'ss-request-signature': signature,
        'ss-request-api' : myself.requestAPI},
      crossDomain: true,
      async: a_sync,
      retryCount: 2 //Need to Implement.
    })
  };
  
  this.getHTTPSOptionForFileUpload = function (uri, method, messageData, boundary, isEC2Proxy) {
		var timestamp = myself.dateString();
	    var header = myself.apiKey + myself.apiPrefix + uri + timestamp + messageData;	    
		var signature = myself.signMessage(header);
		var headers = {
			    'Content-Type': 'multipart/form-data; boundary=' + boundary,
			    'ss-api-key':myself.apiKey,
			    'ss-request-timestamp': timestamp,
			    'ss-request-signature': signature,
			    'ss-request-api': myself.requestAPI
			  };
		var url = new URL(myself.url + myself.apiPrefix + uri);
		
		if(!isEC2Proxy) {
			headers = {};
			url = new URL(uri);
		}
			        
	    var options = {
	    	hostname: url.hostname,
	    	port: url.port,
	    	path: url.pathname + url.search,
	    	headers: headers,
	    	method: method,
	    }

	    return options;
	  }

  this.getHTTPObjForFileUpload = function (uri, messageData, boundary, a_sync) {

    var timestamp = myself.dateString();
    var header = myself.apiKey + myself.apiPrefix + uri + timestamp + messageData;

    var signature = myself.signMessage(header);

    var xhr = new XMLHttpRequest();
    var url = myself.url + myself.apiPrefix + uri;

    xhr.open('POST', url, a_sync);

    xhr.setRequestHeader('Content-Type', 'multipart/form-data; boundary=' + boundary);
    xhr.setRequestHeader('ss-api-key', myself.apiKey);
    xhr.setRequestHeader('ss-request-timestamp', timestamp);
    xhr.setRequestHeader('ss-request-signature', signature);
    xhr.setRequestHeader('ss-request-api', myself.requestAPI);

    return xhr;
  };

  this.getHTTPObjForFileDownload = function (uri, messageData) {

    var timestamp = myself.dateString();
    var header = myself.apiKey + myself.apiPrefix + uri + timestamp + messageData;

    var signature = myself.signMessage(header);

    var xhr = new XMLHttpRequest();
    var url = myself.url + myself.apiPrefix + uri;

    xhr.open('POST', url, true);

    xhr.responseType = 'arraybuffer';
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.setRequestHeader('ss-api-key', myself.apiKey);
    xhr.setRequestHeader('ss-request-timestamp', timestamp);
    xhr.setRequestHeader('ss-request-signature', signature);
    return xhr;
  };
  
  this.getHTTPSOptionForFileDownload = function (uri, messageData) {
	var timestamp = myself.dateString();
	var header = myself.apiKey + myself.apiPrefix + uri + timestamp + messageData;

	var signature = myself.signMessage(header);
	var method = 'GET';
	var headers = {
		    'Content-Type': 'application/json',
		    'Content-Length': messageData.length,
		    'ss-api-key':myself.apiKey,
		    'ss-request-timestamp': timestamp,
		    'ss-request-signature': signature
		  };
		      
    var url = new URL(uri);	    
    var options = {
    	hostname: url.hostname,
    	port: url.port,
    	path: url.pathname + url.search,
    	headers: headers,
    	method: method,
    }
    return options;
  }

	/**
	 * Generates a ISO Timestamp to the nearest second
	 * @ignore
	 * @returns {string} ISO timestamp
	 */
  this.dateString = function() {
    var time = new Date().toISOString();
    return time.substr(0, 19) + "+0000"; //2014-01-14T22:24:00+0000
  };

  this.signMessage = function (messageString) {
    var hmacFunction = new sjcl.misc.hmac(sjcl.codec.utf8String.toBits(myself.apiKeySecret), sjcl.hash.sha256);// Key, Hash

    return sjcl.codec.hex.fromBits(hmacFunction.encrypt(messageString));

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
      myself.isBound(eventStr);
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
    myself.eventHandler.raiseError('UNHANDLED_EXCEPTION', {message: errorMessage, stacktrace: err});
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
	  myself.fileWriteStream.end();
	  myself.eventHandler.raise(myself.FILE_SAVED_EVENT, {fileId: fileId, config: myself.config});
  };
}

function WorkerPool(serverWorkerURI, eventListener)
{
  var myself = this;
  this.serverWorkerURI = serverWorkerURI;
  this.workerPool = [];
  this.eventListener = eventListener;

  this.getWorker = function() {
    for(var i = 0; i<myself.workerPool.length; i++) {
      if(myself.workerPool[i].available) {
        myself.workerPool[i].available = false;
        return myself.workerPool[i];
      }
    }

    var worker;
    if(typeof uploadWorkerURL !== 'undefined') {
      worker = new Worker(uploadWorkerURL);
    } else {
      worker = new Worker(myself.serverWorkerURI);
    }
    myself.workerPool.push({'available': false, 'id': myself.workerPool.length, 'worker': worker});
    myself.addWorkerEventListener(worker);
    return myself.workerPool[myself.workerPool.length-1];
  };

  this.markAsAvailable = function(id) {
    for(var i = 0; i<myself.workerPool.length; i++) {
      if(myself.workerPool[i].id == id) {
        myself.workerPool[i].available = true;
        return;
      }
    }
  }

  this.addWorkerEventListener = function (worker) {
    worker.addEventListener('message', function(data) {
      myself.eventListener(worker.id, data);
    }, false);
  };
}
function AddContactGroup (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/group/{groupId}/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'recipients.add.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;
  this.execute = function (packageId, groupId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{groupId}", groupId);
    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {
      finished(res);
    }, myself.customErrorEvent);
  }
}
function AddContactGroupToPackage (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/group/{groupId}/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'contact.group.add.failed';
  this.responseParser = new ResponseParser(eventHandler);
  this.directoryId = undefined;
  
  var myself = this;
  this.execute = function (packageId, groupId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{groupId}", groupId);
    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {
      finished(res);
    }, myself.customErrorEvent);
  }
}
function AddGroupMember (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/group/{groupId}/user/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'group.member.add.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (groupId, email, async, finished) {
    finished = (finished === undefined) ? function(){} : finished;

    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{groupId}", groupId);
    var response = myself.request.sendRequest(endpoint, {'userEmail': email}, async);
    myself.responseParser.processAjaxData(response, function (res) {
      finished(res);
    }, myself.customErrorEvent);
  }
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
    handler.serverWorkerURI = myself.serverWorkerURI;
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
    handler.serverWorkerURI = myself.serverWorkerURI;
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
function ConvertRSAKey(eventHandler) {

  var myself = this;

  this.FINALIZE_ERROR = 'key.generate.error';
  this.PROGRESS_EVENT = "key.generate.progress";
  this.eventHandler = eventHandler;
  this.NAME = "Trusted Browser";
  this.EMAIL = "no-reply.sendsafely.com";

  this.execute = function (data, callback) {
    seedRandomness(data, callback);
  };

  function seedRandomness(data, callback)
  {
    if(sjcl.random.isReady(6) == 0)
    {
      sjcl.random.addEventListener("seeded", function () {
        startWorker(data, callback);
      });
      sjcl.random.addEventListener("progress", function(evt) {
        var entropyPercent = 0;
        if(evt != undefined && evt != 1 && !isNaN(evt)) {
          entropyPercent = (evt*100);
          myself.eventHandler.raise('sendsafely.entropy.progress', {entropy: entropyPercent});
        } else {
          myself.eventHandler.raise('sendsafely.entropy.ready', {});
        }
      });
    }
    else {
      myself.eventHandler.raise('sendsafely.entropy.ready', {});
      startWorker(data, callback);
    }
  }

  function startWorker(data, callback) {
    var randomness = sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(1024,6));

    // Create the worker.
    //var worker = new Worker(myself.serverWorkerURI);

    window.addEventListener('message', function(e)
    {
      var data = e.data;
      switch (data.cmd)
      {
        case 'key_converted':
          if(callback !== undefined) {
            callback(data.privateKey, data.publicKey);
          }
          break;
        case 'randBuff':
          randomness = sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(data.bytes,6));
          window.postMessage({'cmd': 'randBuff', 'randomness': randomness},'*');
          break;
        case 'debug':
          break;
      }
    }, false);
    window.postMessage({'cmd': 'convert_key', rsaKeys: data, 'userStr': buildNameStr(), 'randomness': randomness},'*');
  }

  function buildNameStr() {
    return myself.NAME + ' <' + myself.EMAIL + '>';
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
    postData['uploadType'] = uploadType;
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

function CreateFileIdDirectory(eventHandler, request) {
  var myself = this;

  this.request = request;
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  this.endpoint = { "url": "/package/{packageId}/file/", "HTTPMethod" : "PUT", "mimetype": "application/json"};

  this.execute = function (packageId, data, parts, uploadType, directoryId, async) {
    var endpoint = myself.request.extend({}, myself.endpoint);

    var postData = {};
    postData['filename'] = data.name;
    postData['uploadType'] = uploadType;
    postData['parts'] = parts;
    postData['filesize'] = data.size;
    postData['directoryId'] = directoryId;
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    return myself.request.sendRequest(endpoint, postData, async);
  }

}
function CreateGroup (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/group/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'group.create.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (groupName, isEnterpriseGroup, async, finished) {
    finished = (finished === undefined) ? function(){} : finished;

    var endpoint = myself.request.extend({}, myself.endpoint);
    var response = myself.request.sendRequest(endpoint, {'groupName': groupName, 'isEnterpriseGroup':isEnterpriseGroup}, async);
    myself.responseParser.processAjaxData(response, function (res) {
      finished(res);
    }, myself.customErrorEvent);
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

      if(sjcl.random.isReady(6) == 0)
      {
        //Set progress to zero to reveal the dialog
        myself.eventHandler.raise('sendsafely.entropy.progress', {entropy: 0});
        sjcl.random.addEventListener("seeded", function () {
          populateAndSendReturnData();
        });
        sjcl.random.addEventListener("progress", function(evt) {
          var entropyPercent = 0;
          if(evt != undefined && evt != 1 && !isNaN(evt)) {
            entropyPercent = (evt*100);
            myself.eventHandler.raise('sendsafely.entropy.progress', {entropy: entropyPercent});
          } else {
            myself.eventHandler.raise('sendsafely.entropy.ready', {});
          }
        });
      }
      else {
        populateAndSendReturnData();
      }
    }, myself.CREATE_PACKAGE_FAILED);
  };

  this.createKeycode = function(callback) {
    if(sjcl.random.isReady(6) == 0)
    {
      sjcl.random.addEventListener("seeded", function () {
        myself.eventHandler.raise('sendsafely.entropy.ready');
        callback(urlSafeBase64(sjcl.codec.base64.fromBits(sjcl.random.randomWords(8,6))));
      });
      sjcl.random.addEventListener("progress", function(evt) {
        var entropyPercent = 0;
        if(evt != undefined && evt != 1 && !isNaN(evt)) {
          entropyPercent = (evt*100);
          myself.eventHandler.raise('sendsafely.entropy.progress', {entropy: entropyPercent});
        }
      });
    }
    else {
      callback(urlSafeBase64(sjcl.codec.base64.fromBits(sjcl.random.randomWords(8,6))));
    }
  }

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
    var useBlinding = sjcl.random.isReady(6) !== 0;
    myself.eventHandler.raise('sendsafely.entropy.ready', {});
    decryptKeycode(privateKey, keyCode, useBlinding, callback);
  }

  function decryptKeycode(privateKey, keyCode, useBlinding, callback) {
    var randomness = [];
    if(useBlinding) {
      randomness = sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(512,6));
    }

	var messageListener = function (e) {
	  var data = e.data;
      switch (data.cmd)
      {
        case 'keycode_decrypted':
          if(callback !== undefined) {
            callback(data.decryptedKeycode);
          }
          break;
        case 'randBuff':
          randomness = sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(data.bytes,6));
          window.postMessage({'cmd': 'randBuff', 'randomness': randomness},'*');
          break;
      }		
	}

	if(eventListenerTracker.hasOwnProperty('DecryptKeycode')) {
		window.removeEventListener('message', eventListenerTracker.DecryptKeycode, true);
	}
	
	eventListenerTracker.DecryptKeycode = messageListener;
	window.addEventListener('message', messageListener, true);

    window.postMessage({'cmd': 'decrypt_keycode', 'privateKey': privateKey, 'keyCode': keyCode, 'randomness': randomness, useBlinding: useBlinding},'*');
  }
}
function DecryptMessage (eventHandler) {
  
  var myself = this;

  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  this.execute = function (ciphertext, packageId, keyCode, serverSecret, callback) {
    var workerParameters =
    {'cmd': 'decrypt_message',
      'serverSecret': urlSafeBase64(serverSecret),
      'keycode': urlSafeBase64(keyCode),
      'salt': sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(2,6)),
      'iv': sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(16,6)),
      'message': ciphertext
    };

    //myself.messageWorker = new Worker(myself.serverWorkerURI);

    var callbackFunction = function(e)
    {
      var data = e.data;
      switch (data.cmd)
      {
        case 'fatal':
          //eventHandler.raise('sendsafely.error', {'error': data.msg, 'data': data.debug});
          eventHandler.raise('MESSAGE_DECRYPT_ERROR', data.msg);
          break;
        case 'done':
          if(callback != undefined) {
            callback(data.data);
          }
          break;
        case 'randBuff':
          window.postMessage({'cmd': 'randBuff', 'iv': sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(64,6))},'*');
          break;
      }
    };

    if(eventListenerTracker.hasOwnProperty('DecryptMessage')) {
    	window.removeEventListener('message', eventListenerTracker.DecryptMessage, true);
    }
	
	eventListenerTracker.DecryptMessage = callbackFunction;
    window.addEventListener('message', callbackFunction, true);
 
    window.postMessage(workerParameters,'*');
  }
}
function DeleteContactGroupFromPackage (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/group/{groupId}/", "HTTPMethod" : "DELETE", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'contact.group.delete.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;
  this.execute = function (packageId, groupId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{groupId}", groupId);
    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {
      finished(res);
    }, myself.customErrorEvent);
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
function DeleteGroup (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/group/{groupId}/", "HTTPMethod" : "DELETE", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'group.delete.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (groupId, async, finished) {
    finished = (finished === undefined) ? function(){} : finished;

    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{groupId}", groupId);
    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {
      finished(res);
    }, myself.customErrorEvent);
  }
}
function DeleteGroupMember (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/group/{groupId}/{userId}/", "HTTPMethod" : "DELETE", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'group.member.delete.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (groupId, userId, async, finished) {
    finished = (finished === undefined) ? function(){} : finished;

    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{groupId}", groupId);
    endpoint.url = endpoint.url.replace("{userId}", userId);
    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function (res) {
      finished(res);
    }, myself.customErrorEvent);
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
function DownloadAndDecryptFile (eventHandler, request, serverWorkerURI) {
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
  this.workerPool = new WorkerPool(serverWorkerURI, workerEventListener);
  this.fileId;
  this.fileName;
  this.fileIndexes = [];
  this.fileWriteStream;

  myself.eventHandler.bind(myself.PENDING_DOWNLOADS_CHANGED_EVENT, startDownloads);
  myself.eventHandler.bind(myself.PENDING_DECRYPTION_CHANGED_EVENT, startDecrypting);
  

  var messageListener = function(event) {
	var data = event.data;
    switch (data.cmd)
    {
      case 'decrypted':
        partDecrypted(data.fileId, data.part, data.data);
        break;
    }
  }

  if(eventListenerTracker.hasOwnProperty('DownloadAndDecryptFile')) {
	window.removeEventListener('message', eventListenerTracker.DownloadAndDecryptFile, true);
  }
		
  eventListenerTracker.DownloadAndDecryptFile = messageListener;		
  window.addEventListener('message', messageListener, true);
  
  function getDownloadPathFromConfig(config, file) {
    var downloadPath = "";
          
    if (config.path && config.fileName) {
      downloadPath = path.join(config.path, config.fileName);
    } else if (config.path) {
      downloadPath = path.join(config.path, file.fileName);
    } else if (config.fileName) {
      downloadPath = config.fileName;
    }
    
    return downloadPath;
  }
  
  function createFileWriteStreamIfInConfig(config, file) {
    if (config && (config.path || config.fileName)) {
      var downloadPath = getDownloadPathFromConfig(config, file);
      
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
      config.storage.fileParts = file.parts;

      var checksum = createChecksum(keyCode, pkg.packageCode);
      if(file.parts == 0) {
    	config.fileParts = 1;  
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
        config.storage.fileParts = file.fileParts;

        var checksum = createChecksum(keyCode, pkg.packageCode);

        if(file.fileKey != "" && file.fileKey != undefined){
          var messageDecryptor = new DecryptMessage(myself.eventHandler);
          messageDecryptor.serverWorkerURI = myself.workerPool.serverWorkerURI;
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
	var requestData = JSON.stringify(requestBody);
    var downloadedBytes = 0;    
    var options = myself.request.getHTTPSOptionForFileDownload(endpoint, requestData, myself.ec2Proxy);
    var downloadedData = [];

    if (true || ! myself.ec2Proxy) {
    	options.headers = {};
    	requestData = null;
    } else {
		options.method = 'POST'
    }
    
    var req = https.request(options, function(res) {
    
        res.on('data', function(chunk) {
        	downloadedData.push(chunk);
        	if(isValidResponse(res)) {
        		var bytesSinceLastUpdate = chunk.length;
                downloadedBytes += chunk.length;
                myself.eventHandler.raise(progressEvent, bytesSinceLastUpdate);             
        	}         
        });
        res.on('end', function() {
        	downloadedData = Buffer.concat(downloadedData);
        	if(isValidResponse(res)) {
                var ab = new ArrayBuffer(downloadedData.length);
                var formattedResponse = new Uint8Array(ab);
                for (var i = 0; i < downloadedData.length; ++i) {
                	formattedResponse[i] = downloadedData[i];
                }
                myself.eventHandler.raise(finishedEvent, formattedResponse);
        	} else {
        		// parse error from server
        		downloadedData = JSON.parse(downloadedData.toString());
        		raiseDownloadError(res);
        	}
        });
        
    }).on('error', function(err) {
    	req.end();
        raiseDownloadError(err);   	
    });
        
    if(myself.ec2Proxy) {
    	req.write(requestData);
    }
    
    req.end();
    
    function isValidResponse(res) {
    	return res.statusCode === 200 && !res.headers['content-type'].includes("application/json");  		
    }
    
    function raiseDownloadError(res) {
    	var debugStr = 'Response Code: ' + res.statusCode + ', Response Text: ' + res.statusMessage + ', Error: ' + (res.message || downloadedData.response);
        console.log(debugStr);
    	myself.eventHandler.raiseError("FAIL", "Server returned an error: " + debugStr);
    }
  };

  function parseDownloadErrorResponse(response) {
    var json = "";
    try {
      // Convert to ArrayBufferView
      var formattedResponse = new Uint8Array(response);
      for(var i = 0; i<formattedResponse.length; i++) {
        json += String.fromCharCode(formattedResponse[i]);
      }
    } catch(err) {
      json = err.message;
    }

    return json;
  }

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

  function workerEventListener(id, event) {
    var data = event.data;
    switch (data.cmd)
    {
      case 'decrypted':
        partDecrypted(data.fileId, data.part, data.data);
        myself.workerPool.markAsAvailable(data.workerId);
        break;
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
    //var worker = myself.workerPool.getWorker();
    var randomness = sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(16,6));
    window.postMessage({'cmd': 'decrypt_file',
      'decryptionKey': fileObj.fileKey||generateDecryptionKey(fileObj.serverSecret, fileObj.keycode),
      'randomness': randomness,
      'fileId': fileObj.fileId,
      'file': fileObj.encryptedData,
      'part': fileObj.part,
      //'workerId': worker.id,
      'dataType': fileObj.config.storage.getFileFormat()
    },'*');
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

  function createEndpoint(fileObject)
  {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", fileObject.packageId);
    endpoint.url = endpoint.url.replace("{fileId}", fileObject.fileId);
    return endpoint;
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
    keyCode = sjcl.codec.utf8String.toBits(urlSafeBase64(keyCode));
    packageCode = sjcl.codec.utf8String.toBits(urlSafeBase64(packageCode));

    return sjcl.codec.hex.fromBits(sjcl.misc.pbkdf2(keyCode, packageCode, 1024, 256));
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
  this.workerPool = [];

  this.addFiles = function (packageId, keyCode, serverSecret, files, uploadType, statusCb, finished) {
    myself.getFileIDs(packageId, undefined, keyCode, serverSecret, files, uploadType, statusCb, finished);
  };

  this.addFilesToDirectory = function (packageId, directoryId, keyCode, serverSecret, files, uploadType, statusCb, finished) {
    myself.getFileIDs(packageId, directoryId, keyCode, serverSecret, files, uploadType, statusCb, finished);
  };

  this.getFileIDs = function (packageId, directoryId, keyCode, serverSecret, files, uploadType, statusCb, finished) {
    myself.addEncryptionKey(packageId, serverSecret, keyCode);
    function handleResponse(index, parts, files) {
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
            myself.encrypting.push({"packageId": packageId, "directoryId": directoryId, "file":files[index], "parts": parts, "part": 1, "name": filename, "fileStart": 0, "id": resp.message});

            var type= (directoryId === undefined) ? undefined : "directory";
            //TODO: REVIEW
            var event = {'fileId': files[index].id==undefined?resp.message:files[index].id, 'filePart':files[index].part, "parts":parts, 'name': filename, 'size': files[index].size, 'packageId': packageId, 'type': type};
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

    for (var i = files.length - 1; i >= 0; i--) {
      var parts;
      if(files[i].size > (myself.SEGMENT_SIZE/4)) {
        parts = 1 + Math.ceil((files[i].size-(myself.SEGMENT_SIZE/4))/myself.SEGMENT_SIZE);
      } else {
        parts = 1;
      }

      handleResponse(i, parts, files);
    }
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
      while(myself.segmentsCurrentlyEncrypting < myself.MAX_CONCURRENT_ENCRYPTIONS) {
        if(currentFile.part === 1){
          var fileObj = {};
          var fileSegment = _slice(currentFile.file.data, 0, Math.min((myself.SEGMENT_SIZE/4), currentFile.file.size));
          fileObj.fileSegment = fileSegment;
          fileObj.id = currentFile.id;
          fileObj.part = currentFile.part;
          fileObj.parts = currentFile.parts;
          fileObj.name = currentFile.name;
          fileObj.directoryId = currentFile.directoryId;

          myself.encrypting[0].fileStart = Math.min(myself.SEGMENT_SIZE/4, myself.encrypting[0].file.size);
        }
        else if(currentFile.part <= currentFile.parts){
          var fileObj = {};
          var fileSegment = _slice(currentFile.file.data, currentFile.fileStart, Math.min(currentFile.fileStart+(myself.SEGMENT_SIZE), currentFile.file.size));
          fileObj.fileSegment = fileSegment;
          fileObj.id = currentFile.id;
          fileObj.part = currentFile.part;
          fileObj.parts = currentFile.parts;
          fileObj.name = currentFile.name;
          //TODO: Added during merge...confirm this
          fileObj.directoryId = currentFile.directoryId;

          myself.encrypting[0].fileStart = Math.min(myself.encrypting[0].fileStart+(myself.SEGMENT_SIZE), myself.encrypting[0].file.size);
        }
        else{
          //Finished last
          myself.encrypting.shift();
          return myself.uploadPart(statusCb, finished);
        }

        myself.encrypting[0].part++;

        myself.segmentsCurrentlyEncrypting++;

        var packageId = currentFile.packageId;
        var directoryId = currentFile.directoryId;
        myself.sendFileToWorker(fileObj, packageId, directoryId, currentFile.file.size, statusCb, finished, function(){
          myself.uploadPart(statusCb, finished);
        });
      }
    }
  };

  this.loadBlobFromUrl = function (packageId, directoryId, statusCb, finished, file, parts) {
    var xhr = new XMLHttpRequest();
    var url = file.url;

    xhr.open('GET', url, true);
    xhr.responseType = 'arraybuffer';

    xhr.onload = function(e) {
      if (this.status === 200) {
        // Convert to ArrayBufferView
        var formattedResponse = new Uint8Array(this.response);

        var blob = new Blob([formattedResponse], {type: 'application/octet-stream'});
        blob.part = file.part;
        blob.id = file.id;
        blob.name = file.name;

        var filename = (file.name === undefined) ? "Unknown File" : file.name;

        //Add to encrypting Queue
        myself.encrypting.push({"packageId": packageId, "directoryId": directoryId, "file":blob, "name": filename, "parts": parts, "part": 1, "fileStart": 0, "id": blob.id});

        var event = {'fileId': file.id, 'name': file.name, 'size': file.size, 'packageId': packageId};
        myself.eventHandler.raise("sendsafely.files.attached", event);
        statusCb("ATTACH", file);

        if(myself.encrypting.length === 1){
          //Start Uploading files
          myself.uploadPart(statusCb, finished);
        }
      } else {
        myself.eventHandler.raiseError('BLOB_ERROR', 'Failed to load blob');
      }
    };

    xhr.send();
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

    var fileId = messageData.fileId;
    var filePart = messageData.filePart;

    var multipart = {};
    multipart["fileId"] = fileId;
    multipart["uploadType"] = "NODE_API";
    multipart["filePart"] = filePart;
    var multiPartForm = createMultiPartForm(boundary, JSON.stringify(multipart), encryptedFile.file);
    var url = requestType.url;
    var method = "POST"
    var contentLength = Buffer.from(multiPartForm.buffer).length;
    	
    if (!myself.ec2Proxy) {
      url = myself.uploadUrls[fileId][filePart];
      method = "PUT";
      contentLength = Buffer.from(encryptedFile.file).length;
    }
    
    var responseData = "";
    
    var options = myself.request.getHTTPSOptionForFileUpload(url, method, JSON.stringify(messageData), boundary, myself.ec2Proxy);	
    options.headers['Content-Length'] = contentLength;
    
    var req = https.request(options, function(res) {
      
        res.on('data', function(chunk) {
        	responseData += chunk;
            uploadCb({loaded: responseData.length});
        });
        res.on('end', function() {
	        uploadCb({loaded: contentLength});
	        var data = res;
            var response = {response:"SERVER_ERROR", message: "A server error has occurred, please try again."};

            if(myself.ec2Proxy && responseData !== undefined){           	
              try {            
                response = JSON.parse(responseData.toString());
              } catch (e) {
              }
            }
            if(myself.ec2Proxy && response.response == "LIMIT_EXCEEDED")
            {
              myself.eventHandler.raise(myself.LIMIT_EXCEEDED_EVENT, {error: response.message});
            }
            else if(myself.ec2Proxy && response.response === "AUTHENTICATION_FAILED"){
              myself.removeFileFromQueue(messageData.fileId);
              myself.eventHandler.raise(myself.UPLOAD_ERROR_EVENT, {error: 'AUTHENTICATION_FAILED', message: response.message});
            }
            else if( (myself.ec2Proxy && response.response == "SUCCESS") || (! myself.ec2Proxy && res.statusCode == 200) ) {
              //response.fileId = response.message;
              var discard = myself.uploading.shift();
              discard = null;

              myself.eventHandler.unbind(myself.UPLOAD_ABORT_EVENT, eventId);
              if(encryptedFile.part == encryptedFile.parts)
              {
                if (! myself.ec2Proxy)
                {
                  var counter = 0;
                  myself.markFileComplete(packageId, fileId, a_sync, function() { done_callback(packageId, fileId, filesize, filename); }, function() { myself.eventHandler.raise(myself.SERVER_ERROR_EVENT, {error: "FILE_INCOMPLETE", message: "Your file did not upload completely. Please refresh and try again."});}, counter);
                }
                else
                {
                  done_callback(packageId, fileId, filesize, filename);
                }
              }
        	  if(myself.uploading.length != 0){
                  myself.nextUploadFile(done_callback, progress_callback);
              }
            }
            else
            {
              if(myself.markedAsDeleted[messageData.fileId] == undefined) {
                if(retryIterator == undefined) {retryIterator = 1;}
                if(retryIterator < 5) {
                  myself.SendPart(requestType, messageData, boundary, filesize, encryptedFile, filename, uploadCb, a_sync, packageId, done_callback, progress_callback, retryIterator+1)
                } else {
                  myself.removeFileFromQueue(messageData.fileId, messageData.fileId);
                  var error = res.statusCode;
                  var message = res.statusMessage;
                  if(myself.ec2Proxy) {
                	  error = response.response;
                	  message = response.message;
                  }
                  myself.eventHandler.raise(myself.UPLOAD_ERROR_EVENT, {error: error, message: message});
                }
              }
            }
        });
        
    }).on('error', function(err) {
    	  if(retryIterator == undefined) {retryIterator = 1;}
	      if(retryIterator < 5) {
	        setTimeout(function() {
	          myself.SendPart(requestType, messageData, boundary, filesize, encryptedFile, filename, uploadCb, a_sync, packageId, done_callback, progress_callback, retryIterator+1);
	        }, retryIterator*1000);
	      } else {
	        //If we fail 5 times and are not using the proxy, flip the proxy switch and try again
	        if (! myself.ec2Proxy )
	        {
	          myself.ec2Proxy = true;
	          retryIterator = 0;
	          setTimeout(function() {
	            myself.SendPart(requestType, messageData, boundary, filesize, encryptedFile, filename, uploadCb, a_sync, packageId, done_callback, progress_callback, retryIterator+1);
	          }, retryIterator*1000);
	        }
	        else
	        {
	        	myself.removeFileFromQueue(messageData.fileId, messageData.fileId);
	            myself.eventHandler.raise(myself.UPLOAD_ERROR_EVENT, {error: err.statusMessage, message: "A server error occurred - Please try again."});
	        }
	      }  
    });
    
    if (myself.ec2Proxy) {
      req.write(Buffer.from(multiPartForm.buffer));
    } else {
      req.write(Buffer.from(encryptedFile.file));
    }
    req.end();
      
    // Add event listener so we can abort the upload if we have to.
    var eventId = myself.eventHandler.bind(myself.UPLOAD_ABORT_EVENT, function(data) {
      if(data.fileId == messageData.fileId) {
        req.end();
      }
    });
  }

  this.abort = function(fileId) {
    // Remove from queues.
    myself.removeFileFromQueue(fileId);
    myself.eventHandler.raise(myself.UPLOAD_ABORT_EVENT, {'fileId': fileId});
  };

  this.sendFileToWorker = function (fileObject, packageId, directoryId, fileSize, statusCb, done, nextCb) {
    function postStartMessage() {
      var randomness = sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(16,6));

      var key = myself.getEncryptionKey(packageId);
      window.postMessage({'cmd': 'start',
        'serverSecret': urlSafeBase64(key.serverSecret),
        'packageId': packageId,
        'directoryId': directoryId,
        'fileId': fileObject.id,
        'keycode': urlSafeBase64(key.keyCode),
        'iv': randomness,
        'file': fileObject.fileSegment,
        'fileSize': fileObject.size,
        'name': fileObject.name,
        'totalFileSize': fileSize,
        'filePart': fileObject.part,
        'parts': fileObject.parts,
        'SEGMENT_SIZE': myself.SEGMENT_SIZE,
        //'id': worker.id,
        'boundary': '------JSAPIFormDataBoundary' + Math.random().toString(36)
      },'*');
    }

    function sendWorkerFile() {
      if(sjcl.random.isReady(6) == 0)
      {
        sjcl.random.addEventListener("seeded", function () {
          myself.eventHandler.raise('sendsafely.entropy.ready');
          postStartMessage();
        });
        sjcl.random.addEventListener("progress", function(evt) {
          var entropyPercent = 0;
          if(evt != undefined && evt != 1 && !isNaN(evt)) {
            entropyPercent = (evt*100);
            myself.eventHandler.raise('sendsafely.entropy.progress', {entropy: entropyPercent});
          } else {
            myself.eventHandler.raise('sendsafely.entropy.ready');
          }
        });
      }
      else {
        postStartMessage();
      }
    }

    var worker = myself.getWorker(statusCb, nextCb, done);
    sendWorkerFile();
  };

  this.getWorker = function(statusCb, nextCb, done) {
    for(var i = 0; i<myself.workerPool.length; i++) {
      if(myself.workerPool[i].available) {
        myself.workerPool[i].available = false;
        return myself.workerPool[i];
      }
    }
    
	
    var worker;
	/*
    if(typeof uploadWorkerURL !== 'undefined') {
      worker = new Worker(uploadWorkerURL);
    } else {
      worker = new Worker(myself.serverWorkerURI);
    }
	*/
    //myself.workerPool.push({'available': false, 'id': myself.workerPool.length, 'worker': worker});
    myself.addWorkerEventListener(worker, statusCb, nextCb, done);
    return myself.workerPool[myself.workerPool.length-1];
  };

  this.markWorkerAsAvailable = function(id) {
    for(var i = 0; i<myself.workerPool.length; i++) {
      if(myself.workerPool[i].id == id) {
        myself.workerPool[i].available = true;
        return;
      }
    }
  };

  this.addWorkerEventListener = function (worker, statusCb, nextCb, done) {
    
    function moveToNextWhenReady() {
      if (myself.uploading.length > 5)
      {
        //console.log("Hold...");
        var timeoutID = window.setTimeout(function()
        {
          moveToNextWhenReady()
        }, 3000);
      }
      else
      {
        //console.log("Next!");
        nextCb();
      }
	
    }
    
	var messageListener = function(e) {
      var data = e.data;
      switch (data.cmd)
      {
        case 'state':
          //file = {name:, size:, id}
          var htmlsafename = $('<div/>').text(data.fileName).html();
          statusCb(data.state, {id: data.fileId, name:htmlsafename, part:data.part, size: data.filesize});
          break;
        case 'fatal':
          myself.eventHandler.raise(myself.UPLOAD_ERROR_EVENT, {error: data.msg, message: data.debug});
          break;
        case 'randBuff':
          window.postMessage({'cmd': 'randBuff', 'iv': sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(64,6))},'*');
          break;
        case 'upload':
          myself.segmentsCurrentlyEncrypting--;
          statusCb("FILE_UPLOADING", {id: data.fileId, part:data.part});

          //Start Encrypting Next Part or File
          moveToNextWhenReady();

          var messageData = {};
          messageData["fileId"] = data.fileId;
          messageData["uploadType"] = "NODE_API";
          messageData["filePart"] = data.part;

          // Check if the part is marked for deletion before actually pushing it.
          if(myself.markedAsDeleted[data.fileId] != undefined) {
            // Marked as deleted, do nothing
          } else {
            myself.uploading.push({"packageId": data.packageId, "boundary": data.boundary, "name": data.name, "messageData": messageData, "file":data, "in_progressCb": function(jqXHR){
              myself.sendProgress(myself.PROGRESS_EVENT, data.fileId, myself.calculateProgress(data.fileId, data.part, jqXHR.loaded));
            }});
          }

          if(myself.uploading.length == 1){
            myself.nextUploadFile(done);
          }

          break;
      }
    
	}
	
	if(eventListenerTracker.hasOwnProperty('EncryptAndUploadFile')) {
		window.removeEventListener('message', eventListenerTracker.EncryptAndUploadFile, true);
	}
	
	eventListenerTracker.EncryptAndUploadFile = messageListener;
	window.addEventListener('message', messageListener , true);
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
  this.totalNumber = 0;
  this.notifyRecipients = true;

  this.callback = undefined;

  var myself = this;

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
    myself.responseParser.processAjaxData(response, function (res) {
      myself.addedKeycodes++;

      if(myself.totalNumber == myself.addedKeycodes && myself.callback !== undefined) {
        myself.callback();
      }
    }, myself.customErrorEvent);
  }

  function encryptKeycode(publicKey, keyCode, callback) {
    var handler = new EncryptKeycode(myself.eventHandler);
    handler.serverWorkerURI = myself.serverWorkerURI;
    handler.execute(publicKey, keyCode, callback);
  }

  function decryptAndEncryptKeycode(privateKey, publicKey, keyCode, callback) {

    var useBlinding = true;

    // Create the worker.
    //var worker = new Worker(myself.serverWorkerURI);

    window.addEventListener('message', function(e)
    {
      var data = e.data;
      switch (data.cmd)
      {
        case 'keycode_encrypted':
          if(callback !== undefined) {	
            callback(publicKey.id, data.encryptedKeyCode);
          }
          break;
        case 'keycode_decrypted':
          var randomness = sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(1024,6));
          window.postMessage({'cmd': 'encrypt_keycode', 'publicKey': publicKey.key, 'keyCode': data.decryptedKeycode, 'randomness': randomness},'*');
          break;
      }
    }, false);

    var randomness = sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(512,6));
    window.postMessage({'cmd': 'decrypt_keycode', 'privateKey': privateKey, 'keyCode': keyCode, 'randomness': randomness, useBlinding: useBlinding},'*');
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

  this.execute = function (publicKey, keyCode, callback) {
    seedRandomness(publicKey, keyCode, callback);
  };

  function startWorker(publicKey, keyCode, callback)
  {
    var randomness = sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(256,6));
 
    var processMessage = function(e) {
    	 var data = e.data;
         switch (data.cmd)
         {
           case 'keycode_encrypted':
             if(callback !== undefined) {
               window.removeEventListener('message', processMessage,false);
               callback(publicKey.id, data.encryptedKeyCode);
             }
             break;
           case 'randBuff':
             randomness = sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(data.bytes,6));
             window.postMessage({'cmd': 'randBuff', 'randomness': randomness},'*');
             break;
         }
    }
    window.addEventListener('message', processMessage, false);
    window.postMessage({'cmd': 'encrypt_keycode', 'publicKey': publicKey.key, 'keyCode': keyCode, 'randomness': randomness},'*');
  }

  function seedRandomness(publicKey, keyCode, callback)
  {
    if(sjcl.random.isReady(6) == 0)
    {
      sjcl.random.addEventListener("seeded", function () {
        startWorker(publicKey, keyCode, callback);
      });
      sjcl.random.addEventListener("progress", function(evt) {
        var entropyPercent = 0;
        if(evt != undefined && evt != 1 && !isNaN(evt)) {
          entropyPercent = (evt*100);
          myself.eventHandler.raise('sendsafely.entropy.progress', {entropy: entropyPercent});
        } else {
          myself.eventHandler.raise('sendsafely.entropy.ready', {});
        }
      });
    }
    else {
      myself.eventHandler.raise('sendsafely.entropy.ready', {});
      startWorker(publicKey, keyCode, callback);
    }
  }
}
function EncryptMessage (eventHandler) {
  
  var myself = this;

  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  this.execute = function (message, packageId, keyCode, serverSecret, callback) {
    function postStartMessage() {
      var randomness = sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(16,6));

      message = (message === undefined) ? "" : message;
      var workerParameters =
      {'cmd': 'encrypt_message',
        'serverSecret': urlSafeBase64(serverSecret),
        'keycode': urlSafeBase64(keyCode),
        'iv': randomness,
        'message': message
      };
      //myself.messageWorker.postMessage(workerParameters);
	  window.postMessage(workerParameters,'*');
    }

    function startWorker() {
      if(sjcl.random.isReady(6) == 0)
      {
        sjcl.random.addEventListener("seeded", function () {
          myself.eventHandler.raise('sendsafely.entropy.ready');
          postStartMessage();
        });
        sjcl.random.addEventListener("progress", function(evt) {
          var entropyPercent = 0;
          if(evt != undefined && evt != 1 && !isNaN(evt)) {
            entropyPercent = (evt*100);
            myself.eventHandler.raise('sendsafely.entropy.progress', {entropy: entropyPercent});
          } else {
            myself.eventHandler.raise('sendsafely.entropy.ready');
          }
        });
      }
      else {
        postStartMessage();
      }
    }
    /*
    myself.messageWorker = undefined;
    if(typeof uploadWorkerURL !== 'undefined') {
      myself.messageWorker = new Worker(uploadWorkerURL);
    } else {
      myself.messageWorker = new Worker(myself.serverWorkerURI);
    }
    */

    var callbackFunction = function(e)
    {
      var data = e.data;
      switch (data.cmd)
      {
        case 'fatal':
          eventHandler.raiseError('MESSAGE_ENCRYPT_ERROR', data.msg);
          break;
        case 'debug':
          break;
        case 'done':
          if(callback != undefined) {
            window.removeEventListener('message', callbackFunction, false);
            callback(data.data);
          }
          break;
        case 'randBuff':
          window.postMessage({'cmd': 'randBuff', 'iv': sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(64,6))},'*');
          break;
      }
    };

    //myself.messageWorker.addEventListener('message', callbackFunction, false);
    window.addEventListener('message', callbackFunction, false);

    startWorker();
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
    keyCode = sjcl.codec.utf8String.toBits(urlSafeBase64(keyCode));
    packageCode = sjcl.codec.utf8String.toBits(urlSafeBase64(packageCode));

    return sjcl.codec.hex.fromBits(sjcl.misc.pbkdf2(keyCode, packageCode, 1024, 256));
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
function GenerateKey (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/generate-key/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'key.generation.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (email, password, keyDescription, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);

    var response = myself.request.sendRequest(endpoint, {email: email, password: password, keyDescription: keyDescription}, true);
    myself.responseParser.processAjaxData(response, function (res) {

      var data = {};
      data.email = res.email;
      data.apiKey = res.apiKey;
      data.apiSecret = res.apiSecret;

      finished(data);
    }, myself.customErrorEvent);
  }
}
function GenerateKey2FA (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/generate-key/{token}/", "HTTPMethod" : "POST", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'key.generation.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;
  this.execute = function (accessToken, smsCode, keyDescription, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{token}", accessToken);
    var response = myself.request.sendRequest(endpoint, {smsCode: smsCode, keyDescription: keyDescription}, true);
    myself.responseParser.processAjaxData(response, function (res) {

      var data = {};
      data.email = res.email;
      data.apiKey = res.apiKey;
      data.apiSecret = res.apiSecret;

      finished(data);
    }, myself.customErrorEvent);
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
    if(sjcl.random.isReady(6) == 0)
    {
      sjcl.random.addEventListener("seeded", function () {
        startWorker(callback);
      });
      sjcl.random.addEventListener("progress", function(evt) {
        var entropyPercent = 0;
        if(evt != undefined && evt != 1 && !isNaN(evt)) {
          entropyPercent = (evt*100);
          myself.eventHandler.raise('sendsafely.entropy.progress', {entropy: entropyPercent});
        } else {
          myself.eventHandler.raise('sendsafely.entropy.ready', {});
        }
      });
    }
    else {
      myself.eventHandler.raise('sendsafely.entropy.ready', {});
      startWorker(callback);
    }
  }

  function startWorker(callback) {
    var randomness = sjcl.codec.utf8String.fromBits(sjcl.random.randomWords(512,6));

    // Create the worker.
    //var worker = new Worker(myself.serverWorkerURI);

    window.addEventListener('message', function(e)
    {
      var data = e.data;
      switch (data.cmd)
      {
        case 'key_generated':
          if(callback !== undefined) {
            callback(data.privateKey, data.publicKey);
          }
          break;
        case "progress":
          myself.eventHandler.raise(myself.PROGRESS_EVENT, {progress: data.progress, total: data.total});
          break;
        case 'debug':
          break;
      }
    }, false);
    window.postMessage({'cmd': 'generate_key', 'bits': 2048, 'userStr': buildNameStr(), 'randomness': randomness},'*');
  }

  function buildNameStr() {
    return {name:myself.NAME, email:myself.EMAIL};
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
      handler.serverWorkerURI = myself.serverWorkerURI;
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
        handler.serverWorkerURI = myself.serverWorkerURI;
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
function GetPublicKey (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/public-key/{publicKeyId}/", "HTTPMethod" : "GET", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'publickey.get.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (publicKeyId, async, finished) {
    if(publicKeyId === undefined) {
      throw new Error("Public Key ID can not be undefined");
    } else {
      var endpoint = myself.request.extend({}, myself.endpoint);
      endpoint.url = endpoint.url.replace("{publicKeyId}", publicKeyId);
      var response = myself.request.sendRequest(endpoint, null, async);
      myself.responseParser.processAjaxData(response, function (res) {
        var data = {};
        data.id = res.id;
        data.publicKey = res.publicKey;
        finished(data);
      }, myself.customErrorEvent);
    }
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
function OAuthRegistration (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/generate-key/oauth/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'registration.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (accessToken, keyDescription, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    var response = myself.request.sendRequest(endpoint, {keyDescription: keyDescription, pinCode: accessToken}, true);
    myself.responseParser.processAjaxData(response, function (res) {

      var data = {};
      data.email = res.email;
      data.apiKey = res.apiKey;
      data.apiSecret = res.apiSecret;

      finished(data);
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
function RemoveContactGroup (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/package/{packageId}/group/{groupId}/", "HTTPMethod" : "DELETE", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);
  this.customErrorEvent = 'group.remove.failed';

  var myself = this;

  this.execute = function (packageId, groupId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{groupId}", groupId);

    var response = myself.request.sendRequest(endpoint, null, async);
    myself.responseParser.processAjaxData(response, function(data) {
      finished(data);
    }, myself.customErrorEvent);
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
  this.uploadAPI = 'NODE_API';
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
function SendFeedback (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/feedback/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'send.feedback.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (message, stacktrace, async, callback) {
    var endpoint = myself.request.extend({}, myself.endpoint);

    var requestData = buildRequestData(message, stacktrace);
    var response = myself.request.sendRequest(endpoint, requestData, async);
    myself.responseParser.processAjaxData(response, function(res) {
      if(callback) {
        callback();
      }
    });
  };

  function buildRequestData(message, stacktrace) {
    var postData = {};
    postData.message = message;
    postData.stacktrace = stacktrace;
    return postData;
  }
}
function StartRegistration (eventHandler, request) {
  this.request = request;
  this.endpoint = { "url": "/register/", "HTTPMethod" : "PUT", "mimetype": "application/json"};
  this.eventHandler = eventHandler;
  this.customErrorEvent = 'registration.failed';
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (email, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    var response = myself.request.sendRequest(endpoint, {'email': email}, true);
    myself.responseParser.processAjaxData(response, function (res) {
      finished();
    }, myself.customErrorEvent);
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

      if(sjcl.random.isReady(8) == 0)
      {
        sjcl.random.addEventListener("seeded", function () {
          encryptKeycodes(res, privateKey, callback);
        });
        sjcl.random.addEventListener("progress", function(evt) {
          var entropyPercent = 0;
          if(evt != undefined && evt != 1 && !isNaN(evt)) {
            entropyPercent = (evt*100);
            myself.eventHandler.raise('sendsafely.entropy.progress', {entropy: entropyPercent});
          } else {
            myself.eventHandler.raise('sendsafely.entropy.ready', {});
          }
        });
      }
      else {
        myself.eventHandler.raise('sendsafely.entropy.ready', {});
        encryptKeycodes(res, privateKey, callback);
      }
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
      handler.serverWorkerURI = myself.serverWorkerURI;
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
function UpdateFile (eventHandler, request) {
  this.request = request;
  this.endpoint = {
    "url": "/package/{packageId}/directory/{directoryId}/file/{fileId}/",
    "HTTPMethod": "POST",
    "mimetype": "application/json"
  };
  this.eventHandler = eventHandler;
  this.responseParser = new ResponseParser(eventHandler);

  var myself = this;

  this.execute = function (packageId, fileId, directoryId, async, finished) {
    var endpoint = myself.request.extend({}, myself.endpoint);
    endpoint.url = endpoint.url.replace("{packageId}", packageId);
    endpoint.url = endpoint.url.replace("{directoryId}", directoryId);
    endpoint.url = endpoint.url.replace("{fileId}", fileId);

    var response = myself.request.sendRequest(endpoint, null, async);
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

SendSafely.SendSafelyDropzone = function SendSafelyDropzone(url, dropzoneId) {
	const myself = new SendSafely(url, dropzoneId, null);
	myself.notifyRecipients = false;

	myself.setUnconfirmedSender = function(email){
		myself.unconfirmedSender = email;
	}
	
	return myself
};

module.exports = SendSafely;

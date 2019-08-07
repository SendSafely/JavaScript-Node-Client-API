if(typeof window === 'undefined') {
  window = {};
}

window.crypto = {
    getRandomValues: function (buf) {
        if(self.ivCounter + buf > self.iv.size)
        {
            self.send({'cmd': 'randBuff'});
        }
        for(var i = 0; i<buf.length; i++)
        {
            buf[i] = self.iv[self.ivCounter++].charCodeAt();
        }
    }
};

self.ivCounter = 0;
self.log = "";

self.addEventListener('message', function(e) {
	var data = e.data;
	switch (data.cmd) {
		case 'start':
      self.ivCounter = 0;
      self.csrf = data.csrf;
			self.serverSecret = data.serverSecret;
			self.packageId = data.packageId;
      self.directoryId = data.directoryId;
			self.file = data.file;
			self.fileId = data.fileId;
			self.uploadUrl = data.uploadUrl;
			self.keycode = data.keycode;
			self.iv = data.iv;
      self.name = data.name;
			self.browser = data.browser;
			self.uploadedBytes = 0;
			self.SEGMENT_SIZE = data.SEGMENT_SIZE;
			self.filePart = data.filePart;
			self.totalFileSize = data.totalFileSize;
			self.totalParts = data.parts;
      self.id = data.id;
      self.boundary = data.boundary;
			
			// Add file
			self.postMessage({'cmd': 'state', 'fileId': self.fileId, 'name': self.name, 'state': 'ENCRYPTION_STARTED', 'part': self.filePart, 'filesize': self.totalFileSize},'*');
			
			self.start();
      break;

        case 'randBuff':
            self.iv = data.iv;
            self.ivCounter = 0;
            break;

        case 'encrypt_message':

            self.serverSecret = data.serverSecret;
            self.message = data.message;
            self.cspUrl = data.cspUrl;
            self.keycode = data.keycode;
            self.salt = data.salt;
            self.iv = data.iv;
            self.workerId = data.workerId;
            self.debug('Starting to encrypt');
            self.encryptMessage();

            break;
        case 'decrypt_message':

            self.serverSecret = data.serverSecret;
            self.message = data.message;
            self.cspUrl = data.cspUrl;
            self.keycode = data.keycode;
            self.workerId = data.workerId;

            self.salt = data.salt;
            self.iv = data.iv;

            self.decryptMessage();

            break;
        case 'decrypt_file':
            self.ivCounter = 0;
            self.iv = data.randomness;
            self.decryptionKey = data.decryptionKey;
            self.fileId = data.fileId;
            self.file = data.file;
            self.workerId = data.workerId;
            self.part = data.part;
            self.dataType = (data.dataType.constructor === Array) ? data.dataType : [data.dataType];
            self.decryptFile();
            break;
        default:
            ;
    };
}, false);

function decryptFile()
{	
    self.pgpDecryptMessage(self.file, self.decryptionKey, function(decryptedData) {
      self.postMessage({'cmd': 'decrypted', 'fileId': self.fileId, 'data': decryptedData, 'part': self.part},'*');
    });
}

function handleDataConversion(dataType, data) {
    var tmpData = data;
    switch(dataType) {
        case 'ARRAY_BUFFER':
            break;
        case 'BASE64':
            tmpData = base64Encode(data);
            break;
    }

    return tmpData;
}

function decryptMessage() {

    try {
        var decryptionKey = self.serverSecret + self.keycode;
        var decoded = base64Decode(self.message);
        self.pgpDecryptMessage(decoded, decryptionKey, function (decryptedMsg) {
            var plaintextString = typedArrayToUnicodeString(decryptedMsg); // Uint8Array([0x01, 0x01, 0x01])
            self.postMessage({'cmd': 'done', data: plaintextString},'*');
        });
    } catch(e) {
        throw(e);
    }

}

function encryptMessage() {
    var encryptionKey = self.serverSecret + self.keycode;
    self.pgpEncryptMessage(encryptionKey, self.message, 'msg.txt', function (encryptedMsg) {
        var base64EncodedResponse = base64EncodeArray(encryptedMsg);
        self.postMessage({'cmd': 'done', data: base64EncodedResponse},'*');
    });
}

function pgpEncryptMessage(encryptionKey, data, filename, callback)
{
    var options = {
        message: openpgp.message.fromText(data), // input as Uint8Array (or String)
        passwords: [encryptionKey],              // multiple passwords possible
        armor: false                              // don't ASCII armor (for Uint8Array output)
    };
    openpgp.encrypt(options).then(function(ciphertext) {
        //var encrypted =  // get raw encrypted packets as Uint8Array
        callback(ciphertext.message.packets.write());
    });
}

function typedArrayToUnicodeString(ua) {
    var binstr = Array.prototype.map.call(ua, function (ch) {
        return String.fromCharCode(ch);
    }).join('');
    var escstr = binstr.replace(/(.)/g, function (m, p) {
        var code = p.charCodeAt().toString(16).toUpperCase();
        if (code.length < 2) {
            code = '0' + code;
        }
        return '%' + code;
    });
    return decodeURIComponent(escstr);
}

async function pgpDecryptMessage(encryptedString, passphrase, callback)
{
    var options = {
            message: await openpgp.message.read(encryptedString), // input as Uint8Array (or String)
            passwords: [passphrase],              // multiple passwords possible
            format: 'binary'
        };
    

    openpgp.decrypt(options).then(function(plaintext) {
        callback(plaintext.data); // String
        plaintext = undefined; //Free up for GC
    });
}

function base64EncodeArray(t,o)
{
    var b64s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var a, c, n;
    var r = o ? o : [],
        l = 0,
        s = 0;
    var tl = t.length;

    for (n = 0; n < tl; n++) {
        c = t[n];
        if (s === 0) {
            r.push(b64s.charAt((c >> 2) & 63));
            a = (c & 3) << 4;
        } else if (s === 1) {
            r.push(b64s.charAt((a | (c >> 4) & 15)));
            a = (c & 15) << 2;
        } else if (s === 2) {
            r.push(b64s.charAt(a | ((c >> 6) & 3)));
            l += 1;
            if ((l % 60) === 0) {
                //r.push("\n");
            }
            r.push(b64s.charAt(c & 63));
        }
        l += 1;
        if ((l % 60) === 0) {
            //r.push("\n");
        }

        s += 1;
        if (s === 3) {
            s = 0;
        }
    }
    if (s > 0) {
        r.push(b64s.charAt(a));
        l += 1;
        if ((l % 60) === 0) {
            //r.push("\n");
        }
        r.push('=');
        l += 1;
    }
    if (s === 1) {
        if ((l % 60) === 0) {
            //r.push("\n");
        }
        r.push('=');
    }
    if (o)
    {
        return;
    }
    return r.join('');
}

function base64Decode(t)
{
    // This is ripped from inside the OpenPGPJS library for compatibility
    var b64s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var c, n;
    var r = [],
        s = 0,
        a = 0;
    var tl = t.length;

    for (n = 0; n < tl; n++) {
        c = b64s.indexOf(t.charAt(n));
        if (c >= 0) {
            if (s) {
                r.push(a | (c >> (6 - s)) & 255);
            }
            s = (s + 2) & 7;
            a = (c << s) & 255;
        }
    }
    return new Uint8Array(r);
}

function start() {
    debug("Using browser: " + self.browser);

    var encryptionKey = self.serverSecret + self.keycode;
    //var reader = new FileReaderSync();
    var typedArray = new Uint8Array(self.file);

    var options = {
        message: openpgp.message.fromBinary(typedArray), // input as Uint8Array (or String)
        passwords: [encryptionKey],              // multiple passwords possible
        armor: false                              // don't ASCII armor (for Uint8Array output)
    };

    openpgp.encrypt(options).then(function(ciphertext) {
        encrypted = ciphertext.message.packets.write(); // get raw encrypted packets as Uint8Array
        self.postMessage({'cmd': 'state', 'name': self.name, 'fileId': self.fileId, 'state': 'FILE_ENCRYPTED', 'part': self.filePart},'*');
        self.postMessage({'cmd': 'upload', 'packageId': self.packageId, 'id': self.id, 'boundary': self.boundary, 'file': encrypted, 'name': self.name, 'fileId': self.fileId, 'part': self.filePart, 'parts': self.totalParts, 'filesize': self.totalFileSize},'*');
    });
}

function updateProgress(type, number) {
    self.postMessage({'cmd': 'progress', 'type': type, 'fileId': fileId, 'percent': number});
}

function debug(msg) {
    self.log += msg + "\n";
    self.send({'cmd': 'debug', 'msg': msg});
}

function send(content) {
    if(self.postMessage != undefined) {
        self.postMessage(content,'*');
    } else {
        postMessage(content,'*');
    }
}

function fatalError(msg, err) {
    if(err !== undefined) {
        self.debug(err);
        self.debug(err.stack);
    }

    self.postMessage({'cmd': 'fatal', 'msg': msg, 'debug': self.log});
    throw new Error('Aborting execution due to error');
}

self.updateProgres = updateProgress;
self.fatalError = fatalError;
self.debug = debug;
self.start = start;
self.send = send;
self.decryptFile = decryptFile;
self.decryptMessage = decryptMessage;
self.encryptMessage = encryptMessage;
self.base64EncodeArray = base64EncodeArray;
self.base64Decode = base64Decode;
self.pgpEncryptMessage = pgpEncryptMessage;
self.pgpDecryptMessage = pgpDecryptMessage;

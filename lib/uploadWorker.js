try {
    if (window === undefined) {
        window = globalThis;
    }
} catch (err) {
    window = {};
}

self.log = "";

self.addEventListener('message', function(e) {
    var data = e.data;
    switch (data.cmd) {
        case 'start':
            self.csrf = data.csrf;
            self.serverSecret = data.serverSecret;
            self.packageId = data.packageId;
            self.directoryId = data.directoryId;
            self.file = data.file;
            self.fileId = data.fileId;
            self.uploadUrl = data.uploadUrl;
            self.keycode = data.keycode;
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
            self.postMessage({'cmd': 'state', 'fileId': self.fileId, 'name': self.name, 'state': 'ENCRYPTION_STARTED', 'part': self.filePart, 'filesize': self.totalFileSize}, '*');

            self.start();
            break;

        case 'encrypt_message':

            self.serverSecret = data.serverSecret;
            self.message = data.message;
            self.cspUrl = data.cspUrl;
            self.keycode = data.keycode;
            self.salt = data.salt;
            self.workerId = data.workerId;

            self.debug('Starting to encrypt');
            self.encryptMessage();

            break;
        case 'decrypt_message':
            self.debug('Starting to decrypt message');
            self.serverSecret = data.serverSecret;
            self.message = data.message;
            self.cspUrl = data.cspUrl;
            self.keycode = data.keycode;
            self.workerId = data.workerId;

            self.salt = data.salt;

            self.decryptMessage();

            break;
        case 'decrypt_file':
            self.debug('Starting to decrypt file');
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
        self.postMessage({'cmd': 'decrypted', 'fileId': self.fileId, 'workerId': self.workerId, 'data': decryptedData, 'part': self.part}, '*');
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
            self.postMessage({'cmd': 'done', data: plaintextString}, '*');
        });
    } catch(e) {
        throw(e);
    }

}

function encryptMessage() {
    var encryptionKey = self.serverSecret + self.keycode;

    self.pgpEncryptMessage(encryptionKey, self.message, 'msg.txt', function (encryptedMsg) {
        var base64EncodedResponse = base64EncodeArray(encryptedMsg);
        self.postMessage({'cmd': 'done', data: base64EncodedResponse}, '*');
    });
}

function pgpEncryptMessage(encryptionKey, data, filename, callback)
{
    // Create open PGP message
    openpgp.createMessage({ "text": data })
        .then(function (message) {
            var options = {
                message,                         // input as message obj per openPGPv6
                passwords: [encryptionKey],      // multiple passwords possible
                format: 'object',
                config: {
                    s2kIterationCountByte: 96
                }
            };

            // Encrypt open PGP message
            openpgp.encrypt(options)
                .then(function(ciphertext) {
                    callback(ciphertext.packets.write());
                });
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

function pgpDecryptMessage(encryptedString, passphrase, callback)
{
    // Read in string as message
    openpgp.readMessage({"binaryMessage": encryptedString})
        .then(function(message) {
            var options = {
                message,                    // parse encrypted bytes
                passwords: [passphrase],    // decrypt with password
                format: 'binary',
                config: {
                    s2kIterationCountByte: 96
                }
            };

            // And decrypt message with openPGP
            openpgp.decrypt(options)
                .then(function(plaintext) {
                    callback(plaintext.data); // String
                    plaintext = undefined; //Free up for GC
                });
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

    var encryptionKey = self.serverSecret + self.keycode;
    var typedArray = new Uint8Array(self.file);

    openpgp.createMessage({ "binary": typedArray })
        .then(function (message) {
            var options = {
                message,                        // input as messageObj per openPGPv6 update
                passwords: [encryptionKey],     // multiple passwords possible
                format: 'binary',
                config: {
                    s2kIterationCountByte: 96
                }
            };

            // Encrypt file with new message obj in options
            openpgp.encrypt(options)
                .then(function(ciphertext) {
                    self.postMessage({'cmd': 'state', 'name': self.name, 'fileId': self.fileId, 'state': 'FILE_ENCRYPTED', 'part': self.filePart}, '*');
                    self.postMessage({'cmd': 'upload', 'packageId': self.packageId, 'id': self.id, 'boundary': self.boundary, 'file': ciphertext, 'name': self.name, 'fileId': self.fileId, 'part': self.filePart, 'parts': self.totalParts, 'filesize': self.totalFileSize}, '*');
                });
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
        self.postMessage(content, '*');
    } else {
        postMessage(content, '*');
    }
}

function fatalError(msg, err) {
    if(err !== undefined) {
        self.debug(err);
        self.debug(err.stack);
    }

    self.postMessage({'cmd': 'fatal', 'msg': msg, 'debug': self.log, 'workerId': self.workerId});
    throw new Error(msg + ': ' + err.stack);
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
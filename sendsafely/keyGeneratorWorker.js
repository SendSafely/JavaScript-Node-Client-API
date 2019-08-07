if(typeof window === 'undefined') {
  window = {};
}

window.crypto = {
  getRandomValues: function (buf) {
    for(var i = 0; i<buf.length; i++)
    {
      if((self.randomCounter%20) === 0) {
        reportProgress(self.randomCounter);
      }
      if((self.randomCounter % 512) === 0)
      {
        self.send({'cmd': 'randBuff', 'bytes': 64});
      }
      buf[i] = self.randomness[self.randomCounter++].charCodeAt();
    }
  }
};

self.randomCounter = 0;

self.addEventListener('message', async function(e) {
  var data = e.data;
  switch (data.cmd) {
    case 'generate_key':
      debug("Starting to generate key..");
      self.randomCounter = 0;
      self.randomness = data.randomness;

      var bits = data.bits;
      var userStr = data.userStr;

      
      var options = 
      {
	    userIds: [userStr], // multiple user IDs
	    numBits: 2048
	  };
      
      openpgp.generateKey(options).then(function(key) {
        var privateKey = key.privateKeyArmored;
        var publicKey = key.publicKeyArmored;
        
        self.send({'cmd': 'key_generated', 'privateKey': privateKey, 'publicKey': publicKey});
      }, function(err) {
        debug("An Unknown Error Occurred While Generating the key");
        debug(err);
      });
      break;
    case 'convert_key':
      self.randomCounter = 0;
      self.randomness = data.randomness;
      var result = convertRawKey(data.rsaKeys, data.userStr);
      self.send({'cmd': 'key_converted', 'privateKey': result.privateKeyArmored, 'publicKey': result.publicKeyArmored});
      break;
    case 'encrypt_keycode':
      self.randomCounter = 0;
      self.randomness = data.randomness;

      debug(data.publicKey);
      var publicKeys = await openpgp.key.readArmored(data.publicKey);
      
      if(publicKeys.keys.length > 0) {
        var pubKey = publicKeys.keys[0];
        
        var options = {
    		message: openpgp.message.fromText(data.keyCode),
    		publicKeys: [pubKey]
        }

        openpgp.encrypt(options).then(function(encryptedMessage) {
          self.send({'cmd': 'keycode_encrypted', 'encryptedKeyCode': encryptedMessage.data});
        }, function(err) {
          debug('ERROR');
          debug(err);
        });
      }
      break;
    case 'decrypt_keycode':
      self.randomCounter = 0;
      self.randomness = data.randomness;
      var privKeys = await openpgp.key.readArmored(data.privateKey);
      privKey = privKeys.keys[0];
      var message = await openpgp.message.readArmored(data.keyCode);
      
      options = 
      {
        message: message,   // parse armored message
        privateKeys: [privKey]                                 // for decryption
      };
      
      openpgp.decrypt(options).then(function(plaintext) {
        self.send({'cmd': 'keycode_decrypted', 'decryptedKeycode': plaintext.data});
        try {
          throw new Error("Hello");
        } catch(err) {
          sendError(err);
        }
      }, function(err) {
        debug('ERROR');
        debug(err);
        sendError(err);
      });
      break;
    case 'randBuff':
      self.randomness += data.randomness;
    default:
      ;
  };
}, false);

function convertRawKey(rsaKeys, userStr) {

  var secretKey = createSecretKey(rsaKeys.privateKey);
  var secretSubKey = createSecretSubKey(rsaKeys.privateSubKey);

  var key = wrapKeyObject(userStr, secretKey, secretSubKey);

  var result = {};
  result.privateKeyArmored = key.armor();
  result.publicKeyArmored = key.toPublic().armor();

  return result;
}

function wrapKeyObject(userId, secretKeyPacket, secretSubkeyPacket)
{
  packetlist = new window.openpgp.packet.List();

  userIdPacket = new window.openpgp.packet.Userid();
  userIdPacket.read(userId);

  dataToSign = {};
  dataToSign.userid = userIdPacket;
  dataToSign.key = secretKeyPacket;
  signaturePacket = new window.openpgp.packet.Signature();
  signaturePacket.signatureType = window.openpgp.enums.signature.cert_generic;
  signaturePacket.publicKeyAlgorithm = window.openpgp.enums.publicKey.rsa_encrypt_sign;
  signaturePacket.hashAlgorithm = window.openpgp.config.prefer_hash_algorithm;
  signaturePacket.keyFlags = [window.openpgp.enums.keyFlags.certify_keys | window.openpgp.enums.keyFlags.sign_data];
  signaturePacket.preferredSymmetricAlgorithms = [];
  signaturePacket.preferredSymmetricAlgorithms.push(window.openpgp.enums.symmetric.aes256);
  signaturePacket.preferredSymmetricAlgorithms.push(window.openpgp.enums.symmetric.aes192);
  signaturePacket.preferredSymmetricAlgorithms.push(window.openpgp.enums.symmetric.aes128);
  signaturePacket.preferredSymmetricAlgorithms.push(window.openpgp.enums.symmetric.cast5);
  signaturePacket.preferredSymmetricAlgorithms.push(window.openpgp.enums.symmetric.tripledes);
  signaturePacket.preferredHashAlgorithms = [];
  signaturePacket.preferredHashAlgorithms.push(window.openpgp.enums.hash.sha256);
  signaturePacket.preferredHashAlgorithms.push(window.openpgp.enums.hash.sha1);
  signaturePacket.preferredHashAlgorithms.push(window.openpgp.enums.hash.sha512);
  signaturePacket.preferredCompressionAlgorithms = [];
  signaturePacket.preferredCompressionAlgorithms.push(window.openpgp.enums.compression.zlib);
  signaturePacket.preferredCompressionAlgorithms.push(window.openpgp.enums.compression.zip);
  if (window.openpgp.config.integrity_protect) {
    signaturePacket.features = [];
    signaturePacket.features.push(1); // Modification Detection
  }
  signaturePacket.sign(secretKeyPacket, dataToSign);

  dataToSign = {};
  dataToSign.key = secretKeyPacket;
  dataToSign.bind = secretSubkeyPacket;
  subkeySignaturePacket = new window.openpgp.packet.Signature();
  subkeySignaturePacket.signatureType = window.openpgp.enums.signature.subkey_binding;
  subkeySignaturePacket.publicKeyAlgorithm = window.openpgp.enums.publicKey.rsa_encrypt_sign;
  subkeySignaturePacket.hashAlgorithm = window.openpgp.config.prefer_hash_algorithm;
  subkeySignaturePacket.keyFlags = [window.openpgp.enums.keyFlags.encrypt_communication | window.openpgp.enums.keyFlags.encrypt_storage];
  subkeySignaturePacket.sign(secretKeyPacket, dataToSign);

  packetlist.push(secretKeyPacket);
  packetlist.push(userIdPacket);
  packetlist.push(signaturePacket);
  packetlist.push(secretSubkeyPacket);
  packetlist.push(subkeySignaturePacket);

  return new window.openpgp.key.Key(packetlist);
}

function createSecretKey(key)
{
  var mpiList = createMPIList(key);
  var packet = createSecretKeyPacketFromList(mpiList, window.openpgp.packet.SecretKey);
  return packet;
}

function createSecretSubKey(key)
{
  var mpiList = createMPIList(key);
  var packet = createSecretKeyPacketFromList(mpiList, window.openpgp.packet.SecretSubkey);
  return packet;
}

function createSecretKeyPacketFromList(mpiList, PacketType)
{
  var secretKeyPacket = new PacketType();
  secretKeyPacket.mpi = mpiList;
  secretKeyPacket.isDecrypted = true;
  secretKeyPacket.algorithm = window.openpgp.enums.read(window.openpgp.enums.publicKey, window.openpgp.enums.publicKey.rsa_encrypt_sign);
  return secretKeyPacket;
}

function createMPIList(privateKey)
{
  var p = createMPI(privateKey.p.value, privateKey.p.radix);
  var q = createMPI(privateKey.q.value, privateKey.q.radix);
  var u = p.data.modInverse(q.data);

  var mpiList = [];
  mpiList.push(createMPI(privateKey.n.value, privateKey.n.radix)); // n
  mpiList.push(createMPI("10001", 16)); // e
  mpiList.push(createMPI(privateKey.d.value, privateKey.d.radix)); // d
  mpiList.push(p); // p
  mpiList.push(q); // q
  mpiList.push(createMPIFromBI(u));

  return mpiList;
}

function createMPI(value, radix)
{
  var BigInteger = window.openpgp.crypto.publicKey.jsbn;
  var bn = new BigInteger(value, radix);
  return createMPIFromBI(bn);
}

function createMPIFromBI(bigIntegeger) {
  var mpi = new window.openpgp.MPI();
  mpi.fromBigInteger(bigIntegeger);
  return mpi;
}

function reportProgress(progress) {
  var TOTAL = 515;
  self.send({cmd: 'progress', progress: progress, total: TOTAL});
}

function sendError(err) {
  var stacktraceStr = "Stacktrace could not be extracted";
  if(err !== undefined && err.stack !== undefined) {
    stacktraceStr = err.stack;
  }

  var msg = err.message;

  self.send({cmd: 'error', stacktrace: stacktraceStr, message: msg});
}

function SecureRandom() {
  function nextBytes(byteArray) {
    for (var n = 0; n < byteArray.length; n++) {
      byteArray[n] = window.openpgp.crypto.random.getSecureRandomOctet();
    }
  }
  this.nextBytes = nextBytes;
}

function debug(msg) {
  self.log += msg + "\n";
  self.send({'cmd': 'debug', 'msg': msg});
}

function send(content) {
  if(self.postMessage != undefined) {
    self.postMessage(content);
  } else {
    postMessage(content);
  }
}

function execute(cmd, errMsg) {
  // wrap the sync cmd in a promise
  var promise = new Promise(function(resolve) {
    var result = cmd();
    resolve(result);
  });

  // handler error globally
  return promise.catch(onError.bind(null, errMsg));
}

function onError(message, error) {
  // log the stack trace
  console.error(error.stack);
  // rethrow new high level error for api users
  throw new Error(message);
}
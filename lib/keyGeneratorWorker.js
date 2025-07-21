try {
  if (window === undefined) {
    window = globalThis;
  }
} catch (err) {
  window = {};
}

self.addEventListener('message', function(e) {
  var data = e.data;
  switch (data.cmd) {
    case 'generate_key':
      debug("Starting to generate key..");

      var userStr = data.userStr;
      var splitUserStr = userStr.split('<');
      var userObj = {};
      if (splitUserStr.length > 1) {
        var name = splitUserStr[0].substring(0, splitUserStr[0].length-1);
        var email = splitUserStr[1].substring(0, splitUserStr[1].length-1);
        userObj = {
          email: email,
          name: name
        }
      }

      var options = {};
      options.rsaBits = 2048;
      options.type = 'rsa';
      options.userIDs = [userObj];
      options.format = 'armored';
      options.config = {showComment: true, showVersion: true};

      openpgp.generateKey(options).then(function(key) {
        debug("Generated key!");
        var privateKey = key.privateKey;
        var publicKey = key.publicKey;
        self.send({'cmd': 'key_generated', 'privateKey': privateKey, 'publicKey': publicKey});
      }, function(err) {
        debug("An Unknown Error Occurred While Generating the key");
        debug(err);
      });
      break;
    case 'convert_key':
      var result = convertRawKey(data.rsaKeys, data.userStr);
      self.send({'cmd': 'key_converted', 'privateKey': result.privateKeyArmored, 'publicKey': result.publicKeyArmored});
      break;
    case 'encrypt_keycode':
      debug(data.publicKey);
      // Read in armored keys
      openpgp.readKeys({"armoredKeys": data.publicKey})
          .then(function(publicKeys) {
            if(publicKeys.length > 0) {
              // Create open PGP message
              openpgp.createMessage({"text": data.keyCode})
                  .then(function(message) {
                    var options = {
                      message,
                      encryptionKeys: publicKeys,
                      config: {
                        s2kIterationCountByte: 96,
                        allowMissingKeyFlags: true
                      }
                    }

                    // Encrypt open PGP message
                    openpgp.encrypt(options)
                        .then(function(encryptedMessage) {
                          self.send({'cmd': 'keycode_encrypted', 'encryptedKeyCode': encryptedMessage});
                        }, function(err) {
                          debug('ERROR');
                          debug(err);
                          sendError(err);
                        });
                  }, function(err) {
                    debug('ERROR');
                    debug(err);
                    sendError(err);
                  });
            }
          }, function(err) {
            console.error(err);
            sendError(err);
          });
      break;
    case 'decrypt_keycode':
      decryptKeycode(data.privateKey, data.keyCode, 0);
      break;
    default:
      ;
  };
}, false);

function decryptKeycode(privateKey, keyCode, failback) {
  // read in armored private key
  openpgp.readKeys({"armoredKeys": privateKey}).then(function (privateKeys) {
    if (privateKeys != undefined && privateKeys.length > 0) {
      // Read encrypted message from key code
      openpgp.readMessage({"armoredMessage": keyCode}).then(async function (encryptedMessage) {
        let options = {
          message: encryptedMessage,
          decryptionKeys: privateKeys
        }
        if (failback === 1) {
          options.config = {
            allowInsecureDecryptionWithSigningKeys: true
          }
        } else if (failback === 2) {
          options.config = {
            allowInsecureDecryptionWithSigningKeys: true,
            allowUnauthenticatedMessages: true
          }
        } else if (failback === 3) {
          options.config = {
            allowMissingKeyFlags: true
          }
        } else if (failback === 4) {
          options.config = {
            allowInsecureDecryptionWithSigningKeys: true,
            allowUnauthenticatedMessages: true,
            allowMissingKeyFlags: true
          }
        }
        try {
          let {data: decrypted} = await openpgp.decrypt(options);
          self.send({'cmd': 'keycode_decrypted', 'decryptedKeycode': decrypted});
        } catch (e) {
          if (e.message === 'Error decrypting message: No decryption key packets found') {
            // this might be a keycode encrypted with our old Java or .NET API that was incorrectly encrypting keycodes with the signing key
            // update the config to bypass this and try again.
            decryptKeycode(privateKey, keyCode, 1)
          } else if (e.message === 'Error decrypting message: Message is not authenticated.' && failback !== 3) {
            // this might be a keycode encrypted with our old Java API that wasn't setting setWithIntegrity = true.
            // update the config to bypass this and try again.
            decryptKeycode(privateKey, keyCode, 2)
          } else if (e.message === 'Error decrypting message: None of the key flags is set: consider passing `config.allowMissingKeyFlags`') {
            // this might be a keycode encrypted with an incorrectly formatted SCEAR key
            // update the config to bypass this and try again.
            decryptKeycode(privateKey, keyCode, 3)
          } else if (e.message === 'Error decrypting message: Message is not authenticated.' && failback === 3) {
            // this might be a keycode encrypted with our old Java API that wasn't setting setWithIntegrity = true,
            // and the keycode was encrypted with an incorrectly formatted SCEAR key
            // update the config to bypass this and try again.
            decryptKeycode(privateKey, keyCode, 4)
          } else {
            // something else is the issue so log it
            debug('ERROR');
            debug(e);
            console.log(e);
            sendError(e);
          }
        }
      });
    }
  });
}

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
  var packetlist = new openpgp.PacketList();

  var userIdPacket = new openpgp.UserIDPacket();
  userIdPacket.read(userId);

  dataToSign = {};
  dataToSign.userid = userIdPacket;
  dataToSign.key = secretKeyPacket;
  var signaturePacket = new openpgp.Signature();
  signaturePacket.signatureType = openpgp.enums.signature.cert_generic;
  signaturePacket.publicKeyAlgorithm = openpgp.enums.publicKey.rsa_encrypt_sign;
  signaturePacket.hashAlgorithm = openpgp.config.prefer_hash_algorithm;
  signaturePacket.keyFlags = [openpgp.enums.keyFlags.certify_keys | openpgp.enums.keyFlags.sign_data];
  signaturePacket.preferredSymmetricAlgorithms = [];
  signaturePacket.preferredSymmetricAlgorithms.push(openpgp.enums.symmetric.aes256);
  signaturePacket.preferredSymmetricAlgorithms.push(openpgp.enums.symmetric.aes192);
  signaturePacket.preferredSymmetricAlgorithms.push(openpgp.enums.symmetric.aes128);
  signaturePacket.preferredSymmetricAlgorithms.push(openpgp.enums.symmetric.cast5);
  signaturePacket.preferredSymmetricAlgorithms.push(openpgp.enums.symmetric.tripledes);
  signaturePacket.preferredHashAlgorithms = [];
  signaturePacket.preferredHashAlgorithms.push(openpgp.enums.hash.sha256);
  signaturePacket.preferredHashAlgorithms.push(openpgp.enums.hash.sha1);
  signaturePacket.preferredHashAlgorithms.push(openpgp.enums.hash.sha512);
  signaturePacket.preferredCompressionAlgorithms = [];
  signaturePacket.preferredCompressionAlgorithms.push(openpgp.enums.compression.zlib);
  signaturePacket.preferredCompressionAlgorithms.push(openpgp.enums.compression.zip);
  if (openpgp.config.integrity_protect) {
    signaturePacket.features = [];
    signaturePacket.features.push(1); // Modification Detection
  }
  signaturePacket.sign(secretKeyPacket, dataToSign);

  dataToSign = {};
  dataToSign.key = secretKeyPacket;
  dataToSign.bind = secretSubkeyPacket;
  var subkeySignaturePacket = new openpgp.Signature();
  subkeySignaturePacket.signatureType = openpgp.enums.signature.subkey_binding;
  subkeySignaturePacket.publicKeyAlgorithm = openpgp.enums.publicKey.rsa_encrypt_sign;
  subkeySignaturePacket.hashAlgorithm = openpgp.config.prefer_hash_algorithm;
  subkeySignaturePacket.keyFlags = [openpgp.enums.keyFlags.encrypt_communication | openpgp.enums.keyFlags.encrypt_storage];
  subkeySignaturePacket.sign(secretKeyPacket, dataToSign);

  packetlist.push(secretKeyPacket);
  packetlist.push(userIdPacket);
  packetlist.push(signaturePacket);
  packetlist.push(secretSubkeyPacket);
  packetlist.push(subkeySignaturePacket);

  return new openpgp.Key(packetlist);
}

function createSecretKey(key)
{
  var mpiList = createMPIList(key);
  var packet = createSecretKeyPacketFromList(mpiList, openpgp.SecretKeyPacket);
  return packet;
}

function createSecretSubKey(key)
{
  var mpiList = createMPIList(key);
  var packet = createSecretKeyPacketFromList(mpiList, openpgp.SecretSubkeyPacket);
  return packet;
}

function createSecretKeyPacketFromList(mpiList, PacketType)
{
  var secretKeyPacket = new PacketType();
  secretKeyPacket.mpi = mpiList;
  secretKeyPacket.isDecrypted = true;
  secretKeyPacket.algorithm = openpgp.enums.read(openpgp.enums.publicKey, openpgp.enums.publicKey.rsa_encrypt_sign);
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
  var BigInteger = openpgp.crypto.publicKey.jsbn;
  var bn = new BigInteger(value, radix);
  return createMPIFromBI(bn);
}

function createMPIFromBI(bigIntegeger) {
  var mpi = new openpgp.MPI();
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
      byteArray[n] = openpgp.crypto.random.getSecureRandomOctet();
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
    self.postMessage(content, '*');
  } else {
    postMessage(content, '*');
  }
}
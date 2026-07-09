const openpgp = require('openpgp');
async function encryptFilePart(ctx) {
    // ctx = { file, serverSecret, keycode }
    const encryptionKey = ctx.serverSecret + ctx.keycode;
    const typedArray = new Uint8Array(ctx.file);
    const message = await openpgp.createMessage({ binary: typedArray });
    const ciphertext = await openpgp.encrypt({
        message,
        passwords: [encryptionKey],
        format: 'binary',
        config: { s2kIterationCountByte: 96 }
    });
    return ciphertext;
}

async function decryptFilePart(ctx) {
    // ctx = { file, decryptionKey }
    const message = await openpgp.readMessage({ binaryMessage: ctx.file });
    const plaintext = await openpgp.decrypt({
        message,
        passwords: [ctx.decryptionKey],
        format: 'binary',
        config: { s2kIterationCountByte: 96 }
    });
    return plaintext.data;
}

// ---------------------------------------------------------------------------
// Message encrypt / decrypt (was uploadWorker.js cases 'encrypt_message' /
// 'decrypt_message')
// ---------------------------------------------------------------------------

async function encryptMessage(ctx) {
    // ctx = { message, serverSecret, keycode }
    const encryptionKey = ctx.serverSecret + ctx.keycode;
    const msg = await openpgp.createMessage({ text: ctx.message });
    const encrypted = await openpgp.encrypt({
        message: msg,
        passwords: [encryptionKey],
        format: 'object',
        config: { s2kIterationCountByte: 96 }
    });
    return base64EncodeArray(encrypted.packets.write());
}

async function decryptMessage(ctx) {
    // ctx = { message, serverSecret, keycode }
    const decryptionKey = ctx.serverSecret + ctx.keycode;
    const decoded = base64Decode(ctx.message);
    const message = await openpgp.readMessage({ binaryMessage: decoded });
    const plaintext = await openpgp.decrypt({
        message,
        passwords: [decryptionKey],
        format: 'binary',
        config: { s2kIterationCountByte: 96 }
    });
    return typedArrayToUnicodeString(plaintext.data);
}

// ---------------------------------------------------------------------------
// Keycode encrypt / decrypt (was keyGeneratorWorker.js cases 'encrypt_keycode'
// / 'decrypt_keycode')
// ---------------------------------------------------------------------------

async function encryptKeycode(ctx) {
    // ctx = { publicKey, keyCode }
    const publicKeys = await openpgp.readKeys({ armoredKeys: ctx.publicKey });
    if (!publicKeys || publicKeys.length === 0) {
        throw new Error('encryptKeycode: no public keys parsed');
    }
    const message = await openpgp.createMessage({ text: ctx.keyCode });
    return openpgp.encrypt({
        message,
        encryptionKeys: publicKeys,
        config: {
            s2kIterationCountByte: 96,
            allowMissingKeyFlags: true
        }
    });
}

async function decryptKeycode(ctx) {
    return _decryptKeycodeWithFailback(ctx.privateKey, ctx.keyCode, 0);
}

// KNOWN parity-preserved bug: at `failback=2`, if openpgp re-throws
// 'Message is not authenticated.' (e.g., if `allowUnauthenticatedMessages`
// fails to suppress it), the second branch (`failback !== 3`) is true and
// the function recurses with `failback=2` — same args, same options, same
// throw → stack overflow. Matches keyGeneratorWorker.js on main exactly
// (same `failback !== 3` branch). In practice openpgp 6's
// `allowUnauthenticatedMessages: true` suppresses the error, so the loop
// terminates.
async function _decryptKeycodeWithFailback(privateKey, keyCode, failback) {
    const privateKeys = await openpgp.readKeys({ armoredKeys: privateKey });
    if (!privateKeys || privateKeys.length === 0) {
        throw new Error('decryptKeycode: no private keys parsed');
    }
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: keyCode });
    const options = {
        message: encryptedMessage,
        decryptionKeys: privateKeys
    };
    if (failback === 1) {
        options.config = { allowInsecureDecryptionWithSigningKeys: true };
    } else if (failback === 2) {
        options.config = {
            allowInsecureDecryptionWithSigningKeys: true,
            allowUnauthenticatedMessages: true
        };
    } else if (failback === 3) {
        options.config = { allowMissingKeyFlags: true };
    } else if (failback === 4) {
        options.config = {
            allowInsecureDecryptionWithSigningKeys: true,
            allowUnauthenticatedMessages: true,
            allowMissingKeyFlags: true
        };
    }

    try {
        const { data } = await openpgp.decrypt(options);
        return data;
    } catch (e) {
        if (e.message === 'Error decrypting message: No decryption key packets found') {
            return _decryptKeycodeWithFailback(privateKey, keyCode, 1);
        } else if (e.message === 'Error decrypting message: Message is not authenticated.' && failback !== 3) {
            return _decryptKeycodeWithFailback(privateKey, keyCode, 2);
        } else if (e.message === 'Error decrypting message: None of the key flags is set: consider passing `config.allowMissingKeyFlags`') {
            return _decryptKeycodeWithFailback(privateKey, keyCode, 3);
        } else if (e.message === 'Error decrypting message: Message is not authenticated.' && failback === 3) {
            return _decryptKeycodeWithFailback(privateKey, keyCode, 4);
        }
        throw e;
    }
}

async function generateKeyPair(ctx) {
    // ctx = { userStr }   userStr is "Name <email>" or just "<email>"
    const userObj = parseUserStr(ctx.userStr);
    const result = await openpgp.generateKey({
        rsaBits: 2048,
        type: 'rsa',
        userIDs: [userObj],
        format: 'armored',
        config: { showComment: true, showVersion: true }
    });
    return { privateKey: result.privateKey, publicKey: result.publicKey };
}

function parseUserStr(userStr) {
    const splitUserStr = userStr.split('<');
    if (splitUserStr.length > 1) {
        const name = splitUserStr[0].substring(0, splitUserStr[0].length - 1);
        const email = splitUserStr[1].substring(0, splitUserStr[1].length - 1);
        return { email, name };
    }
    return {};
}

function convertRawKey(rsaKeys, userStr) {
    const secretKey = createSecretKey(rsaKeys.privateKey);
    const secretSubKey = createSecretSubKey(rsaKeys.privateSubKey);
    const key = wrapKeyObject(userStr, secretKey, secretSubKey);
    return {
        privateKeyArmored: key.armor(),
        publicKeyArmored: key.toPublic().armor()
    };
}

function wrapKeyObject(userId, secretKeyPacket, secretSubkeyPacket) {
    const packetlist = new openpgp.PacketList();

    const userIdPacket = new openpgp.UserIDPacket();
    userIdPacket.read(userId);

    let dataToSign = {
        userid: userIdPacket,
        key: secretKeyPacket
    };
    const signaturePacket = new openpgp.Signature();
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
        signaturePacket.features.push(1);
    }
    signaturePacket.sign(secretKeyPacket, dataToSign);

    dataToSign = {
        key: secretKeyPacket,
        bind: secretSubkeyPacket
    };
    const subkeySignaturePacket = new openpgp.Signature();
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

function createSecretKey(key) {
    const mpiList = createMPIList(key);
    return createSecretKeyPacketFromList(mpiList, openpgp.SecretKeyPacket);
}

function createSecretSubKey(key) {
    const mpiList = createMPIList(key);
    return createSecretKeyPacketFromList(mpiList, openpgp.SecretSubkeyPacket);
}

function createSecretKeyPacketFromList(mpiList, PacketType) {
    const packet = new PacketType();
    packet.mpi = mpiList;
    packet.isDecrypted = true;
    packet.algorithm = openpgp.enums.read(openpgp.enums.publicKey, openpgp.enums.publicKey.rsa_encrypt_sign);
    return packet;
}

function createMPIList(privateKey) {
    const p = createMPI(privateKey.p.value, privateKey.p.radix);
    const q = createMPI(privateKey.q.value, privateKey.q.radix);
    const u = p.data.modInverse(q.data);

    const mpiList = [];
    mpiList.push(createMPI(privateKey.n.value, privateKey.n.radix));
    mpiList.push(createMPI('10001', 16));
    mpiList.push(createMPI(privateKey.d.value, privateKey.d.radix));
    mpiList.push(p);
    mpiList.push(q);
    mpiList.push(createMPIFromBI(u));

    return mpiList;
}

function createMPI(value, radix) {
    const BigInteger = openpgp.crypto.publicKey.jsbn;
    const bn = new BigInteger(value, radix);
    return createMPIFromBI(bn);
}

function createMPIFromBI(bigInteger) {
    const mpi = new openpgp.MPI();
    mpi.fromBigInteger(bigInteger);
    return mpi;
}

function base64EncodeArray(t, o) {
    const b64s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let a, c, n;
    const r = o ? o : [];
    let l = 0, s = 0;
    const tl = t.length;

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
            r.push(b64s.charAt(c & 63));
        }
        l += 1;
        s += 1;
        if (s === 3) {
            s = 0;
        }
    }
    if (s > 0) {
        r.push(b64s.charAt(a));
        l += 1;
        r.push('=');
        l += 1;
    }
    if (s === 1) {
        r.push('=');
    }
    if (o) {
        return;
    }
    return r.join('');
}

function base64Decode(t) {
    const b64s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let c, n;
    const r = [];
    let s = 0, a = 0;
    const tl = t.length;

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

function typedArrayToUnicodeString(ua) {
    const binstr = Array.prototype.map.call(ua, function (ch) {
        return String.fromCharCode(ch);
    }).join('');
    const escstr = binstr.replace(/(.)/g, function (m, p) {
        let code = p.charCodeAt().toString(16).toUpperCase();
        if (code.length < 2) {
            code = '0' + code;
        }
        return '%' + code;
    });
    return decodeURIComponent(escstr);
}

module.exports = {
    encryptFilePart,
    decryptFilePart,
    encryptMessage,
    decryptMessage,
    encryptKeycode,
    decryptKeycode,
    generateKeyPair,
    convertRawKey
};

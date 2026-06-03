// SendSafely/lib/crypto-utils.js
const crypto = require('crypto');

function hmacSha256Hex(key, message) {
  return crypto.createHmac('sha256', key).update(message, 'utf8').digest('hex');
}

function pbkdf2Sha256Hex(password, salt, iterations, byteLength) {
  return crypto.pbkdf2Sync(password, salt, iterations, byteLength, 'sha256').toString('hex');
}

function randomKeycode() {
  return urlSafeBase64(crypto.randomBytes(32).toString('base64'));
}

function urlSafeBase64(b64) {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

module.exports = { hmacSha256Hex, pbkdf2Sha256Hex, randomKeycode };

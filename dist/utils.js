'use strict';

/* global crypto */

/**
 * Convert ascii to ArrayBufffer
 * ex : "bonjour" -> Uint8Array [ 98, 111, 110, 106, 111, 117, 114 ]
 *
 * @param {String} str
 * @returns {ArrayBuffer}
 */
var toArray = function toArray(str) {
  if (typeof str !== 'string') {
    throw new Error('toArray accepts only string');
  }
  var chars = [];
  for (var i = 0; i < str.length; ++i) {
    chars.push(str.charCodeAt(i));
  }
  return new Uint8Array(chars);
};

/**
* Convert ArrayBufffer to hex String
* ex : Uint8Array [ 17, 161, 178 ] -> '11a1b2'
*
* @param {ArrayBuffer} bytes
* @returns {String}
*/
var bufferToHexString = function bufferToHexString(bytes) {
  if (!bytes) {
    return null;
  }
  var hexBytes = [];

  for (var i = 0; i < bytes.length; ++i) {
    var byteString = bytes[i].toString(16);
    if (byteString.length < 2) {
      byteString = '0' + byteString;
    }
    hexBytes.push(byteString);
  }

  return hexBytes.join('');
};

/**
 * Convert ArrayBufffer to ascii
 * ex : Uint8Array [ 98, 111, 110, 106, 111, 117, 114 ] -> "bonjour"
 *
 * @param {ArrayBuffer} bytes
 * @returns {String}
 */
var toString = function toString(bytes) {
  return String.fromCharCode.apply(null, new Uint8Array(bytes));
};

/**
 * Convert hex String to ArrayBufffer
 * ex : '11a1b2' -> Uint8Array [ 17, 161, 178 ]
 *
 * @param {String} hexString
 * @returns {ArrayBuffer}
 */
var hexStringToBuffer = function hexStringToBuffer(hexString) {
  if (hexString.length % 2 !== 0) {
    throw new Error('Invalid hexString');
  }
  var arrayBuffer = new Uint8Array(hexString.length / 2);

  for (var i = 0; i < hexString.length; i += 2) {
    var byteValue = parseInt(hexString.substr(i, 2), 16);
    if (isNaN(byteValue)) {
      throw new Error('Invalid hexString');
    }
    arrayBuffer[i / 2] = byteValue;
  }

  return arrayBuffer;
};

/**
 * Generate a PBKDF2 derived key based on user given passPhrase
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The passphrase length
 * @returns {Promise}   A promise that contains the derived key
 */
var deriveKey = function deriveKey(passPhrase, salt) {
  var iterations = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 10000;

  // Always specify a strong salt
  if (iterations < 10000) {
    console.warn('The iteration number is less than 10000, increase it !');
  }

  return crypto.subtle.importKey('raw', typeof passPhrase === 'string' ? toArray(passPhrase) : passPhrase, 'PBKDF2', false, ['deriveBits', 'deriveKey']).then(function (baseKey) {
    return crypto.subtle.deriveBits({
      name: 'PBKDF2',
      salt: salt || new Uint8Array([]),
      iterations: iterations,
      hash: 'sha-256'
    }, baseKey, 128);
  }).then(function (derivedKey) {
    return new Uint8Array(derivedKey);
  });
};

/**
 * Hash of a string or arrayBuffer
 *
 * @param {string | arrayBuffer} msg The message
 * @param {string} [type] The hash name (SHA-256 by default)
 * @returns {Promise}   A promise that contains the hash as a Uint8Array
 */
var hash = function hash(msg) {
  var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'SHA-256';

  return window.crypto.subtle.digest({
    name: 'SHA-256'
  }, typeof msg === 'string' ? toArray(msg) : msg).then(function (digest) {
    return new Uint8Array(digest);
  });
};

// Generate a random string using the Webwindow API instead of Math.random
// (insecure)
var randomString = function randomString() {
  var length = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 18;

  var charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  var result = '';
  if (window.crypto && window.crypto.getRandomValues) {
    var values = new Uint32Array(length);
    window.crypto.getRandomValues(values);
    for (var i = 0; i < length; i++) {
      result += charset[values[i] % charset.length];
    }
  } else {
    throw new Error("Your browser can't generate secure random numbers");
  }
  return result;
};

/**
   * Generate an AES key based on the cipher mode and keysize
   *
   * @returns {CryptoKey} - The generated AES key.
   */
var genAESKey = function genAESKey() {
  var mode = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 'aes-gcm';
  var keySize = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 128;

  return crypto.subtle.generateKey({
    name: mode,
    length: keySize
  }, true, ['decrypt', 'encrypt']);
};
/**
   * Generate an AES key based on the cipher mode and keysize
   *
   * @returns {CryptoKey} - The generated AES key.
   */
var genAESKeyRaw = function genAESKeyRaw() {
  var mode = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 'aes-gcm';
  var keySize = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 128;

  return genAESKey(mode, keySize).then(function (key) {
    return crypto.subtle.exportKey('raw', key).then(function (key) {
      return new Uint8Array(key);
    });
  });
};

module.exports = {
  toArray: toArray,
  bufferToHexString: bufferToHexString,
  toString: toString,
  hexStringToBuffer: hexStringToBuffer,
  deriveKey: deriveKey,
  randomString: randomString,
  hash: hash,
  genAESKey: genAESKey,
  genAESKeyRaw: genAESKeyRaw
};
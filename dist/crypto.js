(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.CryptoMasq = f()}})(function(){var define,module,exports;return (function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
/**
 * Generate a PBKDF2 derived key based on user given passPhrase
 *
 * @param {string} passPhrase The passphrase that is used to derive the key
 * @returns {Promise}   A promise that contains the derived key
 */
var deriveKey = exports.deriveKey = function deriveKey() {
  var passPhrase = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
  var keyLenth = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 18;
  var iterations = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 10000;

  if (passPhrase.length === 0) {
    passPhrase = randomString(keyLenth);
  }

  // TODO: set this to a real value later
  var salt = new Uint8Array('');

  return crypto.subtle.importKey('raw', toArray(passPhrase), 'PBKDF2', false, ['deriveBits', 'deriveKey']).then(function (baseKey) {
    return crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'sha-256' }, baseKey, 128);
  }).then(function (derivedKey) {
    return new Uint8Array(derivedKey);
  });
};

// Generate a random string using the Webwindow API instead of Math.random (insecure)
var randomString = exports.randomString = function randomString() {
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
    console.log("Your browser can't generate secure random numbers");
  }
  return result;
};

/**
 * Decrypt data with AES-GCM cipher
 *
 * @param {ArrayBuffer} data Data to decrypt
 * @param {ArrayBuffer} key Aes key as raw data. 128 or 256 bits
 * @param {ArrayBuffer} iv The IV with a size of 96 bits (12 bytes)
 * @param {string} mode The encryption mode : AES-GCM
 * @param {ArrayBuffer} additionalData The non-secret authenticated data
 * @returns {ArrayBuffer}
 */
var decryptBuffer = function decryptBuffer(data, key, iv, mode, additionalData) {
  // TODO: test input params
  return crypto.subtle.importKey('raw', key, { name: mode }, true, ['encrypt', 'decrypt']).then(function (bufKey) {
    return crypto.subtle.decrypt({ name: mode, iv: iv, additionalData: additionalData }, bufKey, data).then(function (result) {
      return new Uint8Array(result);
    });
  });
};

/**
 * Encrypt data with AES-GCM cipher
 *
 * @param {ArrayBuffer} data Data to encrypt
 * @param {ArrayBuffer} key Aes key as raw data. 128 or 256 bits
 * @param {ArrayBuffer} iv The IV with a size of 96 bits (12 bytes)
 * @param {string} mode The encryption mode : AES-GCM
 * @param {ArrayBuffer} additionalData The non-secret authenticated data
 * @returns {ArrayBuffer}
 */
var encryptBuffer = function encryptBuffer(data, key, iv, mode, additionalData) {
  return crypto.subtle.importKey('raw', key, { name: mode }, true, ['encrypt', 'decrypt']).then(function (bufKey) {
    return crypto.subtle.encrypt({ name: mode, iv: iv, additionalData: additionalData }, bufKey, data).then(function (result) {
      return new Uint8Array(result);
    });
  });
};

/**
 * Encrypt an object
 *
 * @param {ArrayBuffer} key Encryption key
 * @param {string} data A string containing data to be encrypted (e.g. a stringified JSON)
 * @param {string} additionalData The authenticated data (ex. version number :1.0.1 )
 * @returns {object} Return a promise with a JSON object having the following format :
 *     { ciphertext : {hexString}, iv : {hexString}, version : {string} }
 */
var encrypt = exports.encrypt = function encrypt(key, data, additionalData) {
  // Prepare context
  var iv = window.crypto.getRandomValues(new Uint8Array(12));
  var toEncrypt = toArray(data);

  return encryptBuffer(toEncrypt, key, iv, 'AES-GCM', toArray(additionalData)).then(function (result) {
    return { ciphertext: bufferToHexString(result), iv: bufferToHexString(iv), version: additionalData };
  });
};

/**
 * Decrypt an object
 *
 * @param {ArrayBuffer} key Decryption key
 * @param {object} encrypted data Must contain 3 values:
 *     { ciphertext : {hexString}, iv : {hexString}, version : {string}
 * @returns {string} Return the decrypted data as a string.
 *
 */
var decrypt = exports.decrypt = function decrypt(key, data) {
  // Prepare context
  var ciphertext = hexStringToBuffer(data.ciphertext);
  var additionalData = toArray(data.version);
  var iv = hexStringToBuffer(data.iv);

  return decryptBuffer(ciphertext, key, iv, 'AES-GCM', additionalData).then(function (decrypted) {
    return toString(decrypted);
  });
};

/**
 * Gets tag from encrypted data
 *
 * @param {ArrayBuffer} encrypted Encrypted data
 * @param {number} tagLength Tag length in bits. Default 128 bits
 * @returns {ArrayBuffer}
 */
var getTag = exports.getTag = function getTag(encrypted) {
  var tagLength = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 128;

  return encrypted.slice(encrypted.byteLength - (tagLength + 7 >> 3));
};

/**
 * Convert hex String to ArrayBufffer
 * ex : '11a1b2' -> Uint8Array [ 17, 161, 178 ]
 *
 * @param {String} hexString
 * @returns {ArrayBuffer}
 */
var hexStringToBuffer = exports.hexStringToBuffer = function hexStringToBuffer(hexString) {
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
 * Convert ArrayBufffer to hex String
 * ex : Uint8Array [ 17, 161, 178 ] -> '11a1b2'
 *
 * @param {ArrayBuffer} bytes
 * @returns {String}
 */
var bufferToHexString = exports.bufferToHexString = function bufferToHexString(bytes) {
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
 * Convert ascii to ArrayBufffer
 * ex : "bonjour" -> Uint8Array [ 98, 111, 110, 106, 111, 117, 114 ]
 *
 * @param {String} str
 * @returns {ArrayBuffer}
 */
var toArray = exports.toArray = function toArray() {
  var str = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';

  var chars = [];
  for (var i = 0; i < str.length; ++i) {
    chars.push(str.charCodeAt(i));
  }
  return new Uint8Array(chars);
};

/**
 * Convert ArrayBufffer to ascii
 * ex : Uint8Array [ 98, 111, 110, 106, 111, 117, 114 ] -> "bonjour"
 *
 * @param {ArrayBuffer} bytes
 * @returns {String}
 */
var toString = exports.toString = function toString(bytes) {
  return String.fromCharCode.apply(null, new Uint8Array(bytes));
};
},{}]},{},[1])(1)
});
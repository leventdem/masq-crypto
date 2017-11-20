(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.CryptoMasq = f()}})(function(){var define,module,exports;return (function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
'use strict';

var CryptoMasq = {};

/**
 * Generate a PBKDF2 derived key based on user given passPhrase
 *
 * @param {string} passPhrase The passphrase that is used to derive the key
 * @returns {Promise}   A promise that contains the derived key
 */
CryptoMasq.deriveKey = function () {
  var passPhrase = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
  var iterations = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 10000;

  if (passPhrase.length === 0) {
    passPhrase = CryptoMasq.randomString(CryptoMasq.keyLenth);
  }

  // TODO: set this to a real value later
  var salt = new Uint8Array('');

  return crypto.subtle.importKey('raw', CryptoMasq.asciiToUint8Array(passPhrase), 'PBKDF2', false, ['deriveBits', 'deriveKey']).then(function (baseKey) {
    return crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'sha-256' }, baseKey, 128);
  }, CryptoMasq.failAndLog).then(function (derivedKey) {
    return new Uint8Array(derivedKey);
  }, CryptoMasq.failAndLog);
};

// Generate a random string using the Webwindow API instead of Math.random (insecure)
CryptoMasq.randomString = function () {
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
CryptoMasq.decrypt = function (data, key, iv, mode, additionalData) {
  // TODO: test input params
  return crypto.subtle.importKey('raw', key, { name: mode }, true, ['encrypt', 'decrypt']).then(function (bufKey) {
    return crypto.subtle.decrypt({ name: mode, iv: iv, additionalData: additionalData }, bufKey, data).then(function (result) {
      return new Uint8Array(result);
    }, CryptoMasq.failAndLog);
  }, CryptoMasq.failAndLog);
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
CryptoMasq.encrypt = function (data, key, iv, mode, additionalData) {
  return crypto.subtle.importKey('raw', key, { name: mode }, true, ['encrypt', 'decrypt']).then(function (bufKey) {
    return crypto.subtle.encrypt({ name: mode, iv: iv, additionalData: additionalData }, bufKey, data).then(function (result) {
      return new Uint8Array(result);
    });
  });
};

/**
 * Encrypt an object
 *
 * @param {object} data Basic key-pair values
 * @param {string} additionalData The authenticated data (ex. version number :1.0.1 )
 * @returns {string} Return a stringified JSON object with the following format :
 *     { ciphertext : {hexString}, iv : {hexString}, version : {string} }
 */
CryptoMasq.encryptJSON = function (key, data, additionalData) {
  // Prepare context
  var dataJson = CryptoMasq.asciiToUint8Array(JSON.stringify(data));
  var iv = window.crypto.getRandomValues(new Uint8Array(12));

  return CryptoMasq.encrypt(dataJson, key, iv, 'AES-GCM', CryptoMasq.asciiToUint8Array(additionalData)).then(function (result) {
    return JSON.stringify({ ciphertext: CryptoMasq.bytesToHexString(result), iv: CryptoMasq.bytesToHexString(iv), version: additionalData });
  });
};

/**
 * Decrypt an object
 *
 * @param {object} encrypted data Must contain 3 values:
 *     { ciphertext : {hexString}, iv : {hexString}, version : {string}
 * @returns {ArrayBuffer} Return the decrypted text.
 *
 */
CryptoMasq.decryptJSON = function (key, data) {
  // Prepare context
  var ciphertext = CryptoMasq.hexStringToUint8Array(data.ciphertext);
  var additionalData = CryptoMasq.asciiToUint8Array(data.version);
  var iv = CryptoMasq.hexStringToUint8Array(data.iv);

  return CryptoMasq.decrypt(ciphertext, key, iv, 'AES-GCM', additionalData).then(function (decrypted) {
    return decrypted;
  });
};

/**
 * Gets tag from encrypted data
 *
 * @param {ArrayBuffer} encrypted Encrypted data
 * @param {number} tagLength Tag length in bits. Default 128 bits
 * @returns {ArrayBuffer}
 */
CryptoMasq.getTag = function (encrypted) {
  var tagLength = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 128;

  return encrypted.slice(encrypted.byteLength - (tagLength + 7 >> 3));
};

// EXAMPLE
// var apiData = { POI_1: 'Tour eiffel', POI_2: 'Cafeteria'}

// If no passphrase is given, it will be generated.
// setUserKey('').then(function () {
//   // encryption
//   encryptJSON(JSON.stringify(apiData), '1.0.0').then(function (encryptedJson) {
//     console.log(encryptedJson)
//     // {"ciphertext":"f7bd4...a1fe0fd9","iv":"a033ff25534d21775be6e8c9","version":"1.0.0"}

//     // decryption
//     decryptJSON(JSON.parse(encryptedJson)).then(function (decryptedJson) {
//       console.log(bytesToASCIIString(decryptedJson))
//       // "{\"POI_1\":\"Tour eiffel\",\"POI_2\":\"Cafeteria\"}"
//     })
//   })
// })

CryptoMasq.hexStringToUint8Array = function (hexString) {
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

CryptoMasq.bytesToHexString = function (bytes) {
  // TODO: Check this for redundancy of bytes

  if (!bytes) {
    return null;
  }

  bytes = new Uint8Array(bytes);
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

CryptoMasq.asciiToUint8Array = function () {
  var str = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';

  var chars = [];
  for (var i = 0; i < str.length; ++i) {
    chars.push(str.charCodeAt(i));
  }
  return new Uint8Array(chars);
};

CryptoMasq.bytesToASCIIString = function (bytes) {
  return String.fromCharCode.apply(null, new Uint8Array(bytes));
};

CryptoMasq.failAndLog = function (error) {
  console.log(error);
};

CryptoMasq.hexToBuf = function () {
  var hex = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';

  for (var _bytes = [], c = 0; c < hex.length; c += 2) {
    _bytes.push(parseInt(hex.substr(c, 2), 16));
  }
  return new Uint8Array(bytes);
};

CryptoMasq.bufToHex = function (buf) {
  var byteArray = new Uint8Array(buf);
  var hexString = '';
  var nextHexByte;

  for (var i = 0; i < byteArray.byteLength; i++) {
    nextHexByte = byteArray[i].toString(16);
    if (nextHexByte.length < 2) {
      nextHexByte = '0' + nextHexByte;
    }
    hexString += nextHexByte;
  }
  return hexString;
};

module.exports = CryptoMasq;
},{}]},{},[1])(1)
});
(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.MasqCrypto = f()}})(function(){var define,module,exports;return (function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }(); /* global crypto */


var _utils = require('./utils.js');

var utils = _interopRequireWildcard(_utils);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var aesModes = {
  CBC: 'aes-cbc',
  GCM: 'aes-gcm',
  CTR: 'aes-ctr'
};

var acceptedMode = ['aes-cbc', 'aes-gcm', 'aes-ctr'];

var acceptedKeySize = [128, 192, 256];

/**
 * Decrypt data
 *
 * @param {ArrayBuffer} data - Data to decrypt
 * @param {ArrayBuffer} key - The AES key as raw data. 128 or 256 bits
 * @param {Object} cipherContext - The AES cipher parameters
 * @param {ArrayBuffer} cipherContext.iv - The IV
 * @param {string} cipherContext.name - The encryption mode
 * @param {ArrayBuffer} [cipherContext.additionalData] - The non-secret authenticated data (only aes-gcm)
 * @param {ArrayBuffer} [cipherContext.counter] - The counter used for aes-ctr mode
 * @returns {ArrayBuffer} - The decrypted buffer
 */
var decryptBuffer = function decryptBuffer(data, key, cipherContext) {
  // TODO: test input params
  return crypto.subtle.decrypt(cipherContext, key, data).then(function (result) {
    return new Uint8Array(result);
  });
};

/**
 * Encrypt data
 *
 * @param {ArrayBuffer} data - Data to encrypt
 * @param {ArrayBuffer} key - The AES CryptoKey
 * @param {Object} cipherContext - The AES cipher parameters
 * @param {ArrayBuffer} cipherContext.iv - The IV
 * @param {string} cipherContext.name - The encryption mode
 * @param {ArrayBuffer} [cipherContext.additionalData] - The non-secret authenticated data (only aes-gcm)
 * @param {ArrayBuffer} [cipherContext.counter] - The counter used for aes-ctr mode
 * @returns {ArrayBuffer} - The encrypted buffer
 */
var encryptBuffer = function encryptBuffer(data, key, cipherContext) {
  return crypto.subtle.encrypt(cipherContext, key, data).then(function (result) {
    return new Uint8Array(result);
  });
};
/**
 * AES cipher
 * @constructor
 * @param {Object} params - The AES cipher parameters
 * @param {string} [params.mode] - The encryption mode : aes-gcm, aes-cbc
 * @param {ArrayBuffer} [params.key] - The AES CryptoKey
 * @param {number} [params.keySize] - The key size in bits (128, 192, 256)
 * @param {number} [params.iv] - The IV, if not provided it will be generated randomly
 * @param {number} [params.length] - The counter length for aes-ctr mode
 * @param {string} [params.additionalData] - The authenticated data, only for aes-gcm mode.
 */

var AES = function () {
  function AES(params) {
    _classCallCheck(this, AES);

    this.mode = params.mode || 'aes-gcm';
    this.keySize = params.keySize || 128;
    this.IV = params.iv || null;
    this.key = params.key || null;
    this.length = params.length || 128;
    this.additionalData = params.additionalData || '';
  }

  _createClass(AES, [{
    key: 'checkRaw',


    /**
    * Check the received key format (CryptoKey or raw key).
    * If raw, import the key and return the CryptoKey
    *
    * @param {obj} obj - Save this in obj
    * @returns {CryptoKey|arrayBuffer} - The CryptoKey
    */
    value: function checkRaw(obj, key) {
      return new Promise(function (resolve, reject) {
        if (key instanceof Uint8Array) {
          obj.importKeyRaw(key).then(resolve);
        } else {
          resolve(key);
        }
      });
    }

    /**
    * Transform a CryptoKey into a raw key
    *
    * @param {CryptoKey} key - The CryptoKey
    * @returns {arrayBuffer} - The raw key
    */

  }, {
    key: 'exportKeyRaw',
    value: function exportKeyRaw(key) {
      var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'raw';

      return crypto.subtle.exportKey(type, key).then(function (key) {
        return new Uint8Array(key);
      });
    }

    /**
    * Transform a raw key into a CryptoKey
    *
    * @param {arrayBuffer} key - The key we want to import
    * @returns {CryptoKey} - The CryptoKey
    */

  }, {
    key: 'importKeyRaw',
    value: function importKeyRaw(key) {
      var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'raw';

      return crypto.subtle.importKey(type, key, {
        name: this.mode
      }, true, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);
    }

    /**
    * Decrypt the given input. All cipher context information
    * have been initialized at object creation (default or parameter)
    *
    * @param {object} input - The ciphertext and associated decryption data
    * @param {hexString} input.ciphertext - The ciphertext
    * @param {hexString} input.iv - The IV used at encryption
    * @param {hexString} [input.version] - The additionnal data for aes-gcm mode
    * @returns {string} - The decrypted input
    */

  }, {
    key: 'decrypt',
    value: function decrypt(input) {
      // Prepare context, all modes have at least one property : ciphertext
      var context = {};
      var cipherContext = {};
      context.ciphertext = input.hasOwnProperty('ciphertext') ? utils.hexStringToBuffer(input.ciphertext) : '';
      if (this.mode === 'aes-gcm') {
        context.iv = input.hasOwnProperty('iv') ? utils.hexStringToBuffer(input.iv) : '';
        // aes-gcm may have an additional authenticated data property (optional)
        context.additionalData = input.hasOwnProperty('version') ? utils.toArray(input.version) : [];
        // Prepare cipher context, depends on cipher mode
        cipherContext.name = this.mode;
        cipherContext.iv = context.iv;
        cipherContext.additionalData = context.additionalData;
        // This function test the given key and return the Cryptokey
        return this.checkRaw(this, this.key).then(function (key) {
          return decryptBuffer(context.ciphertext, key, cipherContext);
        }).then(function (res) {
          return utils.toString(res);
        });
      } else if (this.mode === 'aes-cbc') {
        // IV is 128 bits long === 16 bytes
        context.iv = input.hasOwnProperty('iv') ? utils.hexStringToBuffer(input.iv) : '';
        // Prepare cipher context, depends on cipher mode
        cipherContext.name = this.mode;
        cipherContext.iv = context.iv;
        return this.checkRaw(this, this.key).then(function (key) {
          return decryptBuffer(context.ciphertext, key, cipherContext);
        }).then(function (res) {
          return utils.toString(res);
        });
      } else if (this.mode === 'aes-ctr') {
        // IV is 128 bits long === 16 bytes
        context.iv = input.hasOwnProperty('iv') ? utils.hexStringToBuffer(input.iv) : '';
        // Prepare cipher context, depends on cipher mode
        cipherContext.name = this.mode;
        cipherContext.counter = context.iv;
        cipherContext.length = this.length;
        return this.checkRaw(this, this.key).then(function (key) {
          return decryptBuffer(context.ciphertext, key, cipherContext);
        }).then(function (res) {
          return utils.toString(res);
        });
      } else {
        throw new Error('The mode ' + this.mode + ' is not yet supported');
      }
    }

    /**
    * Encrypt the given input. All cipher context information
    * have been initialized at object creation (as default or as parameter)
    * If the input is an object, it has to be stringified
    *
    * @param {string} input - The plaintext
    * @returns {object} - The encrypted input with additional cipher information (e.g. iv)
    */

  }, {
    key: 'encrypt',
    value: function encrypt(input) {
      // all modes have at least the plaintext
      var context = {};
      var cipherContext = {};
      context.plaintext = utils.toArray(input);
      if (this.mode === 'aes-gcm') {
        // IV is 96 bits long === 12 bytes
        context.iv = this.iv || window.crypto.getRandomValues(new Uint8Array(12));
        context.additionalData = utils.toArray(this.additionalData);
        // Prepare cipher context, depends on cipher mode
        cipherContext.name = this.mode;
        cipherContext.iv = context.iv;
        cipherContext.additionalData = context.additionalData;
        // This function tests the given key and return the Cryptokey
        return this.checkRaw(this, this.key).then(function (key) {
          return encryptBuffer(context.plaintext, key, cipherContext);
        }).then(function (result) {
          return {
            ciphertext: utils.bufferToHexString(result),
            iv: utils.bufferToHexString(context.iv),
            version: utils.toString(context.additionalData)
          };
        });
      } else if (this.mode === 'aes-cbc') {
        // IV is 128 bits long === 16 bytes
        context.iv = this.iv || window.crypto.getRandomValues(new Uint8Array(16));
        // Prepare cipher context, depends on cipher mode
        cipherContext.name = this.mode;
        cipherContext.iv = context.iv;
        return this.checkRaw(this, this.key).then(function (key) {
          return encryptBuffer(context.plaintext, key, cipherContext);
        }).then(function (result) {
          return {
            ciphertext: utils.bufferToHexString(result),
            iv: utils.bufferToHexString(context.iv)
          };
        });
      } else if (this.mode === 'aes-ctr') {
        // IV is 128 bits long === 16 bytes
        context.iv = this.iv || window.crypto.getRandomValues(new Uint8Array(16));
        // Prepare cipher context, depends on cipher mode
        cipherContext.name = this.mode;
        cipherContext.counter = context.iv;
        cipherContext.length = this.length;
        return this.checkRaw(this, this.key).then(function (key) {
          return encryptBuffer(context.plaintext, key, cipherContext);
        }).then(function (result) {
          return {
            ciphertext: utils.bufferToHexString(result),
            iv: utils.bufferToHexString(context.iv)
          };
        });
      } else {
        throw new Error('The mode ' + this.mode + ' is not yet supported');
      }
    }

    /**
     * Generate an AES key based on the cipher mode and keysize
     * Cipher mode and key size are initialized at cipher AES instance creation.
     *
     * @returns {CryptoKey} - The generated AES key.
     */

  }, {
    key: 'genAESKey',
    value: function genAESKey() {
      return crypto.subtle.generateKey({
        name: this.mode || 'aes-gcm',
        length: this.keySize || 128
      }, true, ['decrypt', 'encrypt']);
    }

    /**
    * Wrap the given key. All cipher context information of the wrapping key
    * have been initialized at object creation (default or parameter)
    * Return the wrappedKey and the associated iv.
    *
    * @param {CryptoKey} toBeWrappedKey - The key we want to wrap
    * @param {string} [keySize] - The size of the key we want to wrap
    * @param {string} [exportType] - The export format of the toBeWrappedKey
    * @returns {Uint8Array} - The wrapped key
    */

  }, {
    key: 'wrapKey',
    value: function wrapKey(toBeWrappedKey, keySize, exportType) {
      var _this = this;

      var iv = window.crypto.getRandomValues(new Uint8Array(12));
      return this.checkRaw(this, this.key).then(function (instanceKey) {
        return crypto.subtle.wrapKey(exportType || 'raw', toBeWrappedKey, instanceKey, {
          name: _this.mode || 'aes-gcm',
          iv: iv,
          additionalData: utils.toArray('')
        });
      }).then(function (wrappedKey) {
        return {
          encryptedMasterKey: new Uint8Array(wrappedKey),
          iv: iv,
          keySize: keySize || 128
        };
      });
    }

    /**
    * Unwrap the given key. All cipher context information of the wrapping key
    * have been initialized at object creation (default or parameter)
    *
    * @param {Uint8array} wrappedKey - The wrapped key
    * @param {Uint8Array} iv - The iv
    * @param {Uint8Array} keySize - The size of the unwrapped key (same as before wrapping)
    * @param {string} [importType] - The import format of the wrappedKey, must be the same as in wrap.
    * @returns {CryptoKey} - The decrypted input
    */

  }, {
    key: 'unwrapKey',
    value: function unwrapKey(wrappedKey, iv, keySize, importType) {
      var _this2 = this;

      return this.checkRaw(this, this.key).then(function (instanceKey) {
        return crypto.subtle.unwrapKey(importType || 'raw', wrappedKey, instanceKey, {
          name: _this2.mode || 'aes-gcm',
          iv: iv,
          additionalData: utils.toArray('')
        }, {
          name: _this2.mode || 'aes-gcm',
          length: keySize || 128
        }, true, ['encrypt', 'decrypt']);
      });
    }
  }, {
    key: 'additionalData',
    get: function get() {
      return this._additionalData;
    },
    set: function set(newAdditionalData) {
      if (typeof newAdditionalData === 'string') {
        this._additionalData = newAdditionalData;
      } else {
        throw new Error("You did not provide a string for additional data, default value is ''.");
      }
    }
  }, {
    key: 'key',
    get: function get() {
      return this._key;
    },
    set: function set(newKey) {
      this._key = newKey;
    }
  }, {
    key: 'mode',
    get: function get() {
      return this._mode;
    },
    set: function set(newMode) {
      if (acceptedMode.includes(newMode)) {
        this._mode = newMode;
      } else {
        throw new Error('Accepted modes are ' + acceptedMode.join(', '));
      }
    }
  }, {
    key: 'keySize',
    get: function get() {
      return this._keySize;
    },
    set: function set(newKeySize) {
      if (acceptedKeySize.includes(newKeySize)) {
        this._keySize = newKeySize;
      } else {
        throw new Error('Accepted keySize are ' + acceptedKeySize.join(', '));
      }
    }
  }]);

  return AES;
}();

module.exports.AES = AES;
module.exports.aesModes = aesModes;
},{"./utils.js":5}],2:[function(require,module,exports){
'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/* global crypto */

var acceptedCurve = ['P-256', 'P-384', 'P-521'];
var acceptedAlgName = ['ECDH', 'ECDSA'];

/**
 * Elliptic Curve
 * @constructor
 * @param {Object} params - The EC cipher parameters
 * @param {string} params.name - The algorithm name ("ECDH" or "ECDSA")
 * @param {string} [params.hash] - The hash function (sign/verif). Default : "SHA-256", possible values: "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
 * @param {string} [params.curve] - The elliptic curve ("P-256", "P-384", or "P-521")
 */

var EC = function () {
  function EC(params) {
    _classCallCheck(this, EC);

    this.name = params.name || 'ECDH';
    this.curve = params.curve || 'P-384';
    this.hash = params.hash || 'SHA-256';
    this.publicKey = null;
    this.privateKey = null;
  }

  _createClass(EC, [{
    key: 'genECKeyPair',


    /**
     * Generate an EC key pair and store them in the class instance
     *
     * @returns {CryptoKey} - The generated EC key Pair as CryptoKey
     */
    value: function genECKeyPair() {
      var _this = this;

      return crypto.subtle.generateKey({
        name: this.name,
        namedCurve: this.curve
      }, false, this.name === 'ECDH' ? ['deriveKey', 'deriveBits'] : ['sign', 'verify']).then(function (cryptoKey) {
        _this.publicKey = cryptoKey.publicKey;
        _this.privateKey = cryptoKey.privateKey;
        return cryptoKey;
      }).catch(function (err) {
        if (err.code === 9) {
          throw new Error('WebCrypto API error :\n - During ECDH key generation: given namedCurve parameter is not accepted');
        } else {
          throw new Error(err);
        }
      });
    }

    /**
    * Check the received key format (CryptoKey or raw key).
    * If raw, import the key and return the CryptoKey
    *
    * @param {obj} obj - Save this in obj
    * @param {CryptoKey|arrayBuffer} key - The key
    * @returns {CryptoKey|arrayBuffer} - The CryptoKey
    */

  }, {
    key: 'checkRaw',
    value: function checkRaw(obj, key) {
      return new Promise(function (resolve, reject) {
        if (key instanceof Uint8Array) {
          obj.importKeyRaw(key).then(resolve);
        } else {
          resolve(key);
        }
      });
    }

    /**
     * Derive  key (AES-GCM by default) during ECDH key exchange
     * The private EC key is already in EC.privateKey
     *
     * @param {Cryptokey|arrayBuffer} publicKey Public Key of the sender (verified)
     * @param {string} type Key type of the derived key (aes-cbc, aes-gcm)
     * @param {int} keySize Key size of the derived key in bits (128, 192, 256)
     * @param {CryptoKey} [privateKey] The EC private key if not generated via genECKeyPair
     * @returns {arrayBuffer} The derived key
     */

  }, {
    key: 'deriveKeyECDH',
    value: function deriveKeyECDH(publicKey) {
      var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'aes-gcm';

      var _this2 = this;

      var keySize = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 128;
      var privateKey = arguments[3];

      return this.checkRaw(this, publicKey).then(function (key) {
        return crypto.subtle.deriveKey({
          name: _this2.name,
          public: key
        }, privateKey || _this2.privateKey, {
          name: type,
          length: keySize
        }, true, ['decrypt', 'encrypt']);
      }).then(function (derivedKey) {
        return crypto.subtle.exportKey('raw', derivedKey);
      }).then(function (rawKey) {
        return new Uint8Array(rawKey);
      });
    }

    /**
     * Export raw key
     * The public key is already stored in EC.publicKey
     *
     * {CryptoKey} key - The key that we extract raw value (available in EC.publicKey)
     * @returns {arrayBuffer} The raw key
     */

  }, {
    key: 'exportKeyRaw',
    value: function exportKeyRaw(key) {
      return crypto.subtle.exportKey('raw', key || this.publicKey).then(function (rawKey) {
        return new Uint8Array(rawKey);
      });
    }

    /**
     * Import raw key
     *
     * @param {CryptoKey} key - The key that we extract raw value
     * @param {String} curve - The elliptic curve used at the imported key creation
     * @returns {Promise} - The CryptoKey
     */

  }, {
    key: 'importKeyRaw',
    value: function importKeyRaw(key, curve, algName) {
      return crypto.subtle.importKey('raw', key, {
        name: algName || this.name,
        namedCurve: curve || this.curve
      }, true, []);
    }

    /**
     * Sign data
     * EC private key could be already stored in EC.privateKey
     *
     * @param {arrayBuffer} data - The data to be signed
     * @param {CryptoKey} privateKey - The private key (if nt sotred in EC class)
     * @param {String} [hash] - The hash function used for signature. Default 'SHA-256'
     * @returns {arrayBuffer} - The signature
     */

  }, {
    key: 'signEC',
    value: function signEC(data, privateKey, hash) {
      return crypto.subtle.sign({
        name: 'ECDSA',
        hash: { name: hash || this.hash }
      }, privateKey || this.privateKey, data).then(function (signature) {
        return new Uint8Array(signature);
      });
    }

    /**
     * Verif signature
     *
     * @param {CryptoKey} publicKey - The public RSA Key used to verify data signature
     * @param {arrayBuffer} signature - The signature
     * @param {arrayBuffer} signedData - Signed data
     * @param {String} [hash] - The hash function used for signature. Default 'SHA-256'
     * @returns {boolean} - Result
     */

  }, {
    key: 'verifEC',
    value: function verifEC(publicKey, signature, signedData, hash) {
      return crypto.subtle.verify({
        name: 'ECDSA',
        hash: { name: hash || this.hash }
      }, publicKey, signature, signedData);
    }
  }, {
    key: 'curve',
    get: function get() {
      return this._curve;
    },
    set: function set(newCurve) {
      if (acceptedCurve.includes(newCurve)) {
        this._curve = newCurve;
      } else {
        throw new Error('Accepted curves are ' + acceptedCurve.join(', '));
      }
    }
  }, {
    key: 'name',
    get: function get() {
      return this._name;
    },
    set: function set(newName) {
      if (acceptedAlgName.includes(newName)) {
        this._name = newName;
      } else {
        throw new Error('Accepted names are ' + acceptedAlgName.join(', '));
      }
    }
  }]);

  return EC;
}();

module.exports.EC = EC;
},{}],3:[function(require,module,exports){
'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/* global crypto */

/**
 * RSA
 * @constructor
 * @param {Object} params - The RSA cipher parameters
 * @param {string} params.hash The hash function ("SHA-256", "SHA-384", "SHA-512")
 * @param {string} params.name The algorithm name  ("RSA-PSS")
 * @param {string} params.modulusLength - The modulus length (4096 default)
 */
var RSA = function () {
  function RSA(params) {
    _classCallCheck(this, RSA);

    this.modulusLength = params.modulusLength || 4096;
    this.hash = params.hash || 'SHA-256';
    this.name = params.name || 'RSA-PSS';
    this.publicKey = null;
    this.privateKey = null;
  }

  _createClass(RSA, [{
    key: 'genRSAKeyPair',


    /**
     * Generate a RSA-PSS key pair for signature and verification
     *
     * @param {int} modulusLength - The modulus length (1024, 2048 or 4096)
     * @returns {Promise} - The RSA key pair : publicKey and privateKey
     */
    value: function genRSAKeyPair() {
      var _this = this;

      var modulusLength = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 4096;

      return crypto.subtle.generateKey({
        name: 'RSA-PSS',
        modulusLength: modulusLength, // can be 1024, 2048, or 4096
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {
          name: 'SHA-256'
        }
      }, false, ['sign', 'verify']).then(function (cryptoKey) {
        _this._publicKey = cryptoKey.publicKey;
        _this._privateKey = cryptoKey.privateKey;
        return cryptoKey;
      });
    }

    /**
     * Verif data (e.g. raw EC public key in case of ECDH)
     *
     * @param {CryptoKey} publicKey - The public RSA Key used to verify data signature
     * @param {arrayBuffer} signature - The signature
     * @param {arrayBuffer} signedData - Signed data
     * @returns {boolean} - Result
     */

  }, {
    key: 'verifRSA',
    value: function verifRSA(publicKey, signature, signedData) {
      return crypto.subtle.verify({
        name: 'RSA-PSS',
        saltLength: 16
      }, publicKey, signature, signedData);
    }

    /**
     * Sign data (e.g. raw EC public key in case of ECDH)
     * RSA private key is already stored in RSA.privateKey
     *
     * @param {arrayBuffer} data - The data to be signed
     * @param {CryptoKey} privateKey - The private key (if nt sotred in RSA class)
     * @returns {arrayBuffer} - The signature
     */

  }, {
    key: 'signRSA',
    value: function signRSA(data, privateKey) {
      return crypto.subtle.sign({
        name: 'RSA-PSS',
        saltLength: 16
      }, privateKey || this.privateKey, data).then(function (signature) {
        return new Uint8Array(signature);
      });
    }

    /**
     * Import RSA-PSS public key
     *
     * @param {jwk} key - The key (jwk format) that we want to import
     * @param {jwk} name - The algorithm name of the imported RSA key (default : "RSA-PSS")
     * @param {jwk} hash - The hash name of the imported RSA key (default : "SHA-256")
     * @returns {Promise} - The imported key as CryptoKey
     */

  }, {
    key: 'importRSAPubKeyRaw',
    value: function importRSAPubKeyRaw(key, name, hash) {
      return crypto.subtle.importKey('jwk', {
        kty: key.kty,
        e: key.e,
        n: key.n,
        alg: key.alg,
        ext: key.ext
      }, {
        name: name || 'RSA-PSS',
        hash: {
          name: hash || 'SHA-256'
        }
      }, false, ['verify']);
    }

    /**
     * Export RSA-PSS public raw key
     *
     * @param {CryptoKey} key - The key that we extract raw value
     * @returns {Promise} - The raw key
     */

  }, {
    key: 'exportRSAPubKeyRaw',
    value: function exportRSAPubKeyRaw(key, format) {
      return crypto.subtle.exportKey(format || 'jwk', key || this.publicKey);
    }
  }, {
    key: 'publicKey',
    get: function get() {
      return this._publicKey;
    }
  }, {
    key: 'privateKey',
    get: function get() {
      return this._privateKey;
    }
  }]);

  return RSA;
}();

module.exports.RSA = RSA;
},{}],4:[function(require,module,exports){
'use strict';

var _AES = require('./AES');

var _AES2 = _interopRequireDefault(_AES);

var _EC = require('./EC');

var _EC2 = _interopRequireDefault(_EC);

var _RSA = require('./RSA');

var _RSA2 = _interopRequireDefault(_RSA);

var _utils = require('./utils');

var _utils2 = _interopRequireDefault(_utils);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

module.exports.AES = _AES2.default.AES;
module.exports.aesModes = _AES2.default.aesModes;
module.exports.EC = _EC2.default.EC;
module.exports.RSA = _RSA2.default.RSA;
module.exports.utils = _utils2.default;
},{"./AES":1,"./EC":2,"./RSA":3,"./utils":5}],5:[function(require,module,exports){
'use strict';

/* global crypto */

/**
 * Convert ascii to ArrayBufffer
 * ex : "bonjour" -> Uint8Array [ 98, 111, 110, 106, 111, 117, 114 ]
 *
 * @param {String} str
 * @returns {ArrayBuffer}
 */
var toArray = function toArray() {
  var str = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';

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
  }, typeof passPhrase === 'string' ? toArray(msg) : msg).then(function (digest) {
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
},{}]},{},[4])(4)
});
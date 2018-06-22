'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/* global crypto */

/**
 * Print error messages
 *
 * @param {Error} err Error message
 */
var logFail = function logFail(err) {
  console.log(err);
  console.log(err.code);
};

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
      var self = this;
      return crypto.subtle.generateKey({
        name: this.name,
        namedCurve: this.curve
      }, false, this.name === 'ECDH' ? ['deriveKey', 'deriveBits'] : ['sign', 'verify']).then(function (cryptoKey) {
        self.publicKey = cryptoKey.publicKey;
        self.privateKey = cryptoKey.privateKey;
        return cryptoKey;
      }).catch(function (err) {
        switch (err.code) {
          case 9:
            console.log('WebCrypto API error :\n - During ECDH key generation: given namedCurve parameter is not accepted');
            break;
          default:
            console.log(err);
            break;
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
          obj.importKeyRaw(key).then(resolve).catch(logFail);
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

      var _this = this;

      var keySize = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 128;
      var privateKey = arguments[3];

      return this.checkRaw(this, publicKey).then(function (key) {
        return crypto.subtle.deriveKey({
          name: _this.name,
          public: key
        }, privateKey || _this.privateKey, {
          name: type,
          length: keySize
        }, true, ['decrypt', 'encrypt']);
      }).then(function (derivedKey) {
        return crypto.subtle.exportKey('raw', derivedKey);
      }).then(function (rawKey) {
        return new Uint8Array(rawKey);
      }).catch(logFail);
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
      }).catch(logFail);
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
      }).catch(logFail);
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
        console.log(newCurve + ' is not accepted.');
        console.log('Accepted curves are ' + acceptedCurve.join(', '));
        this._curve = newCurve;
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
        console.log(newName + ' is not accepted.');
        console.log('Accepted names are ' + acceptedAlgName.join(', '));
        this._name = newName;
      }
    }
  }]);

  return EC;
}();

module.exports.EC = EC;
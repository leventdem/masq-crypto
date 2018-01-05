
/**
 * Print error messages
 *
 * @param {Error} err Error message
 */
const logFail = (err) => {
  console.log(err)
}

/**
 * Elliptic Curve
 * @constructor
 * @param {Object} EC_params - The EC cipher parameters
 * @param {string} EC_params.curve - The elliptic curve ("P-256", "P-384", or "P-521")
 */
function EC({ curve }) {
  this.curve = curve || 'P-256'
  this.public = null
  this.private = null
}

/**
 * Generate an EC key pair and store them in the class instance
 *
 * @param {string} curve - The chosen Elliptic curve ("P-256", "P-384", or "P-521")
 * @returns {CryptoKey} - The generated EC key Pair as CryptoKey
 */
EC.prototype.genECKeyPair = function () {
  let self = this
  return crypto.subtle.generateKey({
    name: 'ECDH',
    namedCurve: this.curve
  }, false, ['deriveKey', 'deriveBits'])
    .then(cryptoKey => {
      self.public = cryptoKey.publicKey
      self.private = cryptoKey.privateKey
      return cryptoKey
    })
    .catch(logFail)
}

/**
 * Check the received key format (CryptoKey or raw key).
 * If raw, import the key and return the CryptoKey
 *
 * @param {obj} obj - A trick to call another prototype
 * @returns {CryptoKey|arrayBuffer} - The public key
 */
EC.prototype.checkRaw = function (obj, key) {
  return new Promise(function (resolve, reject) {
    if (key instanceof Uint8Array) {
      obj.importKeyRaw(key)
        .then(resolve)
        .catch(logFail)
    }
    else {
      resolve(key)
    }
  })
}

/**
 * Derive  key (AES-GCM by default) during ECDH key exchange
 * The private EC key is already in EC.private
 *
 * @param {Cryptokey|arrayBuffer} publicKey Public Key of the sender (verified) 
 * @param {object} privateKey Private Key of the receiver
 * @param {string} type Key type of the derived key (aes-cbc, aes-ctr)
 * @param {int} keySize Key size of the derived key in bits (128, 192, 256)
 * @returns {arrayBuffer} The derived key
 */
EC.prototype.deriveKeyECDH = function (publicKey, type = 'aes-gcm', keySize = 128) {
  return this.checkRaw(this, publicKey)
    .then(key => {  
      return crypto.subtle.deriveKey({
        name: 'ECDH',
        public: key
      }, this.private, {
          name: type,
          length: keySize
        }, true, ['decrypt', 'encrypt'])
    })
    .then(derivedKey => {
      return crypto.subtle.exportKey('raw', derivedKey)
    })
    .then(rawKey => new Uint8Array(rawKey))
    .catch(logFail)
}

/**
 * Export raw key
 * The public key is already stored in EC.public
 * 
 * {CryptoKey} key - The key that we extract raw value (available in EC.public)
 * @returns {arrayBuffer} The raw key
 */
EC.prototype.exportKeyRaw = function (key = null) {
  return crypto.subtle.exportKey('raw', key || this.public)
    .then(rawKey => new Uint8Array(rawKey))
    .catch(logFail)
}

/**
 * Import raw key
 *
 * @param {CryptoKey} key - The key that we extract raw value
 * @param {String} curve - The elliptic curve used at the imported key creation
 * @returns {Promise} - The CryptoKey
 */
EC.prototype.importKeyRaw = function (key, curve = 'P-256') {
  return crypto.subtle.importKey('raw', key, {
    name: 'ECDH',
    namedCurve: curve
  }, true, [])
}

module.exports = EC
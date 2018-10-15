/* global crypto */

/**
   * Verif data (e.g. raw EC public key in case of ECDH)
   *
   * @param {CryptoKey} publicKey - The public RSA Key used to verify data signature
   * @param {arrayBuffer} signature - The signature
   * @param {arrayBuffer} signedData - Signed data
   * @returns {boolean} - Result
   */
const verifRSA = (publicKey, signature, signedData) => {
  return crypto.subtle.verify({
    name: 'RSA-PSS',
    saltLength: 16
  }, publicKey, signature, signedData)
}

/**
   * Import RSA-PSS public key
   *
   * @param {jwk} key - The key (jwk format) that we want to import
   * @param {jwk} name - The algorithm name of the imported RSA key (default : "RSA-PSS")
   * @param {jwk} hash - The hash name of the imported RSA key (default : "SHA-256")
   * @returns {Promise} - The imported key as CryptoKey
   */
const importRSAPubKey = (key, name, hash) => {
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
  }, false, ['verify'])
}

/**
 * RSA
 * @constructor
 * @param {Object} params - The RSA cipher parameters
 * @param {string} params.hash The hash function ("SHA-256", "SHA-384", "SHA-512")
 * @param {string} params.name The algorithm name  ("RSA-PSS")
 * @param {string} params.modulusLength - The modulus length (4096 default)
 */
class RSA {
  constructor (params) {
    this.modulusLength = params.modulusLength || 4096
    this.hash = params.hash || 'SHA-256'
    this.name = params.name || 'RSA-PSS'
    this.publicKey = null
    this.privateKey = null
  }

  get publicKey () {
    return this._publicKey
  }

  get privateKey () {
    return this._privateKey
  }

  set publicKey (key) {
    this._publicKey = key
  }

  set privateKey (key) {
    this._privateKey = key
  }

  /**
   * Generate a RSA-PSS key pair for signature and verification
   *
   * @param {int} modulusLength - The modulus length (1024, 2048 or 4096)
   * @returns {Promise} - The RSA key pair : publicKey and privateKey
   */
  genRSAKeyPair (modulusLength = 4096) {
    return crypto.subtle.generateKey({
      name: 'RSA-PSS',
      modulusLength: modulusLength, // can be 1024, 2048, or 4096
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {
        name: 'SHA-256'
      }
    }, false, ['sign', 'verify'])
      .then(cryptoKey => {
        this._publicKey = cryptoKey.publicKey
        this._privateKey = cryptoKey.privateKey
        return cryptoKey
      })
  }

  /**
   * Verif data (e.g. raw EC public key in case of ECDH)
   *
   * @param {CryptoKey} publicKey - The public RSA Key used to verify data signature
   * @param {arrayBuffer} signature - The signature
   * @param {arrayBuffer} signedData - Signed data
   * @returns {boolean} - Result
   */
  verifRSA (publicKey, signature, signedData) {
    return verifRSA(publicKey, signature, signedData)
  }

  /**
   * Sign data (e.g. raw EC public key in case of ECDH)
   * RSA private key is already stored in RSA.privateKey
   *
   * @param {arrayBuffer} data - The data to be signed
   * @param {CryptoKey} privateKey - The private key (if nt sotred in RSA class)
   * @returns {arrayBuffer} - The signature
   */
  signRSA (data, privateKey) {
    return crypto.subtle.sign({
      name: 'RSA-PSS',
      saltLength: 16
    }, privateKey || this.privateKey, data)
      .then(signature => new Uint8Array(signature))
  }

  /**
   * Import RSA-PSS public key
   *
   * @param {jwk} key - The key (jwk format) that we want to import
   * @param {jwk} name - The algorithm name of the imported RSA key (default : "RSA-PSS")
   * @param {jwk} hash - The hash name of the imported RSA key (default : "SHA-256")
   * @returns {Promise} - The imported key as CryptoKey
   */
  importRSAPubKey (key, name, hash) {
    importRSAPubKey(key, name, hash).then(key => {
      this.publicKey = key
    })
  }

  /**
   * Export RSA-PSS public raw key
   * Do not forget to stringify the exported key to compute
   * its hash or to store it.
   *
   * @param {CryptoKey} key - The key that we extract raw value
   * @param {string} format - The format ([jwk], spki)
   * @returns {Promise<Object>} - The key
   */
  exportRSAPubKey (key, format) {
    return crypto.subtle.exportKey(format || 'jwk', key || this.publicKey)
  }
}
module.exports.RSA = RSA
module.exports.RSA.verifRSA = verifRSA
module.exports.RSA.importRSAPubKey = importRSAPubKey

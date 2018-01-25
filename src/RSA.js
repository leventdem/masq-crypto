
/**
 * Print error messages
 *
 * @param {Error} err Error message
 */
const logFail = (err) => {
  console.log(err)
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
  constructor(params) {
    this.modulusLength = params.modulusLength || 4096
    this.hash = params.hash || 'SHA-256'
    this.name = params.name || 'RSA-PSS'
    this.publicKey = null
    this.private = null
  }

  get publicKey() {
    return this._publicKey
  }

  /**
   * Set RSA-PSS keys
   *
   * @param {Cryptokey} keys - The public RSA key
   */
  set publicKey(newPublicKey) {
    this._publicKey = newPublicKey
  }

  get privateKey() {
    return this._privateKey
  }

  set privateKey(newPrivateKey) {
    this._privateKey = newPrivateKey
  }

  /**
   * Generate a RSA-PSS key pair for signature and verification
   *
   * @param {int} modulusLength - The modulus length (1024, 2048 or 4096)
   * @returns {Promise} - The RSA key pair : publicKey and privateKey
   */
  genRSAKeyPair(modulusLength = 4096) {
    let self = this
    return crypto.subtle.generateKey({
      name: 'RSA-PSS',
      modulusLength: modulusLength, // can be 1024, 2048, or 4096
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {
        name: 'SHA-256'
      }
    }, false, ['sign', 'verify'])
      .then(cryptoKey => {
        self.publicKey = cryptoKey.publicKey
        self.privateKey = cryptoKey.privateKey
        return cryptoKey
      })
      .catch(logFail)
  }

  /**
   * Verif data (e.g. raw EC public key in case of ECDH)
   *
   * @param {CryptoKey} publicKey - The public RSA Key used to verify data signature
   * @param {arrayBuffer} signature - The signature
   * @param {arrayBuffer} signedData - Signed data
   * @returns {boolean} - Result
   */
  verifRSA(publicKey, signature, signedData) {
    return crypto.subtle.verify({
      name: 'RSA-PSS',
      saltLength: 16
    }, publicKey, signature, signedData)
  }

  /**
   * Sign data (e.g. raw EC public key in case of ECDH)
   * RSA private key is already stored in RSA.privateKey
   *
   * @param {arrayBuffer} data - The data to be signed
   * @param {CryptoKey} privateKey - The private key (if nt sotred in RSA class)
   * @returns {arrayBuffer} - The signature
   */
  signRSA(data, privateKey) {
    return crypto.subtle.sign({
      name: 'RSA-PSS',
      saltLength: 16
    }, privateKey || this.privateKey, data)
      .then(signature => new Uint8Array(signature))
      .catch(logFail)
  }

  /**
   * Import RSA-PSS public key
   *
   * @param {jwk} key - The key (jwk format) that we want to import
   * @param {jwk} name - The algorithm name of the imported RSA key (default : "RSA-PSS")
   * @param {jwk} hash - The hash name of the imported RSA key (default : "SHA-256")
   * @returns {Promise} - The imported key as CryptoKey
   */
  importRSAPubKeyRaw(key, name, hash) {
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
   * Export RSA-PSS public raw key
   *
   * @param {CryptoKey} key - The key that we extract raw value
   * @returns {Promise} - The raw key
   */
  exportRSAPubKeyRaw(key, format) {
    return crypto.subtle.exportKey(format || 'jwk', key || this.publicKey)
  }
}
export default RSA
export {RSA}

/* global crypto */

const acceptedCurve = [
  'P-256',
  'P-384',
  'P-521'
]
const acceptedAlgName = [
  'ECDH',
  'ECDSA'
]

/**
 * Elliptic Curve
 * @constructor
 * @param {Object} params - The EC cipher parameters
 * @param {string} params.name - The algorithm name ("ECDH" or "ECDSA")
 * @param {string} [params.hash] - The hash function (sign/verif). Default : "SHA-256", possible values: "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
 * @param {string} [params.curve] - The elliptic curve ("P-256", "P-384", or "P-521")
 */
class EC {
  constructor (params) {
    this.name = params.name || 'ECDH'
    this.curve = params.curve || 'P-384'
    this.hash = params.hash || 'SHA-256'
    this.publicKey = null
    this.privateKey = null
  }

  get curve () {
    return this._curve
  }

  set curve (newCurve) {
    if (acceptedCurve.includes(newCurve)) {
      this._curve = newCurve
    } else {
      throw new Error(`Accepted curves are ${acceptedCurve.join(', ')}`)
    }
  }
  get name () {
    return this._name
  }

  set name (newName) {
    if (acceptedAlgName.includes(newName)) {
      this._name = newName
    } else {
      throw new Error(`Accepted names are ${acceptedAlgName.join(', ')}`)
    }
  }

  /**
   * Generate an EC key pair and store them in the class instance
   *
   * @returns {CryptoKey} - The generated EC key Pair as CryptoKey
   */
  genECKeyPair () {
    return crypto.subtle.generateKey({
      name: this.name,
      namedCurve: this.curve
    }, false, this.name === 'ECDH' ? ['deriveKey', 'deriveBits'] : ['sign', 'verify'])
      .then(cryptoKey => {
        this.publicKey = cryptoKey.publicKey
        this.privateKey = cryptoKey.privateKey
        return cryptoKey
      })
      .catch(err => {
        if (err.code === 9) {
          throw new Error('WebCrypto API error :\n - During ECDH key generation: given namedCurve parameter is not accepted')
        } else {
          throw new Error(err)
        }
      })
  }

  /**
  * Check the received key format (CryptoKey or raw key).
  * If raw, import the key and return the CryptoKey
  *
  * @param {obj} obj - Save this in obj
  * @param {CryptoKey|arrayBuffer} key - The key
  * @returns {CryptoKey|arrayBuffer} - The CryptoKey
  */
  checkRaw (obj, key) {
    return new Promise(function (resolve, reject) {
      if (key instanceof Uint8Array) {
        obj.importKeyRaw(key)
          .then(resolve)
      } else {
        resolve(key)
      }
    })
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
  deriveKeyECDH (publicKey, type = 'aes-gcm', keySize = 128, privateKey) {
    return this.checkRaw(this, publicKey)
      .then(key => {
        return crypto.subtle.deriveKey({
          name: this.name,
          public: key
        }, privateKey || this.privateKey, {
          name: type,
          length: keySize
        }, true, ['decrypt', 'encrypt'])
      })
      .then(derivedKey => {
        return crypto.subtle.exportKey('raw', derivedKey)
      })
      .then(rawKey => new Uint8Array(rawKey))
  }

  /**
   * Export raw key
   * The public key is already stored in EC.publicKey
   *
   * {CryptoKey} key - The key that we extract raw value (available in EC.publicKey)
   * @returns {arrayBuffer} The raw key
   */
  exportKeyRaw (key) {
    return crypto.subtle.exportKey('raw', key || this.publicKey)
      .then(rawKey => new Uint8Array(rawKey))
  }

  /**
   * Import raw key
   *
   * @param {CryptoKey} key - The key that we extract raw value
   * @param {String} curve - The elliptic curve used at the imported key creation
   * @returns {Promise} - The CryptoKey
   */
  importKeyRaw (key, curve, algName) {
    return crypto.subtle.importKey('raw', key, {
      name: algName || this.name,
      namedCurve: curve || this.curve
    }, true, [])
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
  signEC (data, privateKey, hash) {
    return crypto.subtle.sign({
      name: 'ECDSA',
      hash: { name: hash || this.hash }
    }, privateKey || this.privateKey, data)
      .then(signature => new Uint8Array(signature))
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
  verifEC (publicKey, signature, signedData, hash) {
    return crypto.subtle.verify({
      name: 'ECDSA',
      hash: { name: hash || this.hash }
    }, publicKey, signature, signedData)
  }
}
module.exports.EC = EC


/**
 * Print error messages
 *
 * @param {Error} err Error message
 */
const logFail = (err) => {
  console.log(err)
  console.log(err.code)
}

const acceptedCurve = [
  'P-256',
  'P-384',
  'P-521'
]

/**
 * Elliptic Curve
 * @constructor
 * @param {Object} params - The EC cipher parameters
 * @param {string} params.curve - The elliptic curve ("P-256", "P-384", or "P-521")
 */
class EC {
  constructor(params) {
    this.curve = params.curve || 'P-256'
    this.publicKey = null
    this.privateKey = null
  }

  get curve() {
    return this._curve
  }

  set curve(newCurve) {
    if (acceptedCurve.includes(newCurve)) {
      this._curve = newCurve
    } else {
      console.log(newCurve + ' is not accepted.')
      console.log(`Accepted curves are ${acceptedCurve.join(', ')}`)
      this._curve = newCurve
    }
  }

  /**
   * Generate an EC key pair and store them in the class instance
   *
   * @param {string} curve - The chosen Elliptic curve ("P-256", "P-384", or "P-521")
   * @returns {CryptoKey} - The generated EC key Pair as CryptoKey
   */
  genECKeyPair() {
    let self = this
    return crypto.subtle.generateKey({
      name: 'ECDH',
      namedCurve: this.curve
    }, false, ['deriveKey', 'deriveBits'])
      .then(cryptoKey => {
        self.publicKey = cryptoKey.publicKey
        self.privateKey = cryptoKey.privateKey
        return cryptoKey
      })
      .catch(err => {
        switch (err.code) {
          case 9:
            console.log('WebCrypto API error :\n - During ECDH key generation: given namedCurve parameter is not accepted')
            break;
          default:
            console.log(err)
            break;
        }
      })
  }

  /**
   * Check the received key format (CryptoKey or raw key).
   * If raw, import the key and return the CryptoKey
   *
   * @param {obj} obj - A trick to call another prototype
   * @returns {CryptoKey|arrayBuffer} - The public key
   */
  checkRaw(obj, key) {
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
   * The private EC key is already in EC.privateKey
   *
   * @param {Cryptokey|arrayBuffer} publicKey Public Key of the sender (verified) 
   * @param {object} privateKey Private Key of the receiver
   * @param {string} type Key type of the derived key (aes-cbc, aes-ctr)
   * @param {int} keySize Key size of the derived key in bits (128, 192, 256)
   * @returns {arrayBuffer} The derived key
   */
  deriveKeyECDH(publicKey, type = 'aes-gcm', keySize = 128) {
    return this.checkRaw(this, publicKey)
      .then(key => {
        return crypto.subtle.deriveKey({
          name: 'ECDH',
          public: key
        }, this.privateKey, {
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
   * The public key is already stored in EC.publicKey
   * 
   * {CryptoKey} key - The key that we extract raw value (available in EC.publicKey)
   * @returns {arrayBuffer} The raw key
   */
  exportKeyRaw(key = null) {
    return crypto.subtle.exportKey('raw', key || this.publicKey)
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
  importKeyRaw(key, curve = 'P-256') {
    return crypto.subtle.importKey('raw', key, {
      name: 'ECDH',
      namedCurve: curve
    }, true, [])
  }
}
export default EC

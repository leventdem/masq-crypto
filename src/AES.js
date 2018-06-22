/* global crypto */
import * as utils from './utils.js'

/**
 * Print error messages
 *
 * @param {Error} err Error message
 */
const logFail = (err) => {
  console.log(err)
}

const aesModes = {
  CBC: 'aes-cbc',
  GCM: 'aes-gcm',
  CTR: 'aes-ctr'
}

const acceptedMode = [
  'aes-cbc',
  'aes-gcm',
  'aes-ctr'
]

const acceptedKeySize = [128, 192, 256]

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
const decryptBuffer = (data, key, cipherContext) => {
  // TODO: test input params
  return crypto.subtle.decrypt(cipherContext, key, data)
    .then(result => new Uint8Array(result))
    .catch(logFail)
}

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
const encryptBuffer = (data, key, cipherContext) => {
  return crypto.subtle.encrypt(cipherContext, key, data)
    .then(result => new Uint8Array(result))
    .catch(logFail)
}
/**
 * AES cipher
 * @constructor
 * @param {Object} params - The AES cipher parameters
 * @param {string} [params.mode] - The encryption mode : aes-gcm, aes-cbc
 * @param {ArrayBuffer} [params.key] - The AES CryptoKey
 * @param {number} [params.keySize] - The key size in bits (128, 192, 256)
 * @param {number} [params.iv] - The IV, if not provided it will be generated randomly
 * @param {string} [params.additionalData] - The authenticated data, only for aes-gcm mode.
 */
class AES {
  constructor (params) {
    this.mode = params.mode || 'aes-gcm'
    this.keySize = params.keySize || 128
    this.IV = params.iv || null
    this.key = params.key || null
    this.length = params.length || 128
    this.additionalData = params.additionalData || ''
  }

  get additionalData () {
    return this._additionalData
  }

  set additionalData (newAdditionalData) {
    if (typeof newAdditionalData === 'string') {
      this._additionalData = newAdditionalData
    } else {
      console.log("You did not provide a string for additional data, default value is ''.")
      this._additionalData = ''
    }
  }

  /**
 * Check the received key format (CryptoKey or raw key).
 * If raw, import the key and return the CryptoKey
 *
 * @param {obj} obj - Save this in obj
 * @returns {CryptoKey|arrayBuffer} - The CryptoKey
 */
  checkRaw (obj, key) {
    return new Promise((resolve, reject) => {
      if (key instanceof Uint8Array) {
        obj.importKeyRaw(key)
          .then(resolve)
          .catch(err => console.log(err))
      } else {
        resolve(key)
      }
    })
  }

  /**
  * Transform a CryptoKey into a raw key
  *
  * @param {CryptoKey} key - The CryptoKey
  * @returns {arrayBuffer} - The raw key
  */
  exportKeyRaw (key, type = 'raw') {
    return crypto.subtle.exportKey(type, key)
      .then(key => new Uint8Array(key))
      .catch(err => console.log(err))
  }

  /**
* Transform a raw key into a CryptoKey
*
* @param {arrayBuffer} key - The key we want to import
* @returns {CryptoKey} - The CryptoKey
*/
  importKeyRaw (key, type = 'raw') {
    return crypto.subtle.importKey(type, key, {
      name: this.mode
    }, true, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'])
  }

  get key () {
    return this._key
  }

  set key (newKey) {
    this._key = newKey
  }

  get mode () {
    return this._mode
  }

  set mode (newMode) {
    if (acceptedMode.includes(newMode)) {
      this._mode = newMode
    } else {
      console.log(newMode + ' is not accepted.')
      console.log(`Accepted modes are ${acceptedMode.join(', ')}`)
      console.log(`Default mode is 'aes-gcm'.`)
      this._mode = 'aes-gcm'
    }
  }

  get keySize () {
    return this._keySize
  }

  set keySize (newKeySize) {
    if (acceptedKeySize.includes(newKeySize)) {
      this._keySize = newKeySize
    } else {
      console.log(newKeySize + ' is not accepted.')
      console.log(`Accepted keySize are ${acceptedKeySize.join(', ')}`)
      console.log(`Default keySize is '128'.`)
      this._keySize = 128
    }
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
  decrypt (input) {
    // Prepare context, all modes have at least one property : ciphertext
    let context = {}
    let cipherContext = {}
    let self = this
    context.ciphertext = input.hasOwnProperty('ciphertext') ? utils.hexStringToBuffer(input.ciphertext) : ''
    if (this.mode === 'aes-gcm') {
      context.iv = input.hasOwnProperty('iv') ? utils.hexStringToBuffer(input.iv) : ''
      // aes-gcm may have an additional authenticated data property (optional)
      context.additionalData = input.hasOwnProperty('version') ? utils.toArray(input.version) : []
      // Prepare cipher context, depends on cipher mode
      cipherContext.name = this.mode
      cipherContext.iv = context.iv
      cipherContext.additionalData = context.additionalData
      // This function test the given key and return the Cryptokey
      return this.checkRaw(self, this.key)
        .then(key => {
          return decryptBuffer(context.ciphertext, key, cipherContext)
        })
        .then(res => utils.toString(res))
        .catch(logFail)
    } else if (this.mode === 'aes-cbc') {
      // IV is 128 bits long === 16 bytes
      context.iv = input.hasOwnProperty('iv') ? utils.hexStringToBuffer(input.iv) : ''
      // Prepare cipher context, depends on cipher mode
      cipherContext.name = this.mode
      cipherContext.iv = context.iv
      return this.checkRaw(self, this.key)
        .then(key => {
          return decryptBuffer(context.ciphertext, key, cipherContext)
        })
        .then(res => utils.toString(res))
        .catch(logFail)
    } else if (this.mode === 'aes-ctr') {
      // IV is 128 bits long === 16 bytes
      context.iv = input.hasOwnProperty('iv') ? utils.hexStringToBuffer(input.iv) : ''
      // Prepare cipher context, depends on cipher mode
      cipherContext.name = this.mode
      cipherContext.counter = context.iv
      cipherContext.length = this.length
      return this.checkRaw(self, this.key)
        .then(key => {
          return decryptBuffer(context.ciphertext, key, cipherContext)
        })
        .then(res => utils.toString(res))
        .catch(logFail)
    } else {
      console.log(`The mode ${this.mode} is not yet supported`)
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
  encrypt (input) {
    // all modes have at least the plaintext
    let context = {}
    let cipherContext = {}
    let self = this
    context.plaintext = utils.toArray(input)
    if (this.mode === 'aes-gcm') {
      // IV is 96 bits long === 12 bytes
      context.iv = this.iv || window.crypto.getRandomValues(new Uint8Array(12))
      context.additionalData = utils.toArray(this.additionalData)
      // Prepare cipher context, depends on cipher mode
      cipherContext.name = this.mode
      cipherContext.iv = context.iv
      cipherContext.additionalData = context.additionalData
      // This function tests the given key and return the Cryptokey
      return this.checkRaw(self, this.key)
        .then(key => {
          return encryptBuffer(context.plaintext, key, cipherContext)
        })
        .then(result => {
          return {
            ciphertext: utils.bufferToHexString(result),
            iv: utils.bufferToHexString(context.iv),
            version: utils.toString(context.additionalData)
          }
        })
        .catch(logFail)
    } else if (this.mode === 'aes-cbc') {
      // IV is 128 bits long === 16 bytes
      context.iv = this.iv || window.crypto.getRandomValues(new Uint8Array(16))
      // Prepare cipher context, depends on cipher mode
      cipherContext.name = this.mode
      cipherContext.iv = context.iv
      return this.checkRaw(self, this.key)
        .then(key => {
          return encryptBuffer(context.plaintext, key, cipherContext)
        })
        .then(result => {
          return {
            ciphertext: utils.bufferToHexString(result),
            iv: utils.bufferToHexString(context.iv)
          }
        })
        .catch(logFail)
    } else if (this.mode === 'aes-ctr') {
      // IV is 128 bits long === 16 bytes
      context.iv = this.iv || window.crypto.getRandomValues(new Uint8Array(16))
      // Prepare cipher context, depends on cipher mode
      cipherContext.name = this.mode
      cipherContext.counter = context.iv
      cipherContext.length = this.length
      return this.checkRaw(self, this.key)
        .then(key => {
          return encryptBuffer(context.plaintext, key, cipherContext)
        })
        .then(result => {
          return {
            ciphertext: utils.bufferToHexString(result),
            iv: utils.bufferToHexString(context.iv)
          }
        })
        .catch(logFail)
    } else {
      console.log(`The mode ${this.mode} is not yet supported`)
    }
  }

  /**
   * Generate an AES key based on the cipher mode and keysize
   * Cipher mode and key size are initialized at cipher AES instance creation.
   *
   * @returns {CryptoKey} - The generated AES key.
   */
  genAESKey () {
    return crypto.subtle.generateKey({
      name: this.mode || 'aes-gcm',
      length: this.keySize || 128
    }, true, ['decrypt', 'encrypt'])
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
  wrapKey (toBeWrappedKey, keySize, exportType) {
    let iv = window.crypto.getRandomValues(new Uint8Array(12))
    let self = this
    return this.checkRaw(self, this.key)
      .then(instanceKey => {
        return crypto.subtle.wrapKey(exportType || 'raw',
          toBeWrappedKey,
          instanceKey,
          {
            name: this.mode || 'aes-gcm',
            iv: iv,
            additionalData: utils.toArray('')
          })
      })
      .then(wrappedKey => {
        return {
          encryptedMasterKey: new Uint8Array(wrappedKey),
          iv: iv,
          keySize: keySize || 128
        }
      })
      .catch(logFail)
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
  unwrapKey (wrappedKey, iv, keySize, importType) {
    let self = this

    return this.checkRaw(self, this.key)
      .then(instanceKey => {
        return crypto.subtle.unwrapKey(importType || 'raw',
          wrappedKey,
          instanceKey,
          {
            name: this.mode || 'aes-gcm',
            iv: iv,
            additionalData: utils.toArray('')
          },
          {
            name: this.mode || 'aes-gcm',
            length: keySize || 128
          },
          true,
          ['encrypt', 'decrypt'])
      })
      .catch(err => console.log(err))
  }
}
module.exports.AES = AES
module.exports.aesModes = aesModes

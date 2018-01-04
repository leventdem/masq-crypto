import utils from './utils'
// @ts-check

/**
 * Print error messages
 *
 * @param {Error} err Error message
 */
const logFail = (err) => {
  console.log(err)
}

/**
 * Decrypt data with AES-GCM cipher
 *
 * @param {ArrayBuffer} data Data to decrypt
 * @param {ArrayBuffer} key Aes key as raw data. 128 or 256 bits
 * @param {ArrayBuffer} iv The IV with a size of 96 bits (12 bytes)
 * @param {string} mode The encryption mode : AES-GCM
 * @param {ArrayBuffer} additionalData The non-secret authenticated data
 * @returns {ArrayBuffer} The decrypted buffer
 */
const decryptBuffer = (data, key, iv, mode, additionalData) => {
  // TODO: test input params
  return crypto.subtle.importKey('raw', key, {
    name: mode
  }, true, ['encrypt', 'decrypt']).then(function (bufKey) {
    return crypto.subtle.decrypt({
      name: mode,
      iv,
      additionalData: additionalData
    }, bufKey, data).then(function (result) {
      return new Uint8Array(result)
    }, logFail)
  }, logFail)
}

/**
 * Encrypt data with AES-GCM cipher
 *
 * @param {ArrayBuffer} data Data to encrypt
 * @param {ArrayBuffer} key Aes key as raw data. 128 or 256 bits
 * @param {ArrayBuffer} iv The IV with a size of 96 bits (12 bytes)
 * @param {string} mode The encryption mode : AES-GCM
 * @param {ArrayBuffer} additionalData The non-secret authenticated data
 * @returns {ArrayBuffer} The encrypted buffer
 */
const encryptBuffer = (data, key, iv, mode, additionalData) => {
  return crypto.subtle.importKey('raw', key, {
    name: mode
  }, true, ['encrypt', 'decrypt'])
    .then(bufKey => {
      return crypto.subtle.encrypt({
        name: mode,
        iv,
        additionalData
      }, bufKey, data)
    })
    .then(result => new Uint8Array(result))
    .catch(logFail)
}
/**
 * AES cipher 
 * @constructor
 * @param {Object} AES_params - The AES cipher parameters
 * @param {string} AES_params.mode - The encryption mode : aes-gcm, aes-cbc
 * @param {ArrayBuffer} AES_params.key - Aes key as raw data. 128 or 256 bits
 * @param {number} params.keySize - The key size in bits (128, 192, 256)
 * @param {string} [AES_params.additionalData] - Tee authenticated data, only for aes-gcm mode.
 */
function AES({ mode, key, keySize, additionalData }) {
  this.mode = mode || 'aes-gcm'
  this.keySize = keySize || 128
  this.IV = null
  this.key = key || null
  this.additionalData = additionalData || ''
}

AES.prototype.setMode = function (mode) {
  this.mode = mode
}

AES.prototype.setKey = function (key) {
  this.key = key
}
AES.prototype.setAdditionalData = function (additionalData) {
  this.additionalData = additionalData
}

AES.prototype.decrypt = function (input) {
  // Prepare context, all modes have at least 2 properties : iv and ciphertext
  let context = {}
  context.iv = input.hasOwnProperty('iv') ? utils.hexStringToBuffer(input.iv) : ''
  context.ciphertext = input.hasOwnProperty('ciphertext') ? utils.hexStringToBuffer(input.ciphertext) : ''
  if (this.mode === 'aes-gcm') {
    // aes-gcm may have an additional authenticated data property (optional)
    context.additionalData = input.hasOwnProperty('version') ? utils.toArray(input.version) : []

    return decryptBuffer(context.ciphertext, this.key, context.iv, this.mode, context.additionalData)
      .then(res => utils.toString(res))
      .catch(logFail)
  } else {
    console.log(`The mode ${this.mode} is not yet supported`)
  }
}

AES.prototype.encrypt = function (input) {
  // all modes have at least the plaintext
  let context = {}
  context.plaintext = utils.toArray(input)
  if (this.mode === 'aes-gcm') {
    // IV is 96 bits long === 12 bytes
    context.iv = this.iv || window.crypto.getRandomValues(new Uint8Array(12))
    context.additionalData = utils.toArray(this.additionalData)

    return encryptBuffer(context.plaintext, this.key, context.iv, this.mode, context.additionalData)
      .then(result => {
        return {
          ciphertext: utils.bufferToHexString(result),
          iv: utils.bufferToHexString(context.iv),
          version: utils.toString(context.additionalData)
        }
      })
      .catch(logFail)
  } else {
    console.log(`The mode ${this.mode} is not yet supported`)
  }
}

/**
 * Generate an AES key based on the cipher mode and keysize
 *
 * @returns {CryptoKey} - The generated AES key.
 */
AES.prototype.genAESKey = function () {
  return crypto.subtle.generateKey({
    name: this.mode || 'aes-gcm',
    length: this.keySize || 128
  }, true, ['decrypt', 'encrypt'])
}
module.exports = AES

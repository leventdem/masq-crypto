
var cipherContext = {
  userKey: null,
  derivedKey: null
}

/**
 * Set the userKey and derivedKey
 *
 * @param {string} key The user key is generated at install or retrived from local storage
 * @returns {ArrayBuffer}
 */
function setUserKey (key) {
  if (key === '' || key === null) { cipherContext.key = randomString(18) }
  // TODO : key could be retrieved from localstorage
  else { cipherContext.key = key }
  cipherContext.key = asciiToUint8Array(cipherContext.key)

  // set derivedKey based on userKey
  console.log('key', cipherContext.key)
  return PBKDF2(cipherContext.key).then(function (result) {
    cipherContext.derivedKey = result
    console.log('derivedKey', cipherContext.derivedKey)
  })
}

/**
 * Derivation of key based on PBKDF2
 *
 * @param {ArrayBuffer} key The user key
 * @returns {ArrayBuffer}
 */
function PBKDF2 (key) {
  // var rawSalt = document.getElementById('salt').value
  var rawSalt = ''
  var salt = new Uint8Array(rawSalt)

  return crypto.subtle.importKey('raw', key, 'PBKDF2', false, ['deriveBits', 'deriveKey']).then(function (baseKey) {
    return crypto.subtle.deriveBits({name: 'PBKDF2', salt: salt, iterations: 10000, hash: 'sha-256'}, baseKey, 128)
  }, failAndLog).then(function (derivedKey) {
    return new Uint8Array(derivedKey)
  }, failAndLog)
}

// Generate a random string using the Webwindow API instead of Math.random (insecure)
function randomString (length) {
  var charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  var result = ''
  if (window.crypto && window.crypto.getRandomValues) {
    values = new Uint32Array(length)
    window.crypto.getRandomValues(values)
    for (var i = 0; i < length; i++) {
      result += charset[values[i] % charset.length]
    }
  } else {
    console.log("Your browser can't generate secure random numbers")
  }
  return result
}

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
function decrypt (data, key, iv, mode, additionalData) {
  return crypto.subtle.importKey('raw', key, {name: mode}, true, ['encrypt', 'decrypt']).then(function (bufKey) {
    return crypto.subtle.decrypt({name: mode, iv, additionalData: additionalData}, bufKey, data).then(function (result) {
      return new Uint8Array(result)
    }, failAndLog)
  }, failAndLog)
}

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
function encrypt (data, key, iv, mode, additionalData) {
  return crypto.subtle.importKey('raw', key, {name: mode}, true, ['encrypt', 'decrypt']).then(function (bufKey) {
    console.log(bufKey)
    return crypto.subtle.encrypt({name: mode, iv, additionalData: additionalData}, bufKey, data).then(function (result) {
      return new Uint8Array(result)
    }, failAndLog)
  }, failAndLog)
}

/**
 * Encrypt an object
 *
 * @param {object} data Basic key-pair values
 * @param {string} additionalData The authenticated data (ex. version number :1.0.1 )
 * @returns {object} Return a JSON object (stringified) with the following format :
 *     { ciphertext : {hexString}, iv : {hexString}, version : {string}
 */
function encryptJSON (data, additionalData) {
  // Prepare context
  var dataJson = asciiToUint8Array(JSON.stringify(data))
  var key = cipherContext.derivedKey
  var iv = window.crypto.getRandomValues(new Uint8Array(12))

  return encrypt(dataJson, key, iv, 'AES-GCM', asciiToUint8Array(additionalData)).then(function (result) {
    return JSON.stringify({ciphertext: bytesToHexString(result), iv: bytesToHexString(iv), version: additionalData})
  })
}

/**
 * Decrypt an object
 *
 * @param {object} encrypted data Must contain 3 values:
 *     { ciphertext : {hexString}, iv : {hexString}, version : {string}
 * @returns {ArrayBuffer} Return the decrypted text.
 *
 */
function decryptJSON (data) {
  // Prepare context
  var ciphertext = hexStringToUint8Array(data.ciphertext)
  var additionalData = asciiToUint8Array(data.version)
  var key = cipherContext.derivedKey
  var iv = hexStringToUint8Array(data.iv)

  return decrypt(ciphertext, key, iv, 'AES-GCM', additionalData).then(function (decrypted) {
    return decrypted
  })
}

function loadJson () {
  // Prepare context
  var searchData = { POI_1: 'Tour eiffel', POI_2: 'Cafateria Juna'}
  console.log(JSON.stringify(searchData))
  return encryptJSON(searchData, '1.0.0').then(function (result) {
    return result
  })
}

function decryptJson (data) {
  // Prepare context
  return decryptJSON(JSON.parse(data)).then(function (result) {
    return bytesToASCIIString(result)
  })
}

/**
 * Gets tag from encrypted data
 *
 * @param {ArrayBuffer} encrypted Encrypted data
 * @param {number} tagLength Tag length in bits. Default 128 bits
 * @returns {ArrayBuffer}
 */
function getTag (encrypted, tagLength) {
  if (tagLength === void 0) tagLength = 128
  return encrypted.slice(encrypted.byteLength - ((tagLength + 7) >> 3))
}

console.log('start')
setUserKey('').then(function () {
  loadJson().then(function (encryptedJson) {
    console.log(encryptedJson)
    decryptJson(encryptedJson).then(function (decryptedJson) {
      console.log(decryptedJson)
    })
  })
})

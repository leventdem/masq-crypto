const CryptoMasq = {
  debug: false
}

/**
 * Generate a PBKDF2 derived key based on user given passPhrase
 *
 * @param {string} passPhrase The passphrase that is used to derive the key
 * @returns {Promise}   A promise that contains the derived key
 */
CryptoMasq.deriveKey = (passPhrase = '', iterations = 10000) => {
  if (passPhrase.length === 0) {
    passPhrase = CryptoMasq.randomString(CryptoMasq.keyLenth)
  }

  // TODO: set this to a real value later
  let salt = new Uint8Array('')

  return crypto.subtle.importKey('raw', CryptoMasq.asciiToArray(passPhrase), 'PBKDF2', false, ['deriveBits', 'deriveKey']).then(function (baseKey) {
    return crypto.subtle.deriveBits({name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'sha-256'}, baseKey, 128)
  }, CryptoMasq.failAndLog).then(function (derivedKey) {
    return new Uint8Array(derivedKey)
  }, CryptoMasq.failAndLog)
}

// Generate a random string using the Webwindow API instead of Math.random (insecure)
CryptoMasq.randomString = (length = 18) => {
  var charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  var result = ''
  if (window.crypto && window.crypto.getRandomValues) {
    let values = new Uint32Array(length)
    window.crypto.getRandomValues(values)
    for (let i = 0; i < length; i++) {
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
CryptoMasq.decrypt = (data, key, iv, mode, additionalData) => {
  // TODO: test input params
  return crypto.subtle.importKey('raw', key, {name: mode}, true, ['encrypt', 'decrypt']).then(function (bufKey) {
    return crypto.subtle.decrypt({name: mode, iv, additionalData: additionalData}, bufKey, data).then(function (result) {
      return new Uint8Array(result)
    }, CryptoMasq.failAndLog)
  }, CryptoMasq.failAndLog)
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
CryptoMasq.encrypt = (data, key, iv, mode, additionalData) => {
  return crypto.subtle.importKey('raw', key, {name: mode}, true, ['encrypt', 'decrypt']).then(function (bufKey) {
    return crypto.subtle.encrypt({name: mode, iv, additionalData: additionalData}, bufKey, data).then(function (result) {
      return new Uint8Array(result)
    })
  })
}

/**
 * Encrypt an object
 *
 * @param {object} data Basic key-pair values
 * @param {string} additionalData The authenticated data (ex. version number :1.0.1 )
 * @returns {object} Return a  JSON object with the following format :
 *     { ciphertext : {hexString}, iv : {hexString}, version : {string} }
 */
CryptoMasq.encryptJSON = (key, data, additionalData) => {
  // Prepare context
  var dataJson = CryptoMasq.asciiToArray(JSON.stringify(data))
  var iv = window.crypto.getRandomValues(new Uint8Array(12))

  return CryptoMasq.encrypt(dataJson, key, iv, 'AES-GCM', CryptoMasq.asciiToArray(additionalData)).then(function (result) {
    return JSON.stringify({ciphertext: CryptoMasq.arrayToHexString(result), iv: CryptoMasq.arrayToHexString(iv), version: additionalData})
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
CryptoMasq.decryptJSON = (key, data) => {
  // Prepare context
  var ciphertext = CryptoMasq.hexStringToArray(data.ciphertext)
  var additionalData = CryptoMasq.asciiToArray(data.version)
  var iv = CryptoMasq.hexStringToArray(data.iv)

  return CryptoMasq.decrypt(ciphertext, key, iv, 'AES-GCM', additionalData).then(function (decrypted) {
    return decrypted
  })
}

/**
 * Gets tag from encrypted data
 *
 * @param {ArrayBuffer} encrypted Encrypted data
 * @param {number} tagLength Tag length in bits. Default 128 bits
 * @returns {ArrayBuffer}
 */
CryptoMasq.getTag = (encrypted, tagLength = 128) => {
  return encrypted.slice(encrypted.byteLength - ((tagLength + 7) >> 3))
}

/**
 * Convert hex String to ArrayBufffer
 * ex : '11a1b2' -> Uint8Array [ 17, 161, 178 ]
 *
 * @param {String} hexString
 * @returns {ArrayBuffer}
 */
CryptoMasq.hexStringToArray = (hexString) => {
  if (hexString.length % 2 !== 0) {
    throw new Error('Invalid hexString')
  }
  let arrayBuffer = new Uint8Array(hexString.length / 2)

  for (let i = 0; i < hexString.length; i += 2) {
    let byteValue = parseInt(hexString.substr(i, 2), 16)
    if (isNaN(byteValue)) {
      throw new Error('Invalid hexString')
    }
    arrayBuffer[i / 2] = byteValue
  }

  return arrayBuffer
}

/**
 * Convert ArrayBufffer to hex String
 * ex : Uint8Array [ 17, 161, 178 ] -> '11a1b2'
 *
 * @param {ArrayBuffer} bytes
 * @returns {String}
 */
CryptoMasq.arrayToHexString = (bytes) => {
  if (!bytes) {
    return null
  }
  let hexBytes = []

  for (let i = 0; i < bytes.length; ++i) {
    let byteString = bytes[i].toString(16)
    if (byteString.length < 2) {
      byteString = '0' + byteString
    }
    hexBytes.push(byteString)
  }

  return hexBytes.join('')
}

/**
 * Convert ascii to ArrayBufffer
 * ex : "bonjour" -> Uint8Array [ 98, 111, 110, 106, 111, 117, 114 ]
 *
 * @param {String} str
 * @returns {ArrayBuffer}
 */
CryptoMasq.asciiToArray = (str = '') => {
  var chars = []
  for (let i = 0; i < str.length; ++i) {
    chars.push(str.charCodeAt(i))
  }
  return new Uint8Array(chars)
}

/**
 * Convert ArrayBufffer to ascii
 * ex : Uint8Array [ 98, 111, 110, 106, 111, 117, 114 ] -> "bonjour"
 *
 * @param {ArrayBuffer} bytes
 * @returns {String}
 */
CryptoMasq.arrayToAscii = (bytes) => {
  return String.fromCharCode.apply(null, new Uint8Array(bytes))
}

CryptoMasq.failAndLog = (error) => {
  if (CryptoMasq.debug) { console.log(error) }
}

if (CryptoMasq.arrayToAscii(CryptoMasq.asciiToArray('bonjour')) !== 'bonjour') { console.log('array <-> ascii conversion : error') } else { console.log('array <-> ascii conversion : ok ') }
if (CryptoMasq.arrayToHexString(CryptoMasq.hexStringToArray('11a1b2')) !== '11a1b2') { console.log('array <-> hexString conversion : error') } else { console.log('array <-> hexString conversion : ok ') }

// EXAMPLE
const apiData = { POI_1: 'Tour eiffel', POI_2: 'Cafeteria'}

// If no passphrase is given, it will be generated.
CryptoMasq.deriveKey('').then(function (derivedKey) {
  // encryption
  // const derivedKey = derivedKey
  CryptoMasq.encryptJSON(derivedKey, JSON.stringify(apiData), '1.0.0').then(function (encryptedJson) {
    console.log(encryptedJson)
    // {"ciphertext":"f7bd4...a1fe0fd9","iv":"a033ff25534d21775be6e8c9","version":"1.0.0"}

    // decryption
    CryptoMasq.decryptJSON(derivedKey, JSON.parse(encryptedJson)).then(function (decryptedJson) {
      console.log(CryptoMasq.arrayToAscii(decryptedJson))
      // "{\"POI_1\":\"Tour eiffel\",\"POI_2\":\"Cafeteria\"}"
    })
  })
})

module.exports = CryptoMasq

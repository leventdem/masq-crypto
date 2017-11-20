/**
 * Generate a PBKDF2 derived key based on user given passPhrase
 *
 * @param {string} passPhrase The passphrase that is used to derive the key
 * @returns {Promise}   A promise that contains the derived key
 */
export const deriveKey = (passPhrase = '', iterations = 10000) => {
  if (passPhrase.length === 0) {
    passPhrase = randomString(keyLenth)
  }

  // TODO: set this to a real value later
  let salt = new Uint8Array('')

  return crypto.subtle.importKey('raw', asciiToArray(passPhrase), 'PBKDF2', false, ['deriveBits', 'deriveKey']).then(function (baseKey) {
    return crypto.subtle.deriveBits({name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'sha-256'}, baseKey, 128)
  }).then(function (derivedKey) {
    return new Uint8Array(derivedKey)
  })
}

// Generate a random string using the Webwindow API instead of Math.random (insecure)
export const randomString = (length = 18) => {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  let result = ''
  if (window.crypto && window.crypto.getRandomValues) {
    const values = new Uint32Array(length)
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
const decrypt = (data, key, iv, mode, additionalData) => {
  // TODO: test input params
  return crypto.subtle.importKey('raw', key, {name: mode}, true, ['encrypt', 'decrypt']).then(function (bufKey) {
    return crypto.subtle.decrypt({name: mode, iv, additionalData: additionalData}, bufKey, data).then(function (result) {
      return new Uint8Array(result)
    })
  })
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
const encrypt = (data, key, iv, mode, additionalData) => {
  return crypto.subtle.importKey('raw', key, {name: mode}, true, ['encrypt', 'decrypt']).then(function (bufKey) {
    return crypto.subtle.encrypt({name: mode, iv, additionalData: additionalData}, bufKey, data).then(function (result) {
      return new Uint8Array(result)
    })
  })
}

/**
 * Encrypt an object
 *
 * @param {ArrayBuffer} key Encryption key
 * @param {object} data Basic key-pair values
 * @param {string} additionalData The authenticated data (ex. version number :1.0.1 )
 * @returns {object} Return a  JSON object with the following format :
 *     { ciphertext : {hexString}, iv : {hexString}, version : {string} }
 */
export const encryptJSON = (key, data, additionalData) => {
  // Prepare context
  const dataJson = asciiToArray(JSON.stringify(data))
  const iv = window.crypto.getRandomValues(new Uint8Array(12))

  return encrypt(dataJson, key, iv, 'AES-GCM', asciiToArray(additionalData)).then(function (result) {
    return {ciphertext: arrayToHexString(result), iv: arrayToHexString(iv), version: additionalData}
  })
}

/**
 * Decrypt an object
 *
 * @param {ArrayBuffer} key Decryption key
 * @param {object} encrypted data Must contain 3 values:
 *     { ciphertext : {hexString}, iv : {hexString}, version : {string}
 * @returns {ArrayBuffer} Return the decrypted text.
 *
 */
export const decryptJSON = (key, data) => {
  // Prepare context
  const ciphertext = hexStringToArray(data.ciphertext)
  const additionalData = asciiToArray(data.version)
  const iv = hexStringToArray(data.iv)

  return decrypt(ciphertext, key, iv, 'AES-GCM', additionalData).then(function (decrypted) {
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
export const getTag = (encrypted, tagLength = 128) => {
  return encrypted.slice(encrypted.byteLength - ((tagLength + 7) >> 3))
}

/**
 * Convert hex String to ArrayBufffer
 * ex : '11a1b2' -> Uint8Array [ 17, 161, 178 ]
 *
 * @param {String} hexString
 * @returns {ArrayBuffer}
 */
export const hexStringToArray = (hexString) => {
  if (hexString.length % 2 !== 0) {
    throw new Error('Invalid hexString')
  }
  const arrayBuffer = new Uint8Array(hexString.length / 2)

  for (let i = 0; i < hexString.length; i += 2) {
    const byteValue = parseInt(hexString.substr(i, 2), 16)
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
export const arrayToHexString = (bytes) => {
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
export const asciiToArray = (str = '') => {
  let chars = []
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
export const arrayToAscii = (bytes) => {
  return String.fromCharCode.apply(null, new Uint8Array(bytes))
}

// export const failAndLog = (error) => {
//   if (debug) { console.log(error) }
// }

// Simple conversion test
// if (arrayToAscii(asciiToArray('bonjour')) !== 'bonjour') { console.log('array <-> ascii conversion : error') } else { console.log('array <-> ascii conversion : ok ') }
// if (arrayToHexString(hexStringToArray('11a1b2')) !== '11a1b2') { console.log('array <-> hexString conversion : error') } else { console.log('array <-> hexString conversion : ok ') }

// EXAMPLE
// export const apiData = { POI_1: 'Tour eiffel', POI_2: 'Cafeteria'}

// // If no passphrase is given, it will be generated.
// deriveKey('').then(function (derivedKey) {
//   // encryption
//   encryptJSON(derivedKey, apiData, '1.0.0').then(function (encryptedJson) {
//     console.log(encryptedJson)
//     // Object { ciphertext: "cb9a804…", iv: "145a65b6535d00b5a3cce475", version: "1.0.0" }

//     // decryption
//     decryptJSON(derivedKey, encryptedJson).then(function (decryptedJson) {
//       console.log(arrayToAscii(decryptedJson))
//       // {"POI_1":"Tour eiffel","POI_2":"Cafeteria"}
//     })
//   })
// })


/**
 * Generate a PBKDF2 derived key based on user given passPhrase
 *
 * @param {string} passPhrase The passphrase that is used to derive the key
 * @returns {Promise}   A promise that contains the derived key
 */
export const deriveKey = (passPhrase = '', keyLenth = 18, iterations = 10000) => {
  if (passPhrase.length === 0) {
    passPhrase = randomString(keyLenth)
  }

  // TODO: set this to a real value later
  let salt = new Uint8Array('')

  return crypto.subtle.importKey(
    'raw',
    toArray(passPhrase),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  ).then(function (baseKey) {
    return crypto.subtle.deriveBits({
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'sha-256'
    }, baseKey, 128)
  }, logFail).then(function (derivedKey) {
    return new Uint8Array(derivedKey)
  }, logFail)
}

// Generate a random string using the Webwindow API instead of Math.random
// (insecure)
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

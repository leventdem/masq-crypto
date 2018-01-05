
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
 * @param {Object} RSA_params - The RSA cipher parameters
 * @param {string} RSA_params.curve - The elliptic curve ("P-256", "P-384", or "P-521")
 */
function RSA({ curve }) {
  this.curve = curve || 'P-256'
  this.public = null
  this.private = null
}

/**

/**
 * Generate a RSA-PSS key pair for signature and verification
 *
 * @param {int} modulusLength Chosen modulus length (1024, 2048 or 4096)
 * @returns {Promise} RSA key pair : public and private
 */
RSA.prototype.genRSAKeyPair = function (modulusLength = 4096) {
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
      self.public = cryptoKey.publicKey
      self.private = cryptoKey.privateKey
      return cryptoKey
    })
    .catch(logFail)
}

/**
 * Verif data (e.g. raw EC public key in case of ECDH)
 *
 * @param {CryptoKey} publicKey - The public RSA Key used to verify data signature
 * @param {arrayBuffer} signature - The data signature
 * @param {arrayBuffer} signedData - Signed data
 * @returns {arrayBuffer} - The signature
 */
RSA.prototype.verifRSA = (publicKey, signature, signedData) => {
  return crypto.subtle.verify({
    name: 'RSA-PSS',
    saltLength: 16
  }, publicKey, signature, signedData)
}

/**
 * Sign data (e.g. raw EC public key in case of ECDH)
 * RSA private key is already stored in RSA.private
 *
 * @param {arrayBuffer} data - The data to be signed
 * @returns {arrayBuffer} - The signature
 */
RSA.prototype.signRSA = function (data) {
  return crypto.subtle.sign({
    name: 'RSA-PSS',
    saltLength: 16
  }, this.private, data)
    .then(signature => new Uint8Array(signature))
    .catch(logFail)
}

/**
 * Import RSA-PSS public key
 *
 * @param {jwk} key - The key (jwk format) that we want to import
 * @returns {Promise} - The imported key as CryptoKey
 */
RSA.prototype.importRSAPubKeyRaw = function (key) {
  return crypto.subtle.importKey('jwk', {
    kty: key.kty,
    e: key.e,
    n: key.n,
    alg: key.alg,
    ext: key.ext
  }, {
    name: 'RSA-PSS',
    hash: {
      name: 'SHA-256'
    }
  }, false, ['verify'])
}

/**
 * Export RSA-PSS public key
 *
 * @param {CryptoKey} key The key that we extract raw value
 * @returns {Promise} The raw key
 */
RSA.prototype.exportRSAPubKeyRaw = function (key) {
  return crypto.subtle.exportKey('jwk', key)
}

module.exports = RSA

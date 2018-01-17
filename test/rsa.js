import RSA from '../src/RSA.js'
import { aesModes } from '../src/AES.js'
import * as utils from '../src/utils.js'
// import assert from 'assert'
// import chai from 'chai'

// To avoid error on import please specify the default export in the imported class
// with export default <className> instead of export {className as default}

const should = chai.should()
const keys = []

describe('MasqCrypto RSA', function () {
  var TEST_MESSAGE = utils.toArray('1234567890123456')
  var KEYS = [
    { alg: 'RSA-PSS', usages: ['sign', 'verify'] }
  ]
  var DIGEST = ['SHA-256', 'SHA-384', 'SHA-512']
  var MODULUS_LENGTH = [2048, 4096]

  var keys = []

  context('Generate key', () => {
    it('Params', done => {
      let cRSA = new RSA(
        {
          name: 'RSA-PSS',
          hash: 'SHA-256',
          modulusLength: 4096
        })
      cRSA.genRSAKeyPair()
        .then(keyPair => {
          let pkey = keyPair.privateKey
          chai.expect(pkey.type, 'private')
          chai.expect(pkey.algorithm.name, 'RSA-PSS')
          chai.expect(pkey.algorithm.hash.name, 'SHA-256')
          chai.expect(pkey.algorithm.modulusLength, 4096)
          chai.expect(pkey.algorithm.publicExponent.length, 3)
          chai.expect(pkey.extractable, false)

          let pubkey = keyPair.publicKey
          chai.expect(pubkey.type, 'public')
          chai.expect(pubkey.algorithm.name, 'RSA-PSS')
          chai.expect(pubkey.algorithm.hash.name, 'SHA-256')
          chai.expect(pubkey.algorithm.modulusLength, 4096)
          chai.expect(pubkey.algorithm.publicExponent.length, 3)
          chai.expect(pubkey.extractable, true)
        })
        .then(done, done)
    })
    // Keys
    KEYS.forEach(key => {
      // Digest
      DIGEST.forEach(digest => {
        // modulusLength
        MODULUS_LENGTH.forEach(modLen => {
          var keyName = `${key.alg} ${digest} n:${modLen}`
          var keyTemplate = {
            name: keyName,
            privateKey: null,
            publicKey: null,
            usages: key.usages
          }
          keys.push(keyTemplate)
          it(keyName, done => {
            var alg = {
              name: key.alg,
              hash: digest,
              modulusLength: modLen
            }
            let cRSA = new RSA(alg)
            cRSA.genRSAKeyPair()
              .then(keyPair => {
                should.exist(cRSA.publicKey, 'RSA public Key is empty')
                should.exist(cRSA.privateKey, 'RSA private Key is empty')
                should.exist(keyPair.publicKey, 'RSA public Key is empty')
                should.exist(keyPair.privateKey, 'RSA private Key is empty')
                // save  keys for next tests
                keyTemplate.privateKey = keyPair.privateKey
                keyTemplate.publicKey = keyPair.publicKey

                return Promise.resolve()
              })
              .then(done, done)
          }).timeout(modLen === 4096 ? 6000 : 3000)
        })
      })
    })
  })
  context("Sign/Verify", () => {

    keys.filter(key => key.usages.some(usage => usage === "sign"))
      .forEach(key => {
        it(key.name, done => {
          // TODO: Add label
          let cRSA = new RSA({ name: key.privateKey.algorithm.name })
          cRSA.signRSA(TEST_MESSAGE, key.privateKey)
            .then(sig => {
              should.exist(sig, 'Signature does not exist')
              chai.expect(sig.length).to.not.equal(0, "Has empty signature value")
              return cRSA.verifRSA(key.publicKey, sig, TEST_MESSAGE)
            })
            .then(v => {
              chai.expect(v).to.be.equal(true, "Signature is not valid")
            })
            .then(done, done)
        })
      })
  })
  context("Export/Import", () => {

    // Keys
    keys.forEach(key => {
      // Format
      // TODO add format : "spki", "pkcs8"
      ["jwk"].forEach(format => {
        it(`${format}\t${key.name}`, done => {
          var promise = Promise.resolve()
          // Check public and private keys
          [key.privateKey, key.publicKey].forEach(_key => {
            if ((format === "spki" && _key.type === "public") || (format === "pkcs8" && _key.type === "private") || format === "jwk")
              promise = promise.then(() => {
                return webcrypto.subtle.exportKey(format, _key)
                  .then(jwk => {
                    assert.equal(!!jwk, true, "Has no jwk value")
                    // TODO assert JWK params
                    return webcrypto.subtle.importKey(format, jwk, _key.algorithm, true, _key.usages)
                  })
              })
                .then(k => {
                  assert.equal(!!k, true, "Imported key is empty")
                  checkAlgorithms(_key.algorithm, k.algorithm)
                })
          })
          promise.then(done, done)
        })
      })
    })
  })
})

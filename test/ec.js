import EC from '../src/EC.js'
import { aesModes } from '../src/AES.js'
// import assert from 'assert'
// import chai from 'chai'

// To avoid error on import please specify the default export in the imported class
// with export default <className> instead of export {className as default}

const should = chai.should()
const keys = []

describe('MasqCrypto EC', function () {
  var KEYS = [
    { alg: 'ECDH', usages: ['deriveKey', 'deriveBits'] }
  ]
  var DIGEST = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']
  var NAMED_CURVES = ['P-256', 'P-384', 'P-521']

  var keys = []

  var aECPrivateKey = null

  context('Key generations', () => {

    // Keys
    KEYS.forEach(key => {
      // namedCurve
      NAMED_CURVES.forEach(namedCurve => {
        var keyName = `${key.alg} crv:${namedCurve}`
        var keyTemplate = {
          name: keyName,
          privateKey: null,
          publicKey: null,
          usages: key.usages,
        }
        keys.push(keyTemplate)
        it(keyName, done => {
          var alg = {
            name: key.alg,
            namedCurve: namedCurve
          }
          const myEC = new EC({ name: alg.name, curve: alg.namedCurve })
          myEC.genECKeyPair().then(keyPair => {
            should.exist(myEC.publicKey, 'EC public Key is empty')
            should.exist(myEC.privateKey, 'EC private Key is empty')
            should.exist(keyPair.publicKey, 'EC public Key is empty')
            should.exist(keyPair.privateKey, 'EC private Key is empty')
            chai.assert.equal(myEC.publicKey, keyPair.publicKey)
            chai.assert.equal(myEC.privateKey, keyPair.privateKey)
            // save  keys for next tests
            keyTemplate.privateKey = keyPair.privateKey
            keyTemplate.publicKey = keyPair.publicKey

            return Promise.resolve()
          })
            .then(done, done)
        })
      })
    })

    context("Derive key", () => {

      keys.filter(key => key.usages.some(usage => usage === "deriveKey"))
        .forEach(key => {
          // AES alg
          [aesModes.CBC, aesModes.GCM].forEach(aesAlg => {
            // [aesModes.CBC].forEach(aesAlg => {
            // AES length
            [128, 256].forEach(aesLength => {
              // [128].forEach(aesLength => {
              it(`${aesAlg}-${aesLength}\t${key.name}`, done => {
                const myEC = new EC({ name: key.privateKey.algorithm.name })
                myEC.deriveKeyECDH(key.publicKey, aesAlg, aesLength, key.privateKey).then(aesKey => {
                  should.exist(aesKey, 'Has no derived key')
                  aesKey.should.have.lengthOf(aesLength / 8, `Derived key length is not ${aesLength / 8} bytes`)
                })
                  .then(done, done)
              })
            })
          })
        })
    })
  })

  // When using chained promises, add the test (assert, expect)
  // only in the last promise. Tests in between will not be triggered
  // or may create random behaviour.
  context('ECDH', () => {
    let msg1 = 'ECDH generateKey + exportKey + importKey + derive AES-GCM key'
    it(msg1, done => {
      const aliceEC = new EC({ name: 'ECDH', curve: 'P-256' })
      const bobEC = new EC({ name: 'ECDH', curve: 'P-256' })
      aliceEC.genECKeyPair().then(() => {
        bobEC.genECKeyPair().then(() => {
          bobEC.exportKeyRaw().then(bobRawKey => {
            aliceEC.exportKeyRaw().then(aliceawKey => {
              aliceEC.importKeyRaw(bobRawKey).then(BobECPubKey => {
                // could call deriveKeyECDH with aliceEC.privateKey as fourth argument
                // because the function takes this.privateKey during key derivation with ECDH
                aliceEC.deriveKeyECDH(BobECPubKey, aesModes.GCM, 128).then(AESKeyAlice => {
                  bobEC.importKeyRaw(aliceawKey).then(AliceECPubKey => {
                    bobEC.deriveKeyECDH(AliceECPubKey, 'aes-gcm', 128).then(AESKeyBob => {
                      console.log(AESKeyAlice, AESKeyBob)
                      chai.assert.deepEqual(AESKeyAlice, AESKeyBob, 'Both derived symmetric key do not match')
                    }).then(done, done)
                  })
                })
              })
            })
          })
        })
      })
    })
  })
})

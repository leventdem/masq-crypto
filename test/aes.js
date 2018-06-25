/* global chai, MasqCrypto */

// To avoid error on import please specify the default export in the imported class
// with export default <className> instead of export {className as default}
const should = chai.should()

const KEYS = [
  { alg: MasqCrypto.aesModes.GCM },
  { alg: MasqCrypto.aesModes.CTR },
  { alg: MasqCrypto.aesModes.CBC }
]

// EXAMPLE
let BIG_MESSAGE = ''
for (let i = 0; i < 10; i++) {
  BIG_MESSAGE += '0123456789'
}

const SMALL_MESSAGE = {
  POI_1: 'Tour eiffel',
  POI_2: 'Bastille',
  POI_3: 'Cafeteria'
}
const messages = [
  { name: 'small', data: SMALL_MESSAGE },
  { name: 'big', data: BIG_MESSAGE }
]

function testAlgo (message, key, alg, additionalData = undefined) {
  it(`${message.name} message \t${key.name}`, done => {
    // We create an AES object with some paramters
    const myAES = new MasqCrypto.AES({
      mode: alg.name,
      key: key.key,
      keySize: key.keySize,
      additionalData: additionalData
    })
    // optional : we can add additionalData later
    // myAES.additionalData = "1.0.0"
    myAES.encrypt(JSON.stringify(message.data))
      .then(encryptedJSON => {
        should.exist(encryptedJSON, 'Encrypted message is empty')
        return myAES.decrypt(encryptedJSON)
      })
      .then(decryptedJSON => {
        chai.assert(decryptedJSON, message.data, 'Decrypted message is wrong')
      })
      .then(done, done)
  })
}

describe('MasqCrypto AES', () => {
  describe('with AES key generator aka CryptoKey', () => {
    let keys = []

    context('Generate key with AES key generator aka CryptoKey', () => {
      // Keys
      KEYS.forEach(key => {
        // length (192 bits is not supported)
        [128, 256].forEach(length => {
          const keyName = `${key.alg} l:${length}`
          const keyTemplate = { name: keyName, key: null, keySize: length }
          keys.push(keyTemplate)

          it(keyName, done => {
            const aesKey = new MasqCrypto.AES({ mode: key.alg, keySize: length })
            aesKey.genAESKey()
              .then(aesKey => {
                should.exist(aesKey, 'Aes key is empty')
                keyTemplate.key = aesKey
              })
              .then(done, done)
          })
        })
      })
    })

    context('Encrypt/Decrypt with CryptoKey as input', () => {
      const algos = ['cbc', 'ctr', 'gcm']

      algos.forEach(algo =>
        context(`aes-${algo}`, () => {
          const filteredKeys = keys.filter(key => RegExp(`aes-${algo}`).test(key.name))
          const alg = { name: MasqCrypto.aesModes[algo.toUpperCase()] }
          filteredKeys.forEach(key => {
            messages.forEach(message => {
              testAlgo(message, key, alg)
            })
          })
        })
      )

      context('AES-GCM with additionnal data : "1.0.0"', () => {
        // Filter GCM
        const gcmKeys = keys.filter(key => /aes-gcm/.test(key.name))
        const alg = { name: MasqCrypto.aesModes.GCM }
        gcmKeys.forEach(key => {
          messages.forEach(message => {
            testAlgo(message, key, alg, '1.0.0')
          })
        })
      })
    })
  })

  describe('with webCryptoAPI random generator aka raw keys', () => {
    let keys = []
    context('Generate key with webCryptoAPI random generator aka raw keys', () => {
      keys = []
      // Keys
      KEYS.forEach(key => {
        // length (192 bits is not supported)
        [128, 256].forEach(length => {
          const keyName = `${key.alg} l:${length}`
          const keyTemplate = {
            name: keyName,
            key: null,
            keySize: length
          }
          keys.push(keyTemplate)
          it(keyName, () => {
            // We generate a 128 bits key with crypto random
            // getRandomValues takes bytes # instead of bits #
            let AESKey = window.crypto.getRandomValues(new Uint8Array(length / 8))
            should.exist(AESKey, 'Aes key is empty')
            keyTemplate.key = AESKey
          })
        })
      })
    })

    context('Encrypt/Decrypt with raw keys as input', () => {
      const algos = ['cbc', 'ctr', 'gcm']

      algos.forEach(algo =>
        context(`aes-${algo}`, () => {
          const filteredKeys = keys.filter(key => RegExp(`aes-${algo}`).test(key.name))
          const alg = { name: MasqCrypto.aesModes[algo.toUpperCase()] }
          filteredKeys.forEach(key => {
            messages.forEach(message => {
              testAlgo(message, key, alg)
            })
          })
        })
      )

      context('AES-GCM with additionnal data : "1.0.0"', () => {
        // Filter GCM
        const gcmKeys = keys.filter(key => /aes-gcm/.test(key.name))
        const alg = { name: MasqCrypto.aesModes.GCM }
        gcmKeys.forEach(key => {
          messages.forEach(message => {
            testAlgo(message, key, alg, '1.0.0')
          })
        })
      })
    })

    context('Wrap/Unwrap a key', () => {
      context('AES-GCM', () => {
        // Filter GCM
        const gcmKeys = keys.filter(key => /aes-gcm/.test(key.name))
        gcmKeys.forEach(key => {
          it(`\t${key.name}`, done => {
            const alg = { name: MasqCrypto.aesModes.GCM }
            // We create an AES object with some paramters
            const myAES = new MasqCrypto.AES({
              mode: alg.name,
              key: key.key,
              keySize: key.keySize
            })
            myAES.genAESKey().then(aesKey => {
              myAES.exportKeyRaw(aesKey).then(raw => {
                myAES.wrapKey(aesKey, 'raw').then(res => {
                  should.exist(res, 'Wrapped key')
                  myAES.unwrapKey(res.encryptedMasterKey, res.iv, res.keySize, 'raw').then(unwrapped => {
                    myAES.exportKeyRaw(unwrapped).then(rawUnwrap => {
                      chai.assert(raw, rawUnwrap, 'Unwrapped key does not correspond to original key')
                    })
                  })
                })
              })
            })
              .then(done, done)
          })
        })
      })
    })
  })
})

// To avoid error on import please specify the default export in the imported class
// with export default <className> instead of export {className as default}
const should = chai.should()

let keys = []

describe('MasqCrypto AES', () => {
  // EXAMPLE
  let BIG_MESSAGE = ''
  let i = 0
  while (i++ < 10) {
    BIG_MESSAGE += '0123456789'
  }
  let SMALL_MESSAGE = {
    POI_1: 'Tour eiffel',
    POI_2: 'Bastille',
    POI_3: 'Cafeteria'
  }
  const messages = [
    { name: 'small', data: SMALL_MESSAGE },
    { name: 'big', data: BIG_MESSAGE }
  ]

  const KEYS = [
    { alg: MasqCrypto.aesModes.GCM },
    { alg: MasqCrypto.aesModes.CTR },
    { alg: MasqCrypto.aesModes.CBC }
  ]

  context('Generate key with AES key generator aka CryptoKey', () => {
    // Keys
    KEYS.forEach(key => {
      // length (192 bits is not supported)
      [128, 256].forEach(length => {
        let keyName = `${key.alg} l:${length}`
        var keyTemplate = {
          name: keyName,
          key: null,
          keySize: length
        }
        keys.push(keyTemplate)
        it(keyName, done => {
          let aesKey = new MasqCrypto.AES(
            {
              mode: key.alg,
              keySize: length
            }
          )
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

  // console.log(keys)

  context('Encrypt/Decrypt with CryptoKey as input', () => {
    context('AES-CBC', () => {
      // Filter CBC
      keys.filter(key => /aes-cbc/.test(key.name))
        .forEach(key => {
          messages.forEach(message => {
            // console.log(message.data)
            it(`${message.name} message \t${key.name}`, done => {
              var alg = {
                name: MasqCrypto.aesModes.CBC
              }
              // We create an AES object with some paramters
              const myAES = new MasqCrypto.AES(
                {
                  mode: alg.name,
                  key: key.key,
                  keySize: key.keySize
                }
              )
              myAES.encrypt(JSON.stringify(message.data))
                .then(encryptedJSON => {
                  // console.log(encryptedJSON)
                  should.exist(encryptedJSON, 'Encrypted message is empty')
                  return myAES.decrypt(encryptedJSON)
                })
                .then(decryptedJSON => {
                  // console.log(decryptedJSON)
                  chai.assert(decryptedJSON, message.data, 'Decrypted message is wrong')
                })
                .then(done, done)
            })
          })
        })
    })
    context('AES-CTR', () => {
      // Filter CTR
      keys.filter(key => /aes-ctr/.test(key.name))
        .forEach(key => {
          messages.forEach(message => {
            // console.log(message.data)
            it(`${message.name} message \t${key.name}`, done => {
              var alg = {
                name: MasqCrypto.aesModes.CTR
              }
              // We create an AES object with some paramters
              const myAES = new MasqCrypto.AES(
                {
                  mode: alg.name,
                  key: key.key,
                  keySize: key.keySize
                }
              )
              myAES.encrypt(JSON.stringify(message.data))
                .then(encryptedJSON => {
                  // console.log(encryptedJSON)
                  should.exist(encryptedJSON, 'Encrypted message is empty')
                  return myAES.decrypt(encryptedJSON)
                })
                .then(decryptedJSON => {
                  // console.log(decryptedJSON)
                  chai.assert(decryptedJSON, message.data, 'Decrypted message is wrong')
                })
                .then(done, done)
            })
          })
        })
    })
    context('AES-GCM with additionnal data : "1.0.0"', () => {
      // Filter GCM
      keys.filter(key => /aes-gcm/.test(key.name))
        .forEach(key => {
          messages.forEach(message => {
            // console.log(message.data)
            it(`${message.name} message \t${key.name}`, done => {
              var alg = {
                name: MasqCrypto.aesModes.GCM
              }
              // We create an AES object with some paramters
              const myAES = new MasqCrypto.AES(
                {
                  mode: alg.name,
                  key: key.key,
                  keySize: key.keySize,
                  additionalData: '1.0.0'
                }
              )
              myAES.encrypt(JSON.stringify(message.data))
                .then(encryptedJSON => {
                  // console.log(encryptedJSON)
                  should.exist(encryptedJSON, 'Encrypted message is empty')
                  return myAES.decrypt(encryptedJSON)
                })
                .then(decryptedJSON => {
                  // console.log(decryptedJSON)
                  chai.assert(decryptedJSON, message.data, 'Decrypted message is wrong')
                })
                .then(done, done)
            })
          })
        })
    })
    context('AES-GCM without additionnal data', () => {
      // Filter GCM
      keys.filter(key => /aes-gcm/.test(key.name))
        .forEach(key => {
          messages.forEach(message => {
            // console.log(message.data)
            it(`${message.name} message \t${key.name}`, done => {
              var alg = {
                name: MasqCrypto.aesModes.GCM
              }
              // We create an AES object with some paramters
              const myAES = new MasqCrypto.AES(
                {
                  mode: alg.name,
                  key: key.key,
                  keySize: key.keySize
                }
              )
              myAES.encrypt(JSON.stringify(message.data))
                .then(encryptedJSON => {
                  // console.log(encryptedJSON)
                  should.exist(encryptedJSON, 'Encrypted message is empty')
                  return myAES.decrypt(encryptedJSON)
                })
                .then(decryptedJSON => {
                  // console.log(decryptedJSON)
                  chai.assert(decryptedJSON, message.data, 'Decrypted message is wrong')
                })
                .then(done, done)
            })
          })
        })
    })
  })
  context('Generate key with webCryptoAPI random generator aka raw keys', () => {
    keys = []
    // Keys
    KEYS.forEach(key => {
      // length (192 bits is not supported)
      [128, 256].forEach(length => {
        let keyName = `${key.alg} l:${length}`
        var keyTemplate = {
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
  // console.log(keys)
  context('Encrypt/Decrypt with raw keys as input', () => {
    context('AES-CBC', () => {
      // Filter CBC
      keys.filter(key => /aes-cbc/.test(key.name))
        .forEach(key => {
          messages.forEach(message => {
            // console.log(message.data)
            it(`${message.name} message \t${key.name}`, done => {
              var alg = {
                name: MasqCrypto.aesModes.CBC
              }
              // We create an AES object with some paramters
              const myAES = new MasqCrypto.AES(
                {
                  mode: alg.name,
                  key: key.key,
                  keySize: key.keySize
                }
              )
              myAES.encrypt(JSON.stringify(message.data))
                .then(encryptedJSON => {
                  // console.log(encryptedJSON)
                  should.exist(encryptedJSON, 'Encrypted message is empty')
                  return myAES.decrypt(encryptedJSON)
                })
                .then(decryptedJSON => {
                  // console.log(decryptedJSON)
                  chai.assert(decryptedJSON, message.data, 'Decrypted message is wrong')
                })
                .then(done, done)
            })
          })
        })
    })
    context('AES-CTR', () => {
      // Filter CTR
      keys.filter(key => /aes-ctr/.test(key.name))
        .forEach(key => {
          messages.forEach(message => {
            // console.log(message.data)
            it(`${message.name} message \t${key.name}`, done => {
              var alg = {
                name: MasqCrypto.aesModes.CTR
              }
              // We create an AES object with some paramters
              const myAES = new MasqCrypto.AES(
                {
                  mode: alg.name,
                  key: key.key,
                  keySize: key.keySize
                }
              )
              myAES.encrypt(JSON.stringify(message.data))
                .then(encryptedJSON => {
                  // console.log(encryptedJSON)
                  should.exist(encryptedJSON, 'Encrypted message is empty')
                  return myAES.decrypt(encryptedJSON)
                })
                .then(decryptedJSON => {
                  // console.log(decryptedJSON)
                  chai.assert(decryptedJSON, message.data, 'Decrypted message is wrong')
                })
                .then(done, done)
            })
          })
        })
    })
    context('AES-GCM with additionnal data : "1.0.0"', () => {
      // Filter GCM
      keys.filter(key => /aes-gcm/.test(key.name))
        .forEach(key => {
          messages.forEach(message => {
            // console.log(message.data)
            it(`${message.name} message \t${key.name}`, done => {
              var alg = {
                name: MasqCrypto.aesModes.GCM
              }
              // We create an AES object with some paramters
              const myAES = new MasqCrypto.AES(
                {
                  mode: alg.name,
                  key: key.key,
                  keySize: key.keySize,
                  additionalData: '1.0.0'
                }
              )
              // optional : we can add additionalData later
              // myAES.additionalData = "1.0.0"
              myAES.encrypt(JSON.stringify(message.data))
                .then(encryptedJSON => {
                  // console.log(encryptedJSON)
                  should.exist(encryptedJSON, 'Encrypted message is empty')
                  return myAES.decrypt(encryptedJSON)
                })
                .then(decryptedJSON => {
                  // console.log(decryptedJSON)
                  chai.assert(decryptedJSON, message.data, 'Decrypted message is wrong')
                })
                .then(done, done)
            })
          })
        })
    })
    context('AES-GCM without additionnal data', () => {
      // Filter GCM
      keys.filter(key => /aes-gcm/.test(key.name))
        .forEach(key => {
          messages.forEach(message => {
            // console.log(message.data)
            it(`${message.name} message \t${key.name}`, done => {
              var alg = {
                name: MasqCrypto.aesModes.GCM
              }
              // We create an AES object with some paramters
              const myAES = new MasqCrypto.AES(
                {
                  mode: alg.name,
                  key: key.key,
                  keySize: key.keySize
                }
              )
              myAES.encrypt(JSON.stringify(message.data))
                .then(encryptedJSON => {
                  // console.log(encryptedJSON)
                  should.exist(encryptedJSON, 'Encrypted message is empty')
                  return myAES.decrypt(encryptedJSON)
                })
                .then(decryptedJSON => {
                  // console.log(decryptedJSON)
                  chai.assert(decryptedJSON, message.data, 'Decrypted message is wrong')
                })
                .then(done, done)
            })
          })
        })
    })
  })
  context('Wrap/Unwrap a key', () => {
    context('AES-GCM', () => {
      // Filter GCM
      keys.filter(key => /aes-gcm/.test(key.name))
        .forEach(key => {
          // console.log(message.data)
          it(`\t${key.name}`, done => {
            var alg = {
              name: MasqCrypto.aesModes.GCM
            }
            // We create an AES object with some paramters
            const myAES = new MasqCrypto.AES(
              {
                mode: alg.name,
                key: key.key,
                keySize: key.keySize
              }
            )
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

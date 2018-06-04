describe('MasqCrypto utils', function () {
  context('Data conversion functions', () => {
    it('toString <-> toArray', () => {
      chai.assert(MasqCrypto.utils.toString(MasqCrypto.utils.toArray('bonjour')), 'bonjour', 'must return bonjour string')
    })
    it('bufferToHexString <-> hexStringToBuffer', () => {
      chai.assert(MasqCrypto.utils.bufferToHexString(MasqCrypto.utils.hexStringToBuffer('11a1b2')), '11a1b2', 'must return 11a1b2 string')
    })
  })
  context('Key derivation and passphrase generation', () => {
    let str = ''
    it('Generate a random string [a-zA-Z0-9] and derive', () => {
      str = MasqCrypto.utils.randomString()
      chai.assert.typeOf(str, 'string', 'str is a string')
      chai.assert.lengthOf(str, 18, 'Default length is 18')
    })
    it('Key derivation PBKDF2, passphrase as string, no salt and default iteration numbers', done => {
      MasqCrypto.utils.deriveKey(str)
        .then(derivedKey => {
          should.exist(derivedKey, 'derivedKey is empty')
          chai.assert.lengthOf(derivedKey, 16, 'Default length is 16 bytes (128 bits)')
          chai.assert(derivedKey instanceof Uint8Array, true, 'DerivedKey is not an array')
        })
        .then(done, done)
    })
    it('Key derivation PBKDF2, passphrase as Uint8Array, no salt and default iteration numbers', done => {
      MasqCrypto.utils.deriveKey(MasqCrypto.utils.toArray(str))
        .then(derivedKey => {
          should.exist(derivedKey, 'derivedKey is empty')
          chai.assert.lengthOf(derivedKey, 16, 'Default length is 16 bytes (128 bits)')
          chai.assert(derivedKey instanceof Uint8Array, true, 'DerivedKey is not an array')
        })
        .then(done, done)
    })
    it('Key derivation PBKDF2, passphrase as Uint8Array, salt and default iteration numbers', done => {
      MasqCrypto.utils.deriveKey(MasqCrypto.utils.toArray(str), MasqCrypto.utils.toArray('theSalt'))
        .then(derivedKey => {
          should.exist(derivedKey, 'derivedKey is empty')
          chai.assert.lengthOf(derivedKey, 16, 'Default length is 16 bytes (128 bits)')
          chai.assert(derivedKey instanceof Uint8Array, true, 'DerivedKey is not an array')
        })
        .then(done, done)
    })
    it('Key derivation PBKDF2, check derived key value', done => {
      MasqCrypto.utils.deriveKey('myPassphrase')
        .then(derivedKey => {
          let derivedKeyHexStr = MasqCrypto.utils.bufferToHexString(derivedKey)
          should.exist(derivedKey, 'derivedKey is empty')
          chai.assert.lengthOf(derivedKey, 16, 'Default length is 16 bytes (128 bits)')
          chai.assert(derivedKey instanceof Uint8Array, true, 'DerivedKey is not an array')
          chai.assert.equal(derivedKeyHexStr, '1301739b5d4bdca3c1a6bc0f78f95396', 'Derivation error, must return 1301739b5d4bdca3c1a6bc0f78f95396')
        })
        .then(done, done)
    })
  })
})

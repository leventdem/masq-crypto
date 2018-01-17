import EC from './EC'

const aliceEC = new EC({})
const bobEC = new EC({})

const generateECKeys = () => {
  console.log('Generation of ephemeral EC keys for Alice and Bob')
  return Promise.all([aliceEC.genECKeyPair(), bobEC.genECKeyPair({})])
}

const exportRawKeys = () => {
  console.log('Extraction of raw EC public keys for Alice and Bob')
  return Promise.all([bobEC.exportKeyRaw(), aliceEC.exportKeyRaw()])
}

// Used to store the raw EC public Keys
const alice = {}
const bob = {}

console.log('Start test')

generateECKeys()
  .then(exportRawKeys)
  .then(rawKeys => {
    bob.ECRawPubKey = rawKeys[0]
    alice.ECRawPubKey = rawKeys[1]
    return bobEC.importKeyRaw(alice.ECRawPubKey)
  })
  .then(AliceECPubKey => {
    console.log('Bob : public key verification :  ok')
    // Bob : with Alice Public EC key and his EC private key, we derive a symmetric key
    console.log("Bob derives a symmetric key with Alice's Public EC key and his EC private key ")
    return bobEC.deriveKeyECDH(AliceECPubKey, 'aes-gcm', 128)
  })
  .then(derivedSymmetricAESKeyBob => {
    aliceEC.importKeyRaw(bob.ECRawPubKey).then(BobECPubKey => {
      aliceEC.deriveKeyECDH(BobECPubKey, 'aes-gcm', 128).then(derivedSymmetricAESKeyAlice => {
      }).catch(err => console.log(err))
    }).catch(err => console.log(err))
  })
  .catch(err => console.log(err))

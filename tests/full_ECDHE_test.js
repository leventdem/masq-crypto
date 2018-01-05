import AES from './AES'
import EC from './EC'
import RSA from './RSA'

const aliceRSA = new RSA({ curve: 'P-256' })
const aliceEC = new EC({})
const bobRSA = new RSA({ curve: 'P-256' })
const bobEC = new EC({})

const delay = (ms) => {
  return new Promise(function (resolve, reject) {
    setTimeout(resolve, ms) // (A)
  })
}

const generateRSAKeys = () => {
  return Promise.all([aliceRSA.genRSAKeyPair(), bobRSA.genRSAKeyPair()])
}
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

var ciphertext = null

const apiData = {
  POI_1: 'Tour eiffel',
  POI_2: 'Bastille',
  POI_3: 'Cafeteria'
}

console.log('Start test')
console.log('Here a full ECDHE with RSA sign and verif is simulated')
console.log('Generation of long term RSA keys for Alice and Bob')
console.log('We suppose that Alice and Bob have already exchanged \n their RSA public Keys (e.g. through QrCode')
generateRSAKeys()
  .then(generateECKeys)
  .then(exportRawKeys)
  .then(rawKeys => {
    bob.ECRawPubKey = rawKeys[0]
    alice.ECRawPubKey = rawKeys[1]
    console.log('Alice -> Bob')
    console.log('Alice signs her EC raw Public Key with her RSA private key')
    console.log('Alice sends her EC raw Public Key and the signature')
    return aliceRSA.signRSA(alice.ECRawPubKey)
  })
  .then(signature => bobRSA.verifRSA(aliceRSA.public, signature, alice.ECRawPubKey))
  .then(result => {
    console.log('Bob verifies the received EC public key and compares to the signature ')
    if (result) {
      // if verification is ok, import Alice's public key as CryptoKey
      return bobEC.importKeyRaw(alice.ECRawPubKey)
    } else {
      return Promise.reject(new Error('RSA signature verification failed'))
    }
  })
  .then(AliceECPubKey => {
    console.log('Bob : public key verification :  ok')
    // Bob : with Alice Public EC key and his EC private key, we derive a symmetric key
    console.log("Bob derives a symmetric key with Alice's Public EC key and his EC private key ")
    return bobEC.deriveKeyECDH(AliceECPubKey, 'aes-gcm', 128)
  })
  .then(derivedSymmetricAESKey => {
    console.log('Bob : derivedSymmetricAESKey', derivedSymmetricAESKey)
    let bobAES = new AES(
      {
        mode: 'aes-gcm',
        key: derivedSymmetricAESKey,
        keySize: 128
      }
    )
    // optionnal : we add additionalData:"1.0.0"
    bobAES.setAdditionalData('1.0.0')
    console.log('Bob encrypt data with the derived symmetric key')
    return bobAES.encrypt(JSON.stringify(apiData))
  })
  .then(encryptedJson => {
    console.log(encryptedJson)
    // We store the ciphertext for the future decryption
    console.log('Bob sends the encrypted message')
    ciphertext = encryptedJson
    console.log('Bob -> Alice : second step')
    console.log('Bob signs his EC public Key and send it along with the signature')
    return bobRSA.signRSA(bob.ECRawPubKey)
  })
  .then(signature => aliceRSA.verifRSA(bobRSA.public, signature, bob.ECRawPubKey))
  .then(result => {
    if (result) {
      // if verification is ok, import Alice's public key as CryptoKey
      return aliceEC.importKeyRaw(bob.ECRawPubKey)
    } else {
      return Promise.reject(new Error('RSA signature verification failed'))
    }
  })
  .then(BobECPubKey => {
    console.log('Alice : EC public key verification : ok')
    // Alice : with Bob EC Public key and her EC private key, Alice derives the same AES symmetric key
    return aliceEC.deriveKeyECDH(BobECPubKey, 'aes-gcm', 128)
  })
  .then(derivedSymmetricAESKey => {
    console.log("Alice derives a symmetric key with Bob's Public EC key and her EC private key ")
    console.log('Alice : derivedSymmetricAESKey', derivedSymmetricAESKey)
    let aliceAES = new AES(
      {
        mode: 'aes-gcm',
        key: derivedSymmetricAESKey,
        keySize: 128
      }
    )
    return aliceAES.decrypt(ciphertext)
  })
  .then(decryptedJson => {
    console.log('Alice decrypts the message')
    console.log(decryptedJson) // { POI_1: "Tour eiffel", POI_2: "Cafeteria"}
  })
  .then(res => console.log('Test finished'))
  .catch(err => console.log(err))
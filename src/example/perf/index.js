import AES, { aesModes } from '../../AES'
import EC from '../../EC'
import RSA from '../../RSA'
import * as utils from '../../utils'
import assert from 'assert'

const apiData = {
  POI_1: 'Tour eiffel',
  POI_2: 'Bastille',
  POI_3: 'Cafeteria'
}

/**
 * Print error messages
 *
 * @param {Error} err Error message
 */
const logFail = (err) => {
  console.log(err)
}

const aesCTR = () => {
  // EXAMPLE
  const data = {
    POI_1: 'Tour eiffel',
    POI_2: 'Bastille',
    POI_3: 'Cafeteria'
  }

  // We generate a 128 bits key with crypto random
  const AESKey = window.crypto.getRandomValues(new Uint8Array(16))
  // We create an AES object with some paramters
  const myAES = new AES(
    {
      mode: aesModes.CTR,
      key: AESKey,
      keySize: 128
    }
  )
  console.log(myAES)
  myAES.encrypt(JSON.stringify(data))
    .then(encryptedJSON => {
      console.log(encryptedJSON)
      return myAES.decrypt(encryptedJSON)
    })
    .then(decryptedJSON => console.log(decryptedJSON))
    .catch(err => console.log(err))
}

const ecdh = () => {

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
          console.log(derivedSymmetricAESKeyAlice)
          console.log(derivedSymmetricAESKeyBob)
        }).catch(err => console.log(err))
      }).catch(err => console.log(err))
    })
    .catch(err => console.log(err))
}

//ecdh()
aesCTR()
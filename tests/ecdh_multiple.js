const delay = (ms) => {
  return new Promise(function(resolve, reject) {
    setTimeout(resolve, ms); // (A)
  })
}

const generateRSAKeys = () => {
  return Promise.all([genRSAKeyPair(), genRSAKeyPair()]).then(values => {
    alice.RSA.pub = values[0].publicKey
    alice.RSA.priv = values[0].privateKey
    bob.RSA.pub = values[1].publicKey
    bob.RSA.priv = values[1].privateKey
  })
}

const genECkeys = () => {
  return Promise.all([genECKeyPair(), genECKeyPair()]).then(values => {
    alice.EC.pub = values[0].publicKey
    alice.EC.priv = values[0].privateKey
    bob.EC.pub = values[1].publicKey
    bob.EC.priv = values[1].privateKey

    return Promise.all([
      exportKeyRaw(bob.EC.pub),
      exportKeyRaw(alice.EC.pub)
    ]).then(values => {
      bob.EC.pub.raw = values[0]
      alice.EC.pub.raw = values[1]
    })
  })
}

const sign_send = (sender, time_ms = 1000) => {
  return delay(time_ms).then(function() { // (B)
    return signRSA(sender.RSA.priv, sender.EC.pub.raw)
  })
}

const verif_derive = (sender, receiver, signature, time_ms = 1000) => {
  return delay(time_ms).then(function() { // (B)
    return verifRSA(sender.RSA.pub, signature, sender.EC.pub.raw).then(result => {
      if (result) {
        // if verification is ok, import Alice's public key as CryptoKey
        return crypto.subtle.importKey("raw", sender.EC.pub.raw, {
          name: "ECDH",
          namedCurve: "P-256"
        }, true, [])
      } else {
        return Promise.reject();
      }
    }).then(senderPublicKey => {
      console.log("Public key verification :  ok")
      // Bob : with Alice Public key and his EC private key, we derive a symmetric key
      // Suppose the EC public keys exhange and signature verification is ok Let's
      // derive the same symmetric key
      return deriveKeyECDH(senderPublicKey, receiver.EC.priv, "aes-gcm", 128)
    })
  })
}

const getRandomIntInclusive = (min, max) => {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min; //The maximum is inclusive and the minimum is inclusive
}

function singleTest() {
  return genECkeys().then((result) => {
    console.log("Generation of ephemeral EC keys")
    console.log("Alice -> Bob : encryption")
    return sign_send(alice, delayTime).then(result => {
      return verif_derive(alice, bob, result, delayTime).then(derivedKey => {
        console.log("Bob : derivedKey", derivedKey)
        return encrypt(derivedKey, JSON.stringify(apiData), '1.0.0').then(
          encryptedJson => {
            console.log(encryptedJson)
            console.log("Bob -> Alice : decryption")
            return sign_send(bob, delayTime).then(result => {
              return verif_derive(bob, alice, result, delayTime).then(secondDerivedKey => {
                console.log("Alice : derivedKey", secondDerivedKey)
                return decrypt(secondDerivedKey, encryptedJson).then(decryptedJson => {
                  console.log(decryptedJson) // { POI_1: "Tour eiffel", POI_2: "Cafeteria"}

                })
              })
            })
          }
        )
      })
    })
  })
}

const callTest = (counter) => {
  console.log("calltest");
  apiData["POI_1"] = randomString(getRandomIntInclusive(10, 20))
  apiData["POI_2"] = randomString(getRandomIntInclusive(10, 100))
  singleTest().then(result => {
    console.log("Test finished")
    if (counter > 0)
      callTest(counter - 1)
  })
}

const alice = {
  RSA: {},
  EC: {}
}

const bob = {
  RSA: {},
  EC: {}
}
var MK = []

const apiData = {
  POI_1: 'Tour eiffel',
  POI_2: 'Bastille',
  POI_3: 'Cafeteria'
}

const delayTime = 1000

console.log("Start test")
console.log("Generation of long term RSA keys for A and B")
generateRSAKeys().then((result) => {

  callTest(5)

})

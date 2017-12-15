const alice = {
  RSA: {},
  EC: {}
}

const bob = {
  RSA: {},
  EC: {}
}

Promise.all([genRSAKeyPair(), genRSAKeyPair(), genECKeyPair(), genECKeyPair()]).then(
  values => {
    alice.RSA.pub = values[0].publicKey
    alice.RSA.priv = values[0].privateKey
    bob.RSA.pub = values[1].publicKey
    bob.RSA.priv = values[1].privateKey
    alice.EC.pub = values[2].publicKey
    alice.EC.priv = values[2].privateKey
    bob.EC.pub = values[3].publicKey
    bob.EC.priv = values[3].privateKey
    console.log("1.1")
    Promise.all([
      exportKeyRaw(bob.EC.pub),
      exportKeyRaw(alice.EC.pub)
    ]).then(values => {
      bob.EC.pub.raw = values[0]
      alice.EC.pub.raw = values[1]

      console.log(alice)
      //Alice -> Bob : Alice signs her EC pub key with Bob RSA private Key
      signRSA(alice.RSA.priv, alice.EC.pub.raw).then(signature => {
        // Alice sends her signature and EC public key to Bob Bob checks the signature
        // and the received public key
        verifRSA(alice.RSA.pub, signature, alice.EC.pub.raw).then(result => {
          if (result) {
            // if verification is ok, import Alice's public key as CryptoKey
            return crypto.subtle.importKey("raw", alice.EC.pub.raw, {
              name: "ECDH",
              namedCurve: "P-256"
            }, true, []).then(AlicePublicKey => {
              console.log("verification ok")
              // Bob : with Alice Public key and his EC private key, we derive a symmetric key
              // Suppose the EC public keys exhange and signature verification is ok Let's
              // derive the same symmetric key
              Promise.all([
                deriveKeyECDH(AlicePublicKey, bob.EC.priv, "aes-gcm", 128),
                deriveKeyECDH(bob.EC.pub, alice.EC.priv, "aes-gcm", 128)
              ]).then(values => {
                //if we obtain the same derived key : test is succesful
                console.log(values[0]);
                console.log(values[1]);
                if (values[0].toString() == values[1].toString()) {
                  console.log("Test succesful, both derived symmetric keys are equals")
                } else {
                  console.log("Test fails both derived symmetric keys are not equals")
                }
              }, logFail)
            }, logFail)
          } else {
            console.log("verification fails")
          }
        })
      })
    })
  }
)

# Masq Crypto Library

Promise-based crypto library used by Qwant Masq. It allows applications to encrypt and decrypt JSON data. The cipher used is AES GCM which provides integrity and confidentiality.

The library includes a passphrase generator and key derivation using the PBKDF2 algorithm. 

# Install

## Developer

```
git clone https://github.com/QwantResearch/masq-crypto.git
cd masq-crypto
npm install
```

# Example usage

##Add the client JS reference in your page:

```JavaScript
<script type="text/javascript" src="src/index.js"></script>
```

##Using the crypto library in your app:

```JavaScript
// EXAMPLE
const apiData = { POI_1: 'Tour eiffel', POI_2: 'Cafeteria'}

// If no passphrase is given, it will be generated.
deriveKey('').then(function (derivedKey) {
  // encryption
  encrypt(derivedKey, JSON.stringify(apiData), '1.0.0').then(function (encryptedJson) {
    console.log(encryptedJson)
    // Object { ciphertext: "cb9a804…", iv: "145a65b6535d00b5a3cce475", version: "1.0.0" }

    // decryption
    decrypt(derivedKey, encryptedJson).then(function (decryptedJson) {
      console.log(decryptedJson) // { POI_1: "Tour eiffel", POI_2: "Cafeteria"}
    })
  })
})
```
##ECDHE example :
In order to provide Perfect Forward Secrecy, we implement ECDHE.
We follow this pattern for now : ECDHE-RSA-AES128-GCM-SHA256
Where :
- Authentication is provided with RSA-PSS signature and verification (EC public keys are signed during exchange)
- Encryption is based on the cipher AES-GCM (which provide confidentiality and integrity)
- The derived AES-GCM symmetric key is used only one time for now

In this example, we illustrate a communication between two users : Alice and Bob. 
Here are the steps :
1) Generation of long-term RSA-PSS key pairs (the exchange of the corresponding public keys is out of the scope, this exchange can be done through QR-code)
2) If we want to exhange data, we first generate a ephemeral EC key pairs for each users
3) Each EC public key is signed with the user RSA private key and send over an (unsecured) channel to the other user
4) Each user verifies the received EC public key 
5) If both verification is ok, they derived a common symmetric key with the received EC public key and their own private EC key.
6) They encrypt data with the derived symmetric key with AES-GCM cipher.


```JavaScript
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
```



## Utils functions 
Useful functions to convert between ArrayBuffer - String and hexString, examples:

```JavaScript
let testRes = ''
if (toString(toArray('bonjour')) !== 'bonjour') { testRes = 'Fail' } else { testRes = 'Success' }
console.log('array <-> ascii conversion :' + testRes)
if (bufferToHexString(hexStringToBuffer('11a1b2')) !== '11a1b2') { testRes = 'Fail' } else { testRes = 'Success' }
console.log('array <-> hexString conversion : ' + testRes)
```

## License

Apache-2.0

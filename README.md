# Masq Crypto Library

[![](https://img.shields.io/badge/project-Masq-7C4DFF.svg?style=flat-square)](https://github.com/QwantResearch/masq-store)

![Masq Logo](https://i.imgur.com/qZ3dq0Q.png)

Promise-based crypto library used by Qwant Masq. It allows applications to perform all cryptographic operations. For now, we have already implemented AES encryption (AES-GCM by default), RSA-PSS signature and verification and ECDH for Perfect Forward Secrecy (PFS). Moreover a  key derivation algorithm (PBKDF2) is included. 

The library relies on WebCryptoApi, the only native cryptography available in browsers. However, in a medium term, we will support other cryptographic implementations in case of native applications that do not support WebCryptoApi. 





# Install

## Developer

```
git clone https://github.com/QwantResearch/masq-crypto.git
cd masq-crypto
npm install
```
# Demo
In the main html page, the user has access to 4 different pages. 

## A test page
This page checks the main cryptographic functionalities. A terminal version is available by running :
```bash
npm test
```


## A Perfect Forward PFS demo
A web socket based PFD demo is performed on this page. 

On two browsers, follow those steps :

1) Open the demo page (masq-crypto/src/example/pfs/pfs.html).
2) Choose a username : alice and bob (if you choose exactly those names a confirmation message will 
appear below each user's picture when RSA keys are loaded).
3) Click on **Init** button, the first time a RSA key pair will be generated and stored on indexeddb. Next times, 
the key pair will be loaded from storage.
4) Click on **Request RSA public Key** in order to receive the other user's RSA public key. This key
is used to sign and verify the EC public key during ECDHE.
5) Click on **Start ECDH** to send a message.

**NOTE:** You can see all the communications steps between Alice and Bob in the console log.

## Demo page

In this page, the main cryptographic operations are presented :
- AES operations
- RSA
- ECDH

## Performance comparison between ECDSA and RSA-PSS signature
The question of choosing either ECDSA or RSA-PSS could be asked, as a indicator we have implemented 
a small performance test by signing and verifying a message a hundred times. 
Please specify the same "strength" between both ciphers, i.e. modulus length, hash name for RSA-PSS and elliptic curve for ECDSA. 

# Example usage

## Add the client JS reference in your page:

```HTML
 <script type="text/javascript" src="dist/MasqCrypto.js"></script>
```
Or the minified version:

```HTML
<script type="text/javascript" src="dist/MasqCrypto.min.js"></script>
```

## Using the crypto library in your app:

You can instantiate the new AES, EC or RSA objects. If you want to use the default parameters you only 
need to pass an empty parameters object {}. 

```JavaScript
// An AES instance to encrypt and decrypt data. 
const cipherAES = new MasqCrypto.AES(
    {
      mode: MasqCrypto.aesModes.GCM,
      key: null,
      keySize: 128
    }
  )
  
 // An EC instance for ECDH, allow to establish a shared secret over an insecure channel.
 const cipherEC = new MasqCrypto.EC(
  {
    name: 'ECDH',
    curve: 'P-256'
  }
)

// A RSA instance for signature and verification, based on RSA-PSS.
const cipherRSA = new MasqCrypto.RSA(
  {
    name: 'RSA-PSS',
    hash: 'SHA-256',
    modulusLength: 4096
  }
)
```
**NOTE:** You can find a fully working demo in the `/example/demo` dir.

## AES encryption decryption example
```JavaScript
// EXAMPLE
const apiData = {
  POI_1: 'Tour Eiffel',
  POI_2: 'Bastille',
  POI_3: 'Cafeteria'
}

// We can generate the AES key before and give as parameter of AES instance.
// To see how to generate it with genAESKey(), please see the demo.
const AESKey = window.crypto.getRandomValues(new Uint8Array(16))

// An AES instance to encrypt and decrypt data. 
const cipherAES = new MasqCrypto.AES(
    {
      mode: MasqCrypto.aesModes.GCM,
      key: AESKey,
      keySize: 128
    }
  )
 // optionnal : we add additionalData:"1.0.0"
  let additionalData = '1.0.0'
  cipherAES.additionalData = additionalData
  
  console.log('AES-GCM demo : ')
  console.log('Input : ', apiData)
  console.log('Authenticated data [optional] : ', additionalData)
  cipherAES.encrypt(JSON.stringify(apiData))
    .then(encryptedJSON => {
      // console.log(encryptedJSON)
      Object.keys(encryptedJSON).forEach(key => {
        console.log(`${key} : ${encryptedJSON[key]}`)
      })
      return cipherAES.decrypt(encryptedJSON)
    })
    .then(decryptedJSON => {
      console.log('Decrypted input :', decryptedJSON)
    })
    .catch(err => console.log(err))

// Example of output
// AES-GCM demo : 
// Input :  
// Object { POI_1: "Tour eiffel", POI_2: "Bastille", POI_3: "Cafeteria" }
// Authenticated data [optional] :  1.0.0
// ciphertext : 247e63bb7709219083...c39cbe579f208222cfeb1dc19a28d060439ffc69
// iv : c1c441c4b1b4d65ce6556ac6
// version : 1.0.0
// Decrypted input : {"POI_1":"Tour eiffel","POI_2":"Bastille","POI_3":"Cafeteria"}
    
}
```

## ECDHE example :

In order to provide Perfect Forward Secrecy, we have implemented ECDHE.
For this demo we are using the following scheme : ECDHE-RSA-AES128-GCM-SHA256, where :
- Authentication is provided with RSA-PSS signature and verification (EC public keys are signed during exchange),
- Encryption relies on the cipher AES-GCM (which provides both confidentiality and integrity);
- The derived AES-GCM symmetric key is used only one time.

In this example, we illustrate a communication between two users : Alice and Bob. 
Here are the steps :
1) Generation of long-term RSA-PSS key pairs (the exchange of the corresponding public keys is out of the scope).
2) Before sending data, we first generate a ephemeral EC key pairs for each user.
3) Each EC public key is signed with the other user's RSA private key and sent over an (unsecured) channel.
4) Each user verifies the received EC public key.
5) If both verifications are succesful, Alice and Bob derive a common AES-GCM symmetric key using the received EC public key and their own private EC key.
6) Finally, they encrypt/decrypt data with the derived symmetric key.

```JavaScript
const aliceEC = new MasqCrypto.EC({})
  const bobEC = new MasqCrypto.EC({})

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
      console.log('EC public keys are exchanged ... and verified normally.')
      // Bob : with Alice Public EC key and his EC private key, we derive a symmetric key
      console.log("Bob derives a symmetric key with Alice's Public EC key and his EC private key ")
      return bobEC.deriveKeyECDH(AliceECPubKey, 'aes-gcm', 128)
    })
    .then(derivedSymmetricAESKeyBob => {
      console.log(derivedSymmetricAESKeyBob)
      aliceEC.importKeyRaw(bob.ECRawPubKey).then(BobECPubKey => {
        aliceEC.deriveKeyECDH(BobECPubKey, 'aes-gcm', 128)
          .then(derivedSymmetricAESKeyAlice => {
            console.log("Alice derives a symmetric key with Bob's Public EC key and her EC private key ")
            console.log(derivedSymmetricAESKeyAlice)
          }).catch(err => console.log(err))
      }).catch(err => console.log(err))
    })
    .catch(err => console.log(err))
}
```



## Utils functions 
Useful functions and key derivation

```JavaScript
let passPhrase = ''
const generatePassPhrase = () => {
  console.log('Passphrase generation : ')
  passPhrase = MasqCrypto.utils.randomString(18)
  console.log('Only for a demo of PBKDF2 !!!')
  console.log('Passhrase : ', passPhrase)
}

const derive = () => {
  let iterations = 10000
  console.log('PBKDF2 demo : ')
  MasqCrypto.utils.deriveKey(passPhrase, MasqCrypto.utils.toArray('theSalt'), iterations)
    .then(derivedKey => {
      console.log('Salt : ', MasqCrypto.utils.toArray('theSalt'))
      console.log('Iterations : ', iterations)
      console.log('Derived Key : ', derivedKey)
    })
    .catch(err => console.log(err))
}
```

## License

Apache-2.0

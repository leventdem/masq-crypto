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

Add the client JS reference in your page:

```JavaScript
<script type="text/javascript" src="src/index.js"></script>
```
Using the crypto library in your app:

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

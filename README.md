# Masq Crypto Library

Promise-based crypto library for Qwant Masq. It allows applications encrypt and decrypt JSON object. The cipher used is AES GCM which provides integrity and confidentiality. 
The library provides a passphrase generator and the PBKDF2 algorithm. 

# Install

## Developer

```
git clone https://github.com/QwantResearch/masq-crypto.git
cd masq-crypto
```

# Example usage

Add the client JS reference in your page:

```JavaScript
<script type="text/javascript" src="common.js"></script>
<script type="text/javascript" src="crypto.js"></script>
```
Using the crypto library in your app:

```JavaScript
console.log('start')
var apiData = { POI_1: 'Tour eiffel', POI_2: 'Cafeteria'}

// If no passphrase is given, it will be generated.
setUserKey('').then(function () {
  // encryption
  encryptJSON(JSON.stringify(apiData), '1.0.0').then(function (encryptedJson) {
    console.log(encryptedJson)
    // {"ciphertext":"f7bd4...a1fe0fd9","iv":"a033ff25534d21775be6e8c9","version":"1.0.0"}

    // decryption
    decryptJSON(JSON.parse(encryptedJson)).then(function (decryptedJson) {
      console.log(bytesToASCIIString(decryptedJson))
      // "{\"POI_1\":\"Tour eiffel\",\"POI_2\":\"Cafeteria\"}"
    })
  })
})
```

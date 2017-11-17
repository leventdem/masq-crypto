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
Using the client library in your app:

```JavaScript
console.log('start')
setUserKey('').then(function () {
  loadJson().then(function (encryptedJson) {
    console.log(encryptedJson)
    decryptJson(encryptedJson).then(function (decryptedJson) {
      console.log(decryptedJson)
    })
  })
})
```

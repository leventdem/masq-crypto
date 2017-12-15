// EXAMPLE
const apiData = {
  POI_1: 'Tour eiffel',
  POI_2: 'Cafeteria'
}

// If no passphrase is given, it will be generated.
deriveKey('').then(function(derivedKey) {
  // encryption
  encrypt(derivedKey, JSON.stringify(apiData), '1.0.0').then(
    function(encryptedJson) {
      console.log(encryptedJson)
      // Object { ciphertext: "cb9a804…", iv: "145a65b6535d00b5a3cce475", version:
      // "1.0.0" } decryption
      decrypt(derivedKey, encryptedJson).then(function(decryptedJson) {
        console.log(decryptedJson) // { POI_1: "Tour eiffel", POI_2: "Cafeteria"}
      })
    }
  )
})

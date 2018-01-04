import AES from './AES'

// EXAMPLE
const apiData = {
  POI_1: 'Tour eiffel',
  POI_2: 'Bastille',
  POI_3: 'Cafeteria'
}

// We generate a 128 bits key with crypto random
const AESKey = window.crypto.getRandomValues(new Uint8Array(16))
// We create an AES object with some paramters
const AES = new AES(
  {
    mode: 'aes-gcm',
    key: AESKey,
    keySize: 128
  }
)
// optionnal : we add additionalData:"1.0.0"
AES.setAdditionalData('1.0.0')

AES.encrypt(JSON.stringify(apiData))
  .then(encryptedJSON => {
    console.log(encryptedJSON)
    return AES.decrypt(encryptedJSON)
  })
  .then(decryptedJSON => console.log(decryptedJSON))
  .catch(err => console.log(err))

/*
  encryptedJSON : 
  ciphertext: "102758a3ab...697581f"
  iv: "c9c5f5c65dcdb5fd3b70a088"
  version: "1.0.0"
  
  decryptedJSON : 
  {"POI_1":"Tour eiffel","POI_2":"Bastille","POI_3":"Cafeteria"}
*/

// Generate an AES key
const aes = new AES(
  {
    mode: 'aes-gcm',
    keySize: 128
  }
)
aes.genAESKey()
  .then(console.log)
  .catch(err => console.log(err))
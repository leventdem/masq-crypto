'use strict';

/*
 * User interface :
 * Event and button : only for demo purpose
 */

document.addEventListener('DOMContentLoaded', function () {
  var el = null;
  // AES
  el = document.getElementById('aesGCM');
  if (el) {
    el.addEventListener('click', function (e) {
      aesGCM();
    });
  }
  el = document.getElementById('aesCBC');
  if (el) {
    el.addEventListener('click', function (e) {
      aesCBC();
    });
  }
  el = document.getElementById('aesCTR');
  if (el) {
    el.addEventListener('click', function (e) {
      aesCTR();
    });
  }
  el = document.getElementById('generatePassPhrase');
  if (el) {
    el.addEventListener('click', function (e) {
      generatePassPhrase();
    });
  }
  el = document.getElementById('derive');
  if (el) {
    el.addEventListener('click', function (e) {
      derive();
    });
  }
  el = document.getElementById('masterKeyEncrypt');
  if (el) {
    el.addEventListener('click', function (e) {
      masterKeyEncrypt();
    });
  }
  el = document.getElementById('masterKeyDecrypt');
  if (el) {
    el.addEventListener('click', function (e) {
      masterKeyDecrypt();
    });
  }
  el = document.getElementById('computeHash');
  if (el) {
    el.addEventListener('click', function (e) {
      computeHash();
    });
  }
  el = document.getElementById('ecdh');
  if (el) {
    el.addEventListener('click', function (e) {
      ecdh();
    });
  }
});

var apiData = {
  POI_1: 'Tour eiffel',
  POI_2: 'Bastille',
  POI_3: 'Cafeteria'

  // see aesCBC to have an exmaple with AES.genAESKey()
};var aesGCM = function aesGCM() {
  // We generate a 128 bits key with crypto random
  var AESKey = window.crypto.getRandomValues(new Uint8Array(16));
  // We create an AES object with some paramters
  var cipherAES = new MasqCrypto.AES({
    mode: MasqCrypto.aesModes.GCM,
    key: AESKey,
    keySize: 128
  });
  // optionnal : we add additionalData:"1.0.0"
  var additionalData = '1.0.0';
  cipherAES.additionalData = additionalData;
  console.log('AES-GCM demo : ');
  console.log('Input : ', apiData);
  console.log('Authenticated data [optional] : ', additionalData);
  cipherAES.encrypt(JSON.stringify(apiData)).then(function (encryptedJSON) {
    // console.log(encryptedJSON)
    Object.keys(encryptedJSON).forEach(function (key) {
      console.log(key + ' : ' + encryptedJSON[key]);
    });
    return cipherAES.decrypt(encryptedJSON);
  }).then(function (decryptedJSON) {
    console.log('Decrypted input :', decryptedJSON);
  }).catch(function (err) {
    return console.log(err);
  });
};
var aesCTR = function aesCTR() {
  // We generate a 128 bits key with crypto random
  var AESKey = window.crypto.getRandomValues(new Uint8Array(16));
  // We create an AES object with some paramters
  var cipherAES = new MasqCrypto.AES({
    mode: MasqCrypto.aesModes.CTR,
    key: AESKey,
    keySize: 128
  });

  console.log('AES-CTR demo : ');
  console.log('Input : ', apiData);
  cipherAES.encrypt(JSON.stringify(apiData)).then(function (encryptedJSON) {
    // console.log(encryptedJSON)
    Object.keys(encryptedJSON).forEach(function (key) {
      console.log(key + ' : ' + encryptedJSON[key]);
    });
    return cipherAES.decrypt(encryptedJSON);
  }).then(function (decryptedJSON) {
    console.log('Decrypted input :', decryptedJSON);
  }).catch(function (err) {
    return console.log(err);
  });
};
var aesCBC = function aesCBC() {
  // We create an AES object with some paramters
  var cipherAES = new MasqCrypto.AES({
    mode: MasqCrypto.aesModes.CBC,
    keySize: 128
  });

  console.log('AES-CBC demo : ');
  console.log('Input : ', apiData);
  cipherAES.genAESKey().then(function (key) {
    cipherAES.key = key;
  }).then(function () {
    return cipherAES.encrypt(JSON.stringify(apiData));
  }).then(function (encryptedJSON) {
    // console.log(encryptedJSON)
    Object.keys(encryptedJSON).forEach(function (key) {
      console.log(key + ' : ' + encryptedJSON[key]);
    });
    return cipherAES.decrypt(encryptedJSON);
  }).then(function (decryptedJSON) {
    console.log('Decrypted input :', decryptedJSON);
  }).catch(function (err) {
    return console.log(err);
  });
};

var computeHash = function computeHash() {
  MasqCrypto.utils.hash('hello world').then(function (digest) {
    console.log('Digest :', MasqCrypto.utils.bufferToHexString(digest));
  }).catch(function (err) {
    return console.log(err);
  });
};

var passPhrase = '';
var generatePassPhrase = function generatePassPhrase() {
  console.log('Passphrase generation : ');
  passPhrase = MasqCrypto.utils.randomString(18);
  console.log('Only for a demo of PBKDF2 !!!');
  console.log('Passhrase : ', passPhrase);
};

var derive = function derive() {
  var iterations = 10000;
  console.log('PBKDF2 demo : ');
  MasqCrypto.utils.deriveKey(passPhrase, MasqCrypto.utils.toArray('theSalt'), iterations).then(function (derivedKey) {
    console.log('Salt : ', MasqCrypto.utils.toArray('theSalt'));
    console.log('Iterations : ', iterations);
    console.log('Derived Key : ', derivedKey);
  }).catch(function (err) {
    return console.log(err);
  });
};

var masterKeyEncrypt = function masterKeyEncrypt() {
  // We create an AES object with some paramters
  var cipherAES = new MasqCrypto.AES({
    mode: MasqCrypto.aesModes.GCM,
    keySize: 128
  });

  var iterations = 10000;
  var encryptedMasterKey = {};
  MasqCrypto.utils.deriveKey('secret', MasqCrypto.utils.toArray('theSalt'), iterations).then(function (derivedKey) {
    console.log('Salt : ', MasqCrypto.utils.toArray('theSalt'));
    console.log('Iterations : ', iterations);
    console.log('Derived Key : ', derivedKey);
    cipherAES.key = derivedKey;
    return cipherAES.genAESKey();
  }).then(function (key) {
    return cipherAES.exportKeyRaw(key);
  }).then(function (rawKey) {
    var rawKeyHexStr = MasqCrypto.utils.bufferToHexString(new Uint8Array(rawKey));
    console.log('aes key', rawKeyHexStr);
    return cipherAES.encrypt(rawKeyHexStr);
  }).then(function (encryptedJSON) {
    encryptedMasterKey = encryptedJSON;
    // console.log(encryptedJSON)
    Object.keys(encryptedJSON).forEach(function (key) {
      console.log(key + ' : ' + encryptedJSON[key]);
    });
  }).catch(function (err) {
    return console.log(err);
  });
};
var masterKeyDecrypt = function masterKeyDecrypt() {
  // We create an AES object with some paramters
  var cipherAES = new MasqCrypto.AES({
    mode: MasqCrypto.aesModes.GCM,
    keySize: 128
  });

  var iterations = 10000;
  MasqCrypto.utils.deriveKey('secret', MasqCrypto.utils.toArray('theSalt'), iterations).then(function (derivedKey) {
    console.log('Salt : ', MasqCrypto.utils.toArray('theSalt'));
    console.log('Iterations : ', iterations);
    console.log('Derived Key : ', derivedKey);
    return cipherAES.importKeyRaw(derivedKey);
  }).then(function (key) {
    cipherAES.key = key;
    var encryptedMasterKey = {
      ciphertext: '01a834669ebd48a3ab971d375e8d1bb1a5eb11c9e0e1c5d26bae2ea5e2c8bd71dbeac1e1d23a27619a34b3c1bb21e94b',
      iv: '05d0437a8eb985b7384a6880',
      version: ''
    };
    return cipherAES.decrypt(encryptedMasterKey);
  }).then(function (decryptedJSON) {
    // master key must be : 2b4b1b8bceebecbcaed663081469a7c3
    console.log(decryptedJSON);
  }).catch(function (err) {
    return console.log(err);
  });
};

var ecdh = function ecdh() {
  var aliceEC = new MasqCrypto.EC({});
  var bobEC = new MasqCrypto.EC({});

  var generateECKeys = function generateECKeys() {
    console.log('Generation of ephemeral EC keys for Alice and Bob');
    return Promise.all([aliceEC.genECKeyPair(), bobEC.genECKeyPair({})]);
  };

  var exportRawKeys = function exportRawKeys() {
    console.log('Extraction of raw EC public keys for Alice and Bob');
    return Promise.all([bobEC.exportKeyRaw(), aliceEC.exportKeyRaw()]);
  };

  // Used to store the raw EC public Keys
  var alice = {};
  var bob = {};

  console.log('Start test');

  generateECKeys().then(exportRawKeys).then(function (rawKeys) {
    bob.ECRawPubKey = rawKeys[0];
    alice.ECRawPubKey = rawKeys[1];
    return bobEC.importKeyRaw(alice.ECRawPubKey);
  }).then(function (AliceECPubKey) {
    console.log('EC public keys are exchanged ... and verified normally.');
    // Bob : with Alice Public EC key and his EC private key, we derive a symmetric key
    console.log("Bob derives a symmetric key with Alice's Public EC key and his EC private key ");
    return bobEC.deriveKeyECDH(AliceECPubKey, 'aes-gcm', 128);
  }).then(function (derivedSymmetricAESKeyBob) {
    console.log(derivedSymmetricAESKeyBob);
    aliceEC.importKeyRaw(bob.ECRawPubKey).then(function (BobECPubKey) {
      aliceEC.deriveKeyECDH(BobECPubKey, 'aes-gcm', 128).then(function (derivedSymmetricAESKeyAlice) {
        console.log("Alice derives a symmetric key with Bob's Public EC key and her EC private key ");
        console.log(derivedSymmetricAESKeyAlice);
      }).catch(function (err) {
        return console.log(err);
      });
    }).catch(function (err) {
      return console.log(err);
    });
  }).catch(function (err) {
    return console.log(err);
  });
};
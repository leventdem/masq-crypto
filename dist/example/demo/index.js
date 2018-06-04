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
  el = document.getElementById('ecdh');
  if (el) {
    el.addEventListener('click', function (e) {
      ecdh();
    });
  }
  el = document.getElementById('masterKey');
  if (el) {
    el.addEventListener('click', function (e) {
      masterKey();
    });
  }
  el = document.getElementById('wrap');
  if (el) {
    el.addEventListener('click', function (e) {
      wrap();
    });
  }
  el = document.getElementById('unwrap');
  if (el) {
    el.addEventListener('click', function (e) {
      unwrap();
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

var masterKey = function masterKey() {
  // We create an AES object with some paramters
  var salt = Uint8Array.from([126, 252, 235, 252, 60, 233, 252, 81, 130, 147, 61, 241, 179, 85, 95, 23]);
  console.log(salt);
  MasqCrypto.utils.deriveKey('helloboys', salt).then(function (key) {
    console.log(key);

    var enc = { ciphertext: 'e3a2dc349a79bbab0e823984a66418ab66c2', iv: 'e9d86958f35ff31f78a5ae43', version: '' };
    var cipherAES = new MasqCrypto.AES({ key: key });
    cipherAES.decrypt(enc).then(function (res) {
      console.log(res);
    });
  });
};
var resOfWrapKey = null;
var wrap = function wrap() {
  console.log('1.0');
  var salt = Uint8Array.from([126, 252, 235, 252, 60, 233, 252, 81, 130, 147, 61, 241, 179, 85, 95, 23]);
  MasqCrypto.utils.deriveKey('hello', salt).then(function (key) {
    console.log(key);
    var cipherAES = new MasqCrypto.AES({ key: key });
    cipherAES.genAESKey().then(function (aesKey) {
      console.log(aesKey);
      cipherAES.wrapKey(aesKey, 'raw').then(function (res) {
        console.log(res);
        cipherAES.unwrapKey(res.encryptedMasterKey, res.iv, 'raw').then(function (unwrapped) {
          console.log(unwrapped);
          resOfWrapKey = res;
        });
      });
    });
  });
};

var unwrap = function unwrap() {
  console.log('2.0');
  var salt = Uint8Array.from([126, 252, 235, 252, 60, 233, 252, 81, 130, 147, 61, 241, 179, 85, 95, 23]);
  MasqCrypto.utils.deriveKey('hello', salt).then(function (key) {
    var cipherAES = new MasqCrypto.AES({ key: key });
    cipherAES.unwrapKey(resOfWrapKey.encryptedMasterKey, resOfWrapKey.iv, 'raw').then(function (unwrapped) {
      console.log(unwrapped);
    }).catch(function (err) {
      return console.log(err);
    });
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
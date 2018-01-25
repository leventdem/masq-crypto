'use strict';

var apiData = {
  POI_1: 'Tour eiffel',
  POI_2: 'Bastille',
  POI_3: 'Cafeteria'
};

var parameters = {
  // syncserver: 'ws://10.100.50.17:8080/',
  syncserver: 'wss://sync-beta.qwantresearch.com:8080/',
  syncroom: 'cryyyyptoooo',
  debug: true
};
var wsClient = void 0;
var wsTimeout = 10000;
var clientId = '';

var log = function log() {
  for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
    args[_key] = arguments[_key];
  }

  var reg = function reg(all, cur) {
    if (typeof cur === 'string') {
      return all + cur;
    } else {
      return all + cur.toString();
    }
  };
  if (parameters.debug) {
    console.log('[Masq Crypto]', args.reduce(reg, ''));
  }
};

/**
 * Print error messages
 *
 * @param {Error} err Error message
 */
var logFail = function logFail(err) {
  console.log(err);
};

/**
 * Configuration of Indexeddb for data localforage
 */
localforage.config({
  driver: localforage.INDEXEDDB, // Force WebSQL same as using setDriver()
  name: 'MasqCryptoPFSDemo',
  version: 1.0,
  storeName: 'myStore', // Should be alphanumeric, with underscores.
  description: 'Long term RSA keys and other devices RSA public keys are stored here.'
});

var sendMessage = function sendMessage(msg) {
  if (wsClient.readyState === wsClient.OPEN) {
    log('*** sendMEssage : ', msg.type, ' ***');
    wsClient.send(JSON.stringify(msg));
  } else {
    log('Socket closed !');
  }
};

var delay = function delay(ms) {
  log('wait ...');
  return new Promise(function (resolve, reject) {
    setTimeout(resolve, ms); // (A)
  });
};

var initWSClient = function initWSClient(server, room) {
  return new Promise(function (resolve, reject) {
    room = room || 'foo';
    // const wsUrl = url.resolve(server, room)
    var wsUrl = window.URL !== undefined ? new window.URL(room, server) : server + room;

    var ws = new window.WebSocket(wsUrl);

    ws.onopen = function () {
      // throttle openning new sockets
      if (window.timerID) {
        window.clearInterval(window.timerID);
        delete window.timerID;
      }
      console.log('Connected to Sync server at ' + wsUrl);
      // TODO: check if we need to sync with other devices
      return resolve(ws);
    };

    ws.onerror = function (event) {
      var err = 'Could not connect to Sync server at ' + wsUrl;
      console.log(err);
      return reject(err);
    };
  });
};

/**
 * Initialize the WebSocket client. This allows us to synchronize with the
 * other devices for the user.
 *
 * The current implementation unfortunately mutates the wsClient variable.
 */

var initWs = function initWs(params) {
  if (wsClient && wsClient.readyState === wsClient.OPEN) {
    return;
  }
  if (!params) {
    params = parameters;
  }
  console.log('Initializing WebSocket with params:', params);
  initWSClient(params.syncserver, params.syncroom).then(function (ws) {
    wsClient = ws;

    wsClient.onmessage = function (event) {
      try {
        var msg = JSON.parse(event.data);
        switch (msg.type) {
          case 'hello':
            log('*** onMEssage : ', msg.type, ' ***');
            receiveHello(msg.name);
            break;
          case 'hello_ack':
            log('*** onMEssage : ', msg.type, ' ***');
            receiveHello_ack(msg.name);
            break;
          case 'requestRSAPub':
            log('*** onMEssage : ', msg.type, ' ***');
            receiveRequestRSAPub(msg.name);
            break;
          case 'requestRSAPub_ack':
            log('*** onMEssage : ', msg.type, ' ***');
            receiveRequestRSAPub_ack(msg);
            break;
          case 'startECDH':
            log('*** onMEssage : ', msg.type, ' ***');
            receiveStartECDH(msg);
            break;
          case 'startECDH_ack':
            log('*** onMEssage : ', msg.type, ' ***');
            receiveStartECDH_ack(msg);
            break;
          case 'data':
            log('*** onMEssage : ', msg.type, ' ***');
            receiveData(msg);
            break;

          default:
            log('onMEssage : ', msg);
            break;
        }
      } catch (err) {
        log(err);
      }
    };

    wsClient.onclose = function (event) {
      log('WebSocket connection closed');
      // Try to reconnect if the connection was closed
      if (event.wasClean === false || event.code === 1006) {
        log('..trying to reconnect');
        if (!window.timerID) {
          window.timerID = setInterval(function () {
            initWs(parameters);
          }, wsTimeout);
        }
      }
    };
  }).catch(function (err) {
    log(err);
  });
};

var sendHello = function sendHello() {
  log('send hello message');
  sendMessage({ type: 'hello', name: clientId });
};

var receiveHello = function receiveHello(name) {
  // First we response to hello msg, the sender could this way check if he altough
  // has RSA public key
  sendHello_ack();
  checkRSAPub(name).then(function (res) {
    if (res) {
      log('I already have the RSA public key of ', name);
    } else {
      sendRequestRSAPub();
    }
  });
};

var sendHello_ack = function sendHello_ack() {
  // log('Response to hello message with hello_ack')
  sendMessage({ type: 'hello_ack', name: clientId });
};

var receiveHello_ack = function receiveHello_ack(name) {
  checkRSAPub(name).then(function (res) {
    if (res) {
      log('I already have the RSA public key of ', name);
      log('***Now, both entities have exchanged their RSA public keys***');
    } else {
      sendRequestRSAPub();
    }
  }).catch(logFail);
};

var sendRequestRSAPub = function sendRequestRSAPub() {
  log('Response to hello message with hello_ack');
  var data = {
    type: 'requestRSAPub',
    name: clientId
  };
  sendMessage(data);
};

var receiveRequestRSAPub = function receiveRequestRSAPub(name) {
  log('*** ', clientId, ' : ', name, ' asks my RSA public Key');
  sendRequestRSAPub_ack(name);
};

var sendRequestRSAPub_ack = function sendRequestRSAPub_ack(name) {
  log('*** ', clientId, ' : sends the RSA public Key to ', name);
  cipherRSA.exportRSAPubKeyRaw(cipherRSA.publicKey).then(function (rawKey) {
    // console.log('my RSA Public key', rawKey)
    var data = {
      type: 'requestRSAPub_ack',
      name: clientId,
      publicKeyRSA: rawKey
    };
    sendMessage(data);
  }).catch(logFail);
};

var receiveRequestRSAPub_ack = function receiveRequestRSAPub_ack(msg) {
  log('*** ', clientId, ' : RSA pub key of ', msg.name, ' is received ***');
  // log(msg.publicKeyRSA)
  log('*** Now, both entities have exchanged their RSA public keys. ***');
  storeRSAPub(msg.name, msg.publicKeyRSA);
};

var sendStartECDH = function sendStartECDH(ECPublicKey, signature) {
  var data = {
    name: clientId,
    type: 'startECDH',
    key: ECPublicKey,
    signature: signature
  };
  sendMessage(data);
};

var receiveStartECDH = function receiveStartECDH(msg) {
  log('*** ', clientId, ' : Just received the EC pub key of ', msg.name, '  ***');
  checkReceivedECPubKey(msg.name, MasqCrypto.utils.hexStringToBuffer(msg.key), MasqCrypto.utils.hexStringToBuffer(msg.signature)).then(function (res) {
    if (res) {
      log('*** ', clientId, ' : verification of ', msg.name, ' EC public key : OK ***');
      generateECKeysAndSign().then(function (res) {
        sendStartECDH_ack(res.rawECPublicKey, res.signature);
        log('*** ', clientId, ' : computes the one time common AES secret key. ***');
        return cipherEC.deriveKeyECDH(MasqCrypto.utils.hexStringToBuffer(msg.key), 'aes-gcm', 128);
      }).then(function (aesKey) {
        cipherAES.key = aesKey;
      }).catch(logFail);
    } else {
      log('EC public key verification fails');
      Promise.reject(new Error('EC public key verification failed'));
      // TODO : send error message : the public key verification failes :
      // TODO -  MITM :-(
      // TODO - have you changed the Public RSA key ) sendRequestRSAPub()
    }
  }).catch(logFail);
};

var sendStartECDH_ack = function sendStartECDH_ack(ECPublicKey, signature) {
  var data = {
    name: clientId,
    type: 'startECDH_ack',
    key: ECPublicKey,
    signature: signature
  };
  sendMessage(data);
};

var receiveStartECDH_ack = function receiveStartECDH_ack(msg) {
  log('*** ', clientId, ' : ', msg.name, ' is ready to transfer files. ***');

  checkReceivedECPubKey(msg.name, MasqCrypto.utils.hexStringToBuffer(msg.key), MasqCrypto.utils.hexStringToBuffer(msg.signature)).then(function (res) {
    if (res) {
      log('*** ', clientId, ' : verification of ', msg.name, ' EC public key : OK ***');
      log('*** Now, both entities have exchanged and verified their EC public keys***');
      log('*** ', clientId, ' : computes the one time shared AES secret key. ***');
      return cipherEC.deriveKeyECDH(MasqCrypto.utils.hexStringToBuffer(msg.key), 'aes-gcm', 128).then(function (aesKey) {
        log('*** ', clientId, ' : encrypts a message and sends it. ***');
        encryptData(aesKey, 'dataForFuture');
      }).catch(logFail);
    } else {
      log('EC public key verification fails');
      Promise.reject(new Error('EC public key verification failed'));
      // TODO : send error message : the public key verification fails :
      // TODO -  MITM :-(
      // TODO - have you changed your Public RSA key => sendRequestRSAPub()
    }
  }).catch(logFail);
};

var sendData = function sendData(encryptedData) {
  var data = {
    name: clientId,
    type: 'data',
    data: encryptedData
  };
  sendMessage(data);
};

var receiveData = function receiveData(msg) {
  log('*** ', clientId, ' : ', msg.name, ' sends me data. Let us decrypt it ***');
  decryptData(msg.name, msg.data);
};

var encryptData = function encryptData(aesKey, dataToEncrypt) {
  cipherAES.key = aesKey;
  cipherAES.additionalData = '1.0.0';
  cipherAES.encrypt(JSON.stringify(apiData)).then(function (encryptedJson) {
    // log(encryptedJson)
    sendData(encryptedJson);
  }).catch(logFail);
};

var checkRSAPub = function checkRSAPub(name) {
  return localforage.getItem('connectedDevices').then(function (devices) {
    if (devices === null || !(name in devices)) {
      console.log('no RSA public key registered at all');
      console.log(devices);
      return false;
    } else {
      return true;
    }
  }).catch(logFail);
};

var checkReceivedECPubKey = function checkReceivedECPubKey(name, receivedKey, signature) {
  // Retrieve the RSA public key of name
  return localforage.getItem('connectedDevices').then(function (devices) {
    if (devices === null || !(name in devices)) {
      log('I could not find the RSA public Key of ', name);
      // TODO : call the RSA public key exchange messsage or procedure
      return false;
    }
    return cipherRSA.importRSAPubKeyRaw(devices[name]);
  }).then(function (senderRSAPublicKey) {
    return cipherRSA.verifRSA(senderRSAPublicKey, signature, receivedKey);
  }).then(function (result) {
    if (result) {
      return true;
    } else {
      return false;
    }
  }).catch(logFail);
};

var storeRSAPub = function storeRSAPub(name, key) {
  var listDevices = {};
  localforage.getItem('connectedDevices').then(function (devices) {
    if (devices === null) {
      listDevices[name] = key;
    } else {
      listDevices = devices;
      listDevices[name] = key;
    }
    localforage.setItem('connectedDevices', listDevices);
  }).then(function (res) {
    log('Public key stored');
  }).catch(logFail);
};

var decryptData = function decryptData(name, encryptedData) {
  cipherAES.decrypt(encryptedData).then(function (decryptedJson) {
    log(decryptedJson); // { POI_1: 'Tour eiffel', POI_2: 'Cafeteria'}
  }).catch(logFail);
};

var generateECKeysAndSign = function generateECKeysAndSign() {
  return cipherEC.genECKeyPair().then(function (key) {
    return cipherEC.exportKeyRaw().then(function (rawKey) {
      return cipherRSA.signRSA(rawKey).then(function (signature) {
        return (
          /**
           * We convert to hexString because when the receiver parses the message, the
           * obtained value are not Uint8array but Object which triggers an error with web
           * crypto for verification operation.
           */
          {
            rawECPublicKey: MasqCrypto.utils.bufferToHexString(rawKey),
            signature: MasqCrypto.utils.bufferToHexString(signature)
          }
        );
      }).catch(logFail);
    }).catch(logFail);
  }).catch(logFail);
};

/*
 * User interface :
 * Event and button : only for demo purpose
 */

document.addEventListener('DOMContentLoaded', function () {
  var el = document.getElementById('validateUserName');
  if (el) {
    el.addEventListener('click', function (e) {
      validateUser();
    });
  }

  el = document.getElementById('exchange_RSA_pub_keys');
  if (el) {
    el.addEventListener('click', function (e) {
      sendHello();
    });
  }
  el = document.getElementById('init');
  if (el) {
    el.addEventListener('click', function (e) {
      init();
    });
  }

  el = document.getElementById('start_ecdh');
  if (el) {
    el.addEventListener('click', function (e) {
      startECDH();
    });
  }

  // test perf
  el = document.getElementById('rsaPerf');
  if (el) {
    el.addEventListener('click', function (e) {
      startTestPerfRSA();
    });
  }
  el = document.getElementById('ecPerf');
  if (el) {
    el.addEventListener('click', function (e) {
      startTestPerfEC();
    });
  }
});

var startECDH = function startECDH() {
  log('*** ', clientId, ' : generates a new MasqCrypto.EC key pair for a single message encryption. ***');
  generateECKeysAndSign().then(function (res) {
    sendStartECDH(res.rawECPublicKey, res.signature);
  });
};

var validateUser = function validateUser() {
  clientId = document.getElementById('username').value;
  log(clientId);
  localforage.setItem('clientId', clientId).then(function (res) {
    // log('Using:' + MasqCrypto.driver())
    log('###Change username  into IndexedDB with key ', clientId, '###');
  }, logFail);
};

var checkRSA = function checkRSA() {
  return localforage.getItem('myRSA_Keys').then(function (keysFromlocalforage) {
    if (keysFromlocalforage === null) {
      log("No RSA keys at all, let's generate them for ", clientId);
      return cipherRSA.genRSAKeyPair().then(function (keys) {
        var RSAKeys = {};
        RSAKeys.public = keys.publicKey;
        RSAKeys.private = keys.privateKey;
        console.log(RSAKeys);
        return localforage.setItem('myRSA_Keys', RSAKeys);
      }).then(function (res) {
        // log('Using:' + MasqCrypto.driver())
        log('### Store RSA keys into IndexedDB with key myRSA_Keys ###');
        return 'ok';
      }).catch(logFail);
    } else {
      cipherRSA.publicKey = keysFromlocalforage.public;
      cipherRSA.privateKey = keysFromlocalforage.private;
      // console.log(cipherRSA)
      log('RSA keys retrieved from IndexedDB');
      return 'RSA keys retrieved from IndexedDB';
    }
  }).catch(logFail);
};

var checkClientId = function checkClientId() {
  return localforage.getItem('clientId').then(function (client) {
    if (client !== null) {
      clientId = client;
    }
    var el = document.getElementById('username');
    if (el) {
      el.value = clientId;
    }
    return clientId;
  }).catch(logFail);
};

var init = function init() {
  checkRSA().then(function (res) {
    if (clientId === 'bob' || clientId === 'alice') {
      document.getElementById('rsaKey' + clientId).innerHTML = 'RSA keys loaded !';
    }
  }).catch(logFail);
};

var cipherRSA = new MasqCrypto.RSA({});
var cipherEC = new MasqCrypto.EC({});
var cipherAES = new MasqCrypto.AES({
  mode: MasqCrypto.aesModes.GCM,
  keySize: 128
});

initWs();
checkClientId();

var aesCTR = function aesCTR() {
  // EXAMPLE
  var data = {
    POI_1: 'Tour eiffel',
    POI_2: 'Bastille',
    POI_3: 'Cafeteria'

    // We generate a 128 bits key with crypto random
  };var AESKey = window.crypto.getRandomValues(new Uint8Array(16));
  // We create an AES object with some paramters
  var myAES = new AES({
    mode: aesModes.CTR,
    key: AESKey,
    keySize: 128
  });
  console.log(myAES);
  myAES.encrypt(JSON.stringify(data)).then(function (encryptedJSON) {
    console.log(encryptedJSON);
    return myAES.decrypt(encryptedJSON);
  }).then(function (decryptedJSON) {
    return console.log(decryptedJSON);
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
    console.log('Bob : public key verification :  ok');
    // Bob : with Alice Public EC key and his EC private key, we derive a symmetric key
    console.log("Bob derives a symmetric key with Alice's Public EC key and his EC private key ");
    return bobEC.deriveKeyECDH(AliceECPubKey, 'aes-gcm', 128);
  }).then(function (derivedSymmetricAESKeyBob) {
    aliceEC.importKeyRaw(bob.ECRawPubKey).then(function (BobECPubKey) {
      aliceEC.deriveKeyECDH(BobECPubKey, 'aes-gcm', 128).then(function (derivedSymmetricAESKeyAlice) {
        console.log(derivedSymmetricAESKeyAlice);
        console.log(derivedSymmetricAESKeyBob);
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
console.log(MasqCrypto);
// ecdh()
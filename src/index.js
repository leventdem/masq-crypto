import * as cryp from './crypto'
var localforage = require('localforage');

var ecKeys = {}

const signPubKey = {}

const rawEcKeys = {}

var MK = null

const apiData = {
  POI_1: 'Tour eiffel',
  POI_2: 'Bastille',
  POI_3: 'Cafeteria'
}

var rsaKeys = {
  public: null,
  private: null,
  rawPubKey: null
}

/**
 * Print error messages
 *
 * @param {Error} err Error message
 */
const logFail = (err) => {
  console.log(err)
}

var DB = {
  configure: function() {
    localforage.config({
      driver: localforage.INDEXEDDB, // Force WebSQL; same as using setDriver()
      name: 'MasqStore',
      version: 1.0,
      storeName: 'myStore', // Should be alphanumeric, with underscores.
      description: 'Store info'
    });
    console.log(
      'localforage configured with default driver:',
      localforage.driver()
    );
  }
};

DB.configure()

let parameters = {
  syncserver: "ws://10.100.50.17:8080/",
  syncroom: "cryyyyptoooo",
  debug: true
}
let wsClient
let clientId = 'alice'

export const sendMessage = (msg) => {
  if (wsClient.readyState === wsClient.OPEN) {
    wsClient.send(JSON.stringify(msg))
  } else {
    console.log("Socket closed !");
  }
}

const delay = (ms) => {
  console.log("wait ...")
  return new Promise(function(resolve, reject) {
    setTimeout(resolve, ms); // (A)
  })
}

function initWSClient(server, room) {
  return new Promise((resolve, reject) => {
    room = room || 'foo'
    // const wsUrl = url.resolve(server, room)
    const wsUrl = (window.URL !== undefined)
      ? new window.URL(room, server)
      : server + room

    const ws = new window.WebSocket(wsUrl)

    ws.onopen = () => {
      // throttle openning new sockets
      if (window.timerID) {
        window.clearInterval(window.timerID)
        delete window.timerID
      }
      console.log(`Connected to Sync server at ${wsUrl}`)
      // TODO: check if we need to sync with other devices
      return resolve(ws)
    }

    ws.onerror = (event) => {
      const err = `Could not connect to Sync server at ${wsUrl}`
      // console.log(err)
      return reject(err)
    }
  })
}

/**
 * Initialize the WebSocket client. This allows us to synchronize with the
 * other devices for the user.
 *
 * The current implementation unfortunately mutates the wsClient variable.
 */

const initWs = (params) => {
  if (wsClient && wsClient.readyState === wsClient.OPEN) {
    return
  }
  if (!params) {
    params = parameters
  }
  console.log('Initializing WebSocket with params:', params)
  initWSClient(params.syncserver, params.syncroom).then((ws) => {
    wsClient = ws

    wsClient.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        switch (msg.type) {
          case 'hello':
            console.log("onMessage :", msg.type)
            helloMessageReceived(msg.name)
            break
          case 'requestRSAPub':
            console.log("onMessage :", msg.type)
            let data = {
              type: "sendRSAPub",
              name: clientId,
              publicKeyRSA: rsaKeys.rawPubKey
            }
            sendMessage(data)
            break
          case 'sendRSAPub':
            console.log("onMessage :", msg.type)
            console.log("I receive a RSA pub key of ", msg.name);
            console.log(msg.publicKeyRSA);
            storeRSAPub(msg.name, msg.publicKeyRSA)
            break
          case 'readyToTransfer':
            console.log("onMessage :", msg.type)
            console.log(
              msg.name,
              "is ready to transfer files. I will check the received EC public Key"
            );
            verifSignSendData(
              msg.name,
              cryp.hexStringToBuffer(msg.key),
              cryp.hexStringToBuffer(msg.signature)
            )
            break
          case 'readyToTransfer_2':
            console.log("onMessage :", msg.type)
            console.log(msg.name, "is ready to transfer files. Decrypt data");
            decryptData(msg.name, msg.data)
            break
          case 'startECDH':
            console.log("onMessage :", msg.type)
            console.log("I receive the EC pub key + sign of ", msg.name);
            console.log(msg.key);
            checkReceivedECPubKey(
              msg.name,
              cryp.hexStringToBuffer(msg.key),
              cryp.hexStringToBuffer(msg.signature)
            )
            break
          default:
            console.log("onMessage :", msg.type)
            break
        }
      } catch (err) {
        console.log(err)
      }
    }

    wsClient.onclose = (event) => {
      console.log(`WebSocket connection closed`)
      // Try to reconnect if the connection was closed
      if (event.wasClean === false || event.code === 1006) {
        console.log(`..trying to reconnect`)
        if (!window.timerID) {
          window.timerID = setInterval(() => {
            initWs(parameters)
          }, wsTimeout)
        }
      }
    }
  }).catch((err) => {
    log(err)
  })
}

const validateUser = () => {
  clientId = document.getElementById('username').value
  console.log(clientId)
  localforage.setItem("clientId", clientId).then(res => {
    //console.log('Using:' + localforage.driver());
    console.log('###Change username  into IndexedDB with key "clientId"###');
  }, logFail)
}

const helloMessageSend = () => {
  console.log('send hello message');
  sendMessage({type: "hello", name: clientId})
}

const helloMessageReceived = (name) => {
  localforage.getItem("connectedDevices").then(devices => {
    if (devices === null || !(name in devices)) {
      let data = {
        type: "requestRSAPub",
        name: clientId
      }
      sendMessage(data)
    } else {
      console.log("I already have the RSA public key of ", name)
    }
  }, logFail)
}

const storeRSAPub = (name, key) => {
  var listDevices = {}
  localforage.getItem("connectedDevices").then(devices => {
    if (devices === null) {
      listDevices[name] = key
    } else {
      listDevices = devices
      listDevices[name] = key
    }
    localforage.setItem('connectedDevices', listDevices).then(res => {
      console.log("Public key stored")
    }, logFail)
  }, logFail)
}

const decryptData = (name, encryptedData) => {
  cryp.decrypt(MK, encryptedData).then(decryptedJson => {
    console.log(decryptedJson) // { POI_1: "Tour eiffel", POI_2: "Cafeteria"}
  }, logFail)
}

const verifSignSendData = (name, receivedKey, signature) => {

  //Retrieve the RSA public key of name
  localforage.getItem("connectedDevices").then(devices => {
    if (devices === null || !(name in devices)) {
      console.log("I could not find the RSA public Key of ", name)
      return
    }
    cryp.importRSAPubKeyRaw(devices[name]).then(senderRSAPublicKey => {
      console.log("received EC public Key before verification");
      console.log(senderRSAPublicKey, signature, receivedKey);
      cryp.verifRSA(senderRSAPublicKey, signature, receivedKey).then(result => {
        if (result) {
          // if verification is ok, import received EC public key as CryptoKey
          cryp.importKeyRaw(receivedKey).then(receivedECPublicKey => {
            console.log("verification ok")
            // Bob : with Alice Public key and his EC private key, we derive a symmetric key
            // Suppose the EC public keys exhange and signature verification is ok Let's
            // derive the same symmetric key
            cryp.deriveKeyECDH(receivedECPublicKey, ecKeys.privateKey, "aes-gcm", 128).then(
              aesKey => {
                MK = aesKey
                cryp.encrypt(aesKey, JSON.stringify(apiData), '1.0.0').then(encryptedJson => {
                  //console.log(encryptedJson)
                  let data = {
                    name: clientId,
                    type: "readyToTransfer_2",
                    data: encryptedJson
                  }
                  sendMessage(data)
                }, logFail)
              },
              logFail
            )
          }, logFail)
        } else {
          console.log("verification fails")
        }
      }, logFail)
    }, logFail)
  }, logFail)
}

const checkReceivedECPubKey = (name, receivedKey, signature) => {
  console.log('I generate my own EC keys');
  cryp.genECKeyPair().then(ECkeys => {
    ecKeys = ECkeys
    //Retrieve the RSA public key of name
    localforage.getItem("connectedDevices").then(devices => {
      if (devices === null || !(name in devices)) {
        console.log("I could not find the RSA public Key of ", name)
        return
      }
      cryp.importRSAPubKeyRaw(devices[name]).then(senderRSAPublicKey => {
        // console.log("received EC public Key before verification");
        // console.log(senderRSAPublicKey, signature, receivedKey);
        cryp.verifRSA(senderRSAPublicKey, signature, receivedKey).then(result => {
          if (result) {
            // if verification is ok, import received EC public key as CryptoKey
            cryp.importKeyRaw(receivedKey).then(receivedECPublicKey => {
              console.log("verification ok")
              // Bob : with Alice Public key and his EC private key, we derive a symmetric key
              // Suppose the EC public keys exhange and signature verification is ok Let's
              // derive the same symmetric key
              cryp.deriveKeyECDH(receivedECPublicKey, ecKeys.privateKey, "aes-gcm", 128).then(
                aesKey => {
                  MK = aesKey
                  cryp.exportKeyRaw(ecKeys.publicKey).then(clientECPublicKey => {
                    cryp.signRSA(rsaKeys.private, clientECPublicKey).then(signatureToSend => {

                      let data = {
                        name: clientId,
                        type: "readyToTransfer",
                        key: cryp.bufferToHexString(clientECPublicKey),
                        signature: cryp.bufferToHexString(signatureToSend)
                      }
                      sendMessage(data)
                    }, logFail)
                  }, logFail)
                },
                logFail
              )
            }, logFail)
          } else {
            console.log("verification fails")
          }
        }, logFail)
      }, logFail)
    }, logFail)
  }, logFail)
}

const startECDH = () => {
  console.log('I initiate a ECDH to share info.');
  console.log('I generate EC keys');
  cryp.genECKeyPair().then(key => {
    ecKeys = key
    cryp.exportKeyRaw(key.publicKey).then(rawKey => {
      cryp.signRSA(rsaKeys.private, rawKey).then(signature => {
        // test purpose console.log(rsaKeys.public, signature, rawKey);
        // cryp.verifRSA(rsaKeys.public, signature, rawKey).then(result => {   if
        // (result) {     console.log("spefic test is succesful")   } }, logFail)
        let data = {
          name: clientId,
          type: "startECDH",
          key: cryp.bufferToHexString(rawKey),
          signature: cryp.bufferToHexString(signature)
        }
        sendMessage(data)
      }, logFail)
    }, logFail)
  }, logFail)
}

document.addEventListener('DOMContentLoaded', function() {
  var el = document.getElementById('validateUserName');
  if (el) {
    el.addEventListener('click', function(e) {
      validateUser();
    });
  };

  el = document.getElementById('exchange_RSA_pub_keys');
  if (el) {
    el.addEventListener('click', function(e) {
      helloMessageSend();
    });
  };

  el = document.getElementById('start_ecdh');
  if (el) {
    el.addEventListener('click', function(e) {
      startECDH();
    });
  };

});

const checkRSA = () => {
  return localforage.getItem('myRSA_Keys').then(key => {
    if (key === null) {
      return cryp.genRSAKeyPair().then(key => {
        console.log(key);
        rsaKeys.public = key.publicKey
        rsaKeys.private = key.privateKey

        console.log("export rawkey")
        return cryp.exportRSAPubKeyRaw(key.publicKey).then(rawKey => {
          console.log(rawKey)
          rsaKeys.rawPubKey = rawKey
          return localforage.setItem("myRSA_Keys", rsaKeys).then(res => {
            //console.log('Using:' + localforage.driver());
            console.log('###RSA key  into IndexedDB with key "myRSA_Keys"###');
            return "First, time RSA keys have been generated"
          }, logFail)
        }, logFail)
      }, logFail)
    } else {
      // console.log(key);
      rsaKeys = key
      console.log(rsaKeys);
      return "RSA keys retrieved from localstorage"
    }

  }, logFail)

}

const checkClientId = () => {
  localforage.getItem('clientId').then(client => {
    if (client !== '') {
      clientId = client
    }
    var el = document.getElementById('username')
    if (el)
      el.value = clientId
  }, logFail)
}

const init = () => {
  checkClientId()
  checkRSA().then((res) => {
    document.getElementById('rsaKey' + clientId).innerHTML = 'RSA keys loaded !'
    console.log(res)
  })
}

initWs()
init()

// delay(2500).then(() => {   console.log("send message")
//
//   sendMessage({type: "check"})
//
// })

import localforage from 'localforage'
import AES, { aesModes } from './AES'
import EC from './EC'
import RSA from './RSA'
import utils from './utils'

const apiData = {
  POI_1: 'Tour eiffel',
  POI_2: 'Bastille',
  POI_3: 'Cafeteria'
}

const parameters = {
  // syncserver: 'ws://10.100.50.17:8080/',
  syncserver: 'wss://sync-beta.qwantresearch.com:8080/',
  syncroom: 'cryyyyptoooo',
  debug: true
}
let wsClient
let wsTimeout = 10000
let clientId = ''

var log = (...args) => {
  const reg = (all, cur) => {
    if (typeof (cur) === 'string') {
      return all + cur
    } else {
      return all + cur.toString()
    }
  }
  if (parameters.debug) {
    console.log('[Masq Crypto]', args.reduce(reg, ''))
  }
}

/**
 * Print error messages
 *
 * @param {Error} err Error message
 */
const logFail = (err) => {
  console.log(err)
}

/**
 * Configuration of Indexeddb for data storage
 */
var DB = {
  configure: function () {
    localforage.config({
      driver: localforage.INDEXEDDB, // Force WebSQL same as using setDriver()
      name: 'MasqStore',
      version: 1.0,
      storeName: 'myStore', // Should be alphanumeric, with underscores.
      description: 'Store info'
    })
    // log(   'localforage configured with default driver:',
    // localforage.driver() )
  }
}

DB.configure()

export const sendMessage = (msg) => {
  if (wsClient.readyState === wsClient.OPEN) {
    log('*** sendMEssage : ', msg.type, ' ***')
    wsClient.send(JSON.stringify(msg))
  } else {
    log('Socket closed !')
  }
}

const delay = (ms) => {
  log('wait ...')
  return new Promise(function (resolve, reject) {
    setTimeout(resolve, ms) // (A)
  })
}

const initWSClient = (server, room) => {
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
      console.log(err)
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
            log('*** onMEssage : ', msg.type, ' ***')
            receiveHello(msg.name)
            break
          case 'hello_ack':
            log('*** onMEssage : ', msg.type, ' ***')
            receiveHello_ack(msg.name)
            break
          case 'requestRSAPub':
            log('*** onMEssage : ', msg.type, ' ***')
            receiveRequestRSAPub(msg.name)
            break
          case 'requestRSAPub_ack':
            log('*** onMEssage : ', msg.type, ' ***')
            receiveRequestRSAPub_ack(msg)
            break
          case 'startECDH':
            log('*** onMEssage : ', msg.type, ' ***')
            receiveStartECDH(msg)
            break
          case 'startECDH_ack':
            log('*** onMEssage : ', msg.type, ' ***')
            receiveStartECDH_ack(msg)
            break
          case 'data':
            log('*** onMEssage : ', msg.type, ' ***')
            receiveData(msg)
            break

          default:
            log('onMEssage : ', msg)
            break
        }
      } catch (err) {
        log(err)
      }
    }

    wsClient.onclose = (event) => {
      log(`WebSocket connection closed`)
      // Try to reconnect if the connection was closed
      if (event.wasClean === false || event.code === 1006) {
        log(`..trying to reconnect`)
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

const sendHello = () => {
  log('send hello message')
  sendMessage({ type: 'hello', name: clientId })
}

const receiveHello = (name) => {
  // First we response to hello msg, the sender could this way check if he altough
  // has RSA public key
  sendHello_ack()
  checkRSAPub(name).then(res => {
    if (res) {
      log('I already have the RSA public key of ', name)
    } else {
      sendRequestRSAPub()
    }
  })
}

const sendHello_ack = () => {
  // log('Response to hello message with hello_ack')
  sendMessage({ type: 'hello_ack', name: clientId })
}

const receiveHello_ack = (name) => {
  checkRSAPub(name)
    .then(res => {
      if (res) {
        log('I already have the RSA public key of ', name)
        log('***Now, both entities have exchanged their RSA public keys***')
      } else {
        sendRequestRSAPub()
      }
    })
    .catch(logFail)
}

const sendRequestRSAPub = () => {
  log('Response to hello message with hello_ack')
  let data = {
    type: 'requestRSAPub',
    name: clientId
  }
  sendMessage(data)
}

const receiveRequestRSAPub = (name) => {
  log('*** ', clientId, ' : ', name, ' asks my RSA public Key')
  sendRequestRSAPub_ack(name)
}

const sendRequestRSAPub_ack = (name) => {
  log('*** ', clientId, ' : sends the RSA public Key to ', name)
  cipherRSA.exportRSAPubKeyRaw(cipherRSA.public)
    .then(rawKey => {
      // console.log('my RSA Public key', rawKey)
      let data = {
        type: 'requestRSAPub_ack',
        name: clientId,
        publicKeyRSA: rawKey
      }
      sendMessage(data)
    })
    .catch(logFail)
}

const receiveRequestRSAPub_ack = (msg) => {
  log('*** ', clientId, ' : RSA pub key of ', msg.name, ' is received ***'
  )
  // log(msg.publicKeyRSA)
  log('*** Now, both entities have exchanged their RSA public keys. ***')
  storeRSAPub(msg.name, msg.publicKeyRSA)
}

const sendStartECDH = (ECPublicKey, signature) => {
  let data = {
    name: clientId,
    type: 'startECDH',
    key: ECPublicKey,
    signature: signature
  }
  sendMessage(data)
}

const receiveStartECDH = (msg) => {
  log(
    '*** ',
    clientId,
    ' : Just received the EC pub key of ',
    msg.name,
    '  ***'
  )
  checkReceivedECPubKey(
    msg.name,
    utils.hexStringToBuffer(msg.key),
    utils.hexStringToBuffer(msg.signature)
  )
    .then(res => {
      if (res) {
        log('*** ', clientId, ' : verification of ', msg.name, ' EC public key : OK ***')
        generateECKeysAndSign()
          .then(res => {
            sendStartECDH_ack(res.rawECPublicKey, res.signature)
            log('*** ', clientId, ' : computes the one time common AES secret key. ***')
            return cipherEC.deriveKeyECDH(
              utils.hexStringToBuffer(msg.key),
              'aes-gcm',
              128
            )
          })
          .then((aesKey) => {
            cipherAES.key = aesKey
          })
          .catch(logFail)
      } else {
        log('EC public key verification fails')
        Promise.reject(new Error('EC public key verification failed'))
        // TODO : send error message : the public key verification failes :
        // TODO -  MITM :-(
        // TODO - have you changed the Public RSA key ) sendRequestRSAPub()
      }
    })
    .catch(logFail)
}

const sendStartECDH_ack = (ECPublicKey, signature) => {
  let data = {
    name: clientId,
    type: 'startECDH_ack',
    key: ECPublicKey,
    signature: signature
  }
  sendMessage(data)
}

const receiveStartECDH_ack = (msg) => {
  log('*** ', clientId, ' : ', msg.name, ' is ready to transfer files. ***')

  checkReceivedECPubKey(
    msg.name,
    utils.hexStringToBuffer(msg.key),
    utils.hexStringToBuffer(msg.signature)
  ).then(res => {
    if (res) {
      log('*** ', clientId, ' : verification of ', msg.name, ' EC public key : OK ***')
      log(
        '*** Now, both entities have exchanged and verified their EC public keys***'
      )
      log('*** ', clientId, ' : computes the one time shared AES secret key. ***')
      return cipherEC.deriveKeyECDH(
        utils.hexStringToBuffer(msg.key),
        'aes-gcm',
        128
      )
        .then((aesKey) => {
          log('*** ', clientId, ' : encrypts a message and sends it. ***')
          encryptData(aesKey, 'dataForFuture')
        })
        .catch(logFail)
    } else {
      log('EC public key verification fails')
      Promise.reject(new Error('EC public key verification failed'))
      // TODO : send error message : the public key verification fails :
      // TODO -  MITM :-(
      // TODO - have you changed your Public RSA key => sendRequestRSAPub()
    }
  })
    .catch(logFail)
}

const sendData = (encryptedData) => {
  let data = {
    name: clientId,
    type: 'data',
    data: encryptedData
  }
  sendMessage(data)
}

const receiveData = (msg) => {
  log('*** ', clientId, ' : ', msg.name, ' sends me data. Let us decrypt it ***')
  decryptData(msg.name, msg.data)
}

const encryptData = (aesKey, dataToEncrypt) => {
  cipherAES.key = aesKey
  cipherAES.additionalData = '1.0.0'
  cipherAES.encrypt(JSON.stringify(apiData))
    .then(encryptedJson => {
      // log(encryptedJson)
      sendData(encryptedJson)
    })
    .catch(logFail)
}

const checkRSAPub = (name) => {
  return localforage.getItem('connectedDevices')
    .then(devices => {
      if (devices === null || !(name in devices)) {
        console.log('no RSA public key registered at all')
        console.log(devices)
        return false
      } else {
        return true
      }
    })
    .catch(logFail)
}

const checkReceivedECPubKey = (name, receivedKey, signature) => {
  // Retrieve the RSA public key of name
  return localforage.getItem('connectedDevices').then(devices => {
    if (devices === null || !(name in devices)) {
      log('I could not find the RSA public Key of ', name)
      // TODO : call the RSA public key exchange messsage or procedure
      return false
    }
    return cipherRSA.importRSAPubKeyRaw(devices[name])
  })
    .then(senderRSAPublicKey => {
      return cipherRSA.verifRSA(senderRSAPublicKey, signature, receivedKey)
    })
    .then(result => {
      if (result) {
        return true
      } else {
        return false
      }
    })
    .catch(logFail)
}

const storeRSAPub = (name, key) => {
  var listDevices = {}
  localforage.getItem('connectedDevices')
    .then(devices => {
      if (devices === null) {
        listDevices[name] = key
      } else {
        listDevices = devices
        listDevices[name] = key
      }
      localforage.setItem('connectedDevices', listDevices)
    })
    .then(res => {
      log('Public key stored')
    })
    .catch(logFail)
}

const decryptData = (name, encryptedData) => {
  cipherAES.decrypt(encryptedData)
    .then(decryptedJson => {
      log(decryptedJson) // { POI_1: 'Tour eiffel', POI_2: 'Cafeteria'}
    })
    .catch(logFail)
}

const generateECKeysAndSign = () => {
  return cipherEC.genECKeyPair().then(key => {
    return cipherEC.exportKeyRaw().then(rawKey => {
      return cipherRSA.signRSA(rawKey).then(signature => {
        return (
          /**
           * We convert to hexString because when the receiver parse the message, the
           * obtained value are not Uint8array but Object which triggers an error with web
           * crypto for verification operation.
           */
          {
            rawECPublicKey: utils.bufferToHexString(rawKey),
            signature: utils.bufferToHexString(signature)
          }
        )
      }).catch(logFail)
    }).catch(logFail)
  }).catch(logFail)
}

/*
 * User interface :
 * Event and button : only for demo purpose
 */

document.addEventListener('DOMContentLoaded', function () {
  var el = document.getElementById('validateUserName')
  if (el) {
    el.addEventListener('click', function (e) {
      validateUser()
    })
  }

  el = document.getElementById('exchange_RSA_pub_keys')
  if (el) {
    el.addEventListener('click', function (e) {
      sendHello()
    })
  }
  el = document.getElementById('init')
  if (el) {
    el.addEventListener('click', function (e) {
      init()
    })
  }

  el = document.getElementById('start_ecdh')
  if (el) {
    el.addEventListener('click', function (e) {
      startECDH()
    })
  }
})

const startECDH = () => {
  log('*** ', clientId, ' : generates a new EC key pair for a single message encryption. ***')
  generateECKeysAndSign().then(res => {
    sendStartECDH(res.rawECPublicKey, res.signature)
  })
}

const validateUser = () => {
  clientId = document.getElementById('username').value
  log(clientId)
  localforage.setItem('clientId', clientId).then(res => {
    // log('Using:' + localforage.driver())
    log('###Change username  into IndexedDB with key ', clientId, '###')
  }, logFail)
}

const checkRSA = () => {
  return localforage.getItem('myRSA_Keys')
    .then(keysFromStorage => {
      if (keysFromStorage === null) {
        log("No RSA keys at all, let's generate them for ", clientId)
        return cipherRSA.genRSAKeyPair()
          .then(keys => {
            let RSAKeys = {}
            RSAKeys.public = keys.publicKey
            RSAKeys.private = keys.privateKey
            console.log(RSAKeys)
            return localforage.setItem('myRSA_Keys', RSAKeys)
          })
          .then(res => {
            // log('Using:' + localforage.driver())
            log('### Store RSA keys into IndexedDB with key myRSA_Keys ###')
            return 'ok'
          })
          .catch(logFail)
      } else {
        cipherRSA.setKey(keysFromStorage)
        // console.log(cipherRSA)
        log('RSA keys retrieved from IndexedDB')
        return 'RSA keys retrieved from IndexedDB'
      }
    })
    .catch(logFail)
}

const checkClientId = () => {
  return localforage.getItem('clientId')
    .then(client => {
      if (client !== null) {
        clientId = client
      }
      var el = document.getElementById('username')
      if (el) { el.value = clientId }
      return clientId
    })
    .catch(logFail)
}

const init = () => {
  checkRSA().then((res) => {
    if (clientId === 'bob' || clientId === 'alice') {
      document.getElementById('rsaKey' + clientId).innerHTML = 'RSA keys loaded !'
    }
  })
    .catch(logFail)
}

const cipherRSA = new RSA({})
const cipherEC = new EC({})
const cipherAES = new AES(
  {
    mode: aesModes.GCM,
    keySize: 128
  })

initWs()
checkClientId()

/*
 * User interface :
 * Event and button : only for demo purpose
 */

document.addEventListener('DOMContentLoaded', function () {
  var el = null
  // test perf
  el = document.getElementById('rsaPerf')
  if (el) {
    el.addEventListener('click', function (e) {
      startTestPerfRSA()
    })
  }
  el = document.getElementById('ecPerf')
  if (el) {
    el.addEventListener('click', function (e) {
      startTestPerfEC()
    })
  }
})

const delay = (ms) => {
  return new Promise(function (resolve, reject) {
    setTimeout(resolve, ms) // (A)
  })
}

const singleTestRSA = (keyPair, msg) => {
  let cRSA = new MasqCrypto.RSA({ name: 'RSA-PSS' })
  return cRSA.signRSA(msg, keyPair.privateKey)
    .then(sig => cRSA.verifRSA(keyPair.publicKey, sig, msg))
    .then(v => {
      if (!v) {
        console.log('Test wrong')
      }
      return v
    })
}
const singleTestEC = (keyPair, msg) => {
  let cEC = new MasqCrypto.EC({ name: 'ECDSA' })
  return cEC.signEC(msg, keyPair.privateKey)
    .then(sig => cEC.verifEC(keyPair.publicKey, sig, msg))
    .then(v => {
      if (!v) {
        console.log('Test wrong')
      }
      return v
    })
}

const callRSATest = (counter, keyPair, msg) => {
  singleTestRSA(keyPair, msg).then(result => {
    if (counter > 0) { callRSATest(counter - 1, keyPair, msg) }
    else {
      let end = new Date().getTime()
      let time = end - start
      console.log('RSA test finished : time is ' + time + ' ms.')
    }
  })
}
const callECTest = (counter, keyPair, msg) => {
  singleTestEC(keyPair, msg).then(result => {
    if (counter > 0) { callECTest(counter - 1, keyPair, msg) }
    else {
      let end = new Date().getTime()
      let time = end - start
      console.log('EC test finished : time is ' + time + ' ms.')
    }
  })
}

let start = null
const startTestPerfRSA = () => {
  var TEST_MESSAGE = MasqCrypto.utils.toArray('1234567890123456')
  let cRSA = new MasqCrypto.RSA({ name: 'RSA-PSS' })
  cRSA.genRSAKeyPair()
    .then((keyPair) => {
      console.log('RSA-PSS test starts')
      let testNumber = 100
      console.log('Number of sign/verif : ' + testNumber)
      start = new Date().getTime()
      callRSATest(testNumber, keyPair, TEST_MESSAGE)
    })
}

const startTestPerfEC = () => {
  var TEST_MESSAGE = MasqCrypto.utils.toArray('1234567890123456')
  let cRSA = new MasqCrypto.EC({ name: 'ECDSA' })
  cRSA.genECKeyPair()
    .then((keyPair) => {
      console.log('ECDSA test starts')
      let testNumber = 100
      console.log('Number of sign/verif : ' + testNumber)
      start = new Date().getTime()
      callECTest(testNumber, keyPair, TEST_MESSAGE)
    })
}

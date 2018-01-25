'use strict';

/*
 * User interface :
 * Event and button : only for demo purpose
 */

document.addEventListener('DOMContentLoaded', function () {
  var el = null;
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

var delay = function delay(ms) {
  return new Promise(function (resolve, reject) {
    setTimeout(resolve, ms); // (A)
  });
};

var singleTestRSA = function singleTestRSA(keyPair, msg) {
  var cRSA = new MasqCrypto.RSA({ name: 'RSA-PSS' });
  return cRSA.signRSA(msg, keyPair.privateKey).then(function (sig) {
    return cRSA.verifRSA(keyPair.publicKey, sig, msg);
  }).then(function (v) {
    if (!v) {
      console.log('Test wrong');
    }
    return v;
  });
};
var singleTestEC = function singleTestEC(keyPair, msg) {
  var cEC = new MasqCrypto.EC({ name: 'ECDSA' });
  return cEC.signEC(msg, keyPair.privateKey).then(function (sig) {
    return cEC.verifEC(keyPair.publicKey, sig, msg);
  }).then(function (v) {
    if (!v) {
      console.log('Test wrong');
    }
    return v;
  });
};

var callRSATest = function callRSATest(counter, keyPair, msg) {
  singleTestRSA(keyPair, msg).then(function (result) {
    if (counter > 0) {
      callRSATest(counter - 1, keyPair, msg);
    } else {
      var end = new Date().getTime();
      var time = end - start;
      console.log('RSA test finished : time is ' + time + ' ms.');
    }
  });
};
var callECTest = function callECTest(counter, keyPair, msg) {
  singleTestEC(keyPair, msg).then(function (result) {
    if (counter > 0) {
      callECTest(counter - 1, keyPair, msg);
    } else {
      var end = new Date().getTime();
      var time = end - start;
      console.log('EC test finished : time is ' + time + ' ms.');
    }
  });
};

var start = null;
var startTestPerfRSA = function startTestPerfRSA() {
  var TEST_MESSAGE = MasqCrypto.utils.toArray('1234567890123456');
  var cRSA = new MasqCrypto.RSA({ name: 'RSA-PSS' });
  cRSA.genRSAKeyPair().then(function (keyPair) {
    console.log('RSA-PSS test starts');
    var testNumber = 100;
    console.log('Number of sign/verif : ' + testNumber);
    start = new Date().getTime();
    callRSATest(testNumber, keyPair, TEST_MESSAGE);
  });
};

var startTestPerfEC = function startTestPerfEC() {
  var TEST_MESSAGE = MasqCrypto.utils.toArray('1234567890123456');
  var cRSA = new MasqCrypto.EC({ name: 'ECDSA' });
  cRSA.genECKeyPair().then(function (keyPair) {
    console.log('ECDSA test starts');
    var testNumber = 100;
    console.log('Number of sign/verif : ' + testNumber);
    start = new Date().getTime();
    callECTest(testNumber, keyPair, TEST_MESSAGE);
  });
};
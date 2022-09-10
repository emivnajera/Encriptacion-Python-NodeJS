var CryptoJS = require("crypto-js");

var message = "Gerardo Pitudo";
var key = "AAAAAAAAAAAAAAAA"; //key used in Python
key = CryptoJS.enc.Utf8.parse(key);

function encrypt(raw) {
  var encrypted = CryptoJS.AES.encrypt(raw, key, {
    mode: CryptoJS.mode.ECB,
  });
  return (encrypted = encrypted.toString());
}

function decrypt(enc) {
  var decrypted = CryptoJS.AES.decrypt(enc, key, { mode: CryptoJS.mode.ECB });
  return decrypted.toString(CryptoJS.enc.Utf8);
}
var enc = encrypt(message);
console.log('encrypted ECB Base64: ',enc);
console.log('data: ',decrypt(enc));

var _ = require('lodash');
var crypto = require('crypto');
var aesjs = require('aes-js');

var DELIM = '~~~';

Tinypass = function(options) {
  this.options = options;
  return this;
};
exports.Tinypass = Tinypass;

Tinypass.prototype.authorizationHeader = function(data) {
  return this.options.aid + ':' + this.hashHmacSha256(this.options.privateKey, data);
};

Tinypass.prototype.encrypt = function(text) {
  var blockSize = 16;
  var cipherTextBuffers = [];
  var padding;

  // Make a copy of the key to modify it
  var privateKey = this.options.privateKey;

  // Set the key to exactly 32
  if (privateKey.length > 32) {
    privateKey = privateKey.substring(0, 32);
  } else if (privateKey.length < 32) {
    privateKey = _.padRight(privateKey, 32, 'X');
  }

  // Convert the key and init an aesEcb instance with that key
  var key = aesjs.util.convertStringToBytes(privateKey);
  var aesEcb = new aesjs.ModeOfOperation.ecb(key);

  // Convert the text to bytes and loop over 16 block increments, encrypting each one
  var textAsBytes = aesjs.util.convertStringToBytes(text);
  for (var i = 0; i <= textAsBytes.length; i += blockSize) {
    var plainTextByteBlock = textAsBytes.slice(i, i + blockSize);

    // Set set the padding character to be the ASCII code equivalent
    var paddingSize = blockSize - plainTextByteBlock.length;
    var padding = new Buffer(paddingSize);
    padding.fill(String.fromCharCode(paddingSize));

    // Pad accordingly
    plainTextByteBlock = Buffer.concat([plainTextByteBlock, padding]);

    // Push the block to the main buffer
    cipherTextBuffers.push(aesEcb.encrypt(plainTextByteBlock));
  }

  // Join all the blocks together
  cipherTextBuffers = Buffer.concat(cipherTextBuffers);

  // Encode and concat the string with a hash signature
  var safeText = this.encode(cipherTextBuffers);
  safeText = safeText + DELIM + this.hashHmacSha256(this.options.privateKey, safeText);

  return safeText;
};

// Encode helper
Tinypass.prototype.encode = function(data) {
  data = _.trimRight(data.toString('base64').replace(/\+/g, '-').replace(/\//g, '_'), '=');
  return data;
}

// Decode helper
Tinypass.prototype.decode = function(data) {
  data = data.replace(/\-/g, '+').replace(/\_/g, '/');
  var buff = new Buffer(data, 'base64');
  return buff;
}

// Hash helper
Tinypass.prototype.hashHmacSha256 = function(key, data) {
  return this.encode(crypto.createHmac('SHA256', key).update(data).digest('base64'));
}

exports.createClient = function(options) {
  var client = new Tinypass(options);

  return client;
};

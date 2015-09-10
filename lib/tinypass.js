var crypto = require('crypto');

Tinypass = function(options) {
  this.options = options;
  return this;
};
exports.Tinypass = Tinypass;

Tinypass.prototype.authorizationHeader = function(httpRequest) {
  return this.options.aid + ':' + crypto.createHmac('SHA256', this.options.privateKey).update(httpRequest).digest('base64');
};

exports.createClient = function(options) {
  var client = new Tinypass(options);

  return client;
};

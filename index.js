var chalk = require('chalk');
var tinypass = require('./lib/tinypass').createClient({ aid: 'AID', privateKey: 'KEY' });

var request = 'GET /r2/access?rid=[RID]&user_ref=[USER_REF]'
var data = 'BwVjNeGVpcoO13Dn1LS6WqWfYMXKr3WkUOTTAK_zz5zWiA2vdGqRO1Mx1L3PTS4oClKfRXnnde-wFP6wUzJ6Z79k_SBT4cCF8kKL1BA-isxsqRHmvO4WwZtBhGsyGWlLQni-BxSVeTUrz4uqYwAfV7lZx5UwyI3T8e5MUfm8mOQR9x7pSfRWBiXR_fgQfhBnDTCLfsVfB929Usl4UE7axthPYiIxfssxqPG4N36ySmt9escBf0DohDUcYrLVSR99InXLw-vq7mhN58M4BY7pCA~~~iIynfdNYmP_GuXpMCImuIPpMWMwZlKJm9FDg7QipCJI';
var text = new Buffer('odd networks');

console.log('Request String: ' + chalk.blue(request));
console.log('Tinypass Auth Header: ' + chalk.green(tinypass.authorizationHeader(request)));
console.log('Tinypass Encrypt: ' + chalk.green(tinypass.encrypt(request)));
console.log('Tinypass Decrypt: ' + chalk.green(tinypass.decrypt(tinypass.encrypt(request))));
console.log('Tinypass Encode: ' + chalk.green(tinypass.encode(text)));
console.log('Tinypass Decode: ' + chalk.green(tinypass.decode(tinypass.encode(text))));

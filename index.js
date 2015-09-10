var chalk = require('chalk');
var tinypass = require('./lib/tinypass').createClient({ aid: '8bc847a6-d1b7-4014-a043-c8b8e33418a9', privateKey: 'zqZABUNnGzUuo2bCFJKxXBddVqDmoyD8' });

var request = 'GET /r2/access?rid=[RID]&user_ref=[USER_REF]'

console.log('Request String: ' + chalk.blue(request));
console.log('Tinypass Auth Header: ' + chalk.green(tinypass.authorizationHeader(request)));

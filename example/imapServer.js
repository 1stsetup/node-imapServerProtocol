var net = require('net');
var fs = require('fs');

const IMAP_STATE_NOT_AUTHENTICATED = 1;
const IMAP_STATE_AUTHENTICATED = 2;
const IMAP_STATE_SELECTED = 4;
const IMAP_STATE_LOGOUT = 8;

var imapProtocol = require('../imapServerProtocol');

var server = net.createServer(function(socket) { //'connection' listener
	console.log('server connected');
	var imapHandler = new imapProtocol(undefined, socket, false);

	imapHandler.setCommand("LOGIN", {
		allowedStates : IMAP_STATE_NOT_AUTHENTICATED,
		argumentsAllowed: 2,
		responseFunc: function(imap, tag, args) {
			console.log("Hello:%s. You password='%s'",args[0], args[1]);
			imap.sendOK(tag, "LOGIN completed");
		}
	});

	// For option see http://nodejs.org/api/crypto.html#crypto_crypto_createcredentials_details
	imapHandler.enableTLS({ key : fs.readFileSync("test-key.pem"),
			cert : fs.readFileSync("test-cert.pem")});

	imapHandler.on('imapOk', function(tag, command, args) {
console.log("imapOK: tag:%s, command:%s", tag, command);
		imapHandler.sendOK(tag, command);
	});

	imapHandler.on('imapBad', function(tag, string) {
		imapHandler.sendBAD(tag, string);
	});

	imapHandler.on('imapNo', function(string) {
		imapHandler.sendNO(undefined, string);
	});

	imapHandler.showGreeting();
});

server.listen(8124, function() { //'listening' listener
	console.log('server bound');
});

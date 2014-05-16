var util = require('util');
var Transform = require('stream').Transform;
util.inherits(imapProtocol, Transform);

const IMAP_STATE_NOT_AUTHENTICATED = 1;
const IMAP_STATE_AUTHENTICATED = 2;
const IMAP_STATE_SELECTED = 4;
const IMAP_STATE_LOGOUT = 8;

function stateToString(aState) {
	switch (aState) {
		case IMAP_STATE_NOT_AUTHENTICATED : return "not authenticated";
		case IMAP_STATE_AUTHENTICATED : return "authenticated";
		case IMAP_STATE_SELECTED : return "selected";
		case IMAP_STATE_LOGOUT : return "logout";
	}

	return "Unknown state:"+aState;
}

var IMAP_COMMANDS = {
	"CAPABILITY" : {
		allowedStates : IMAP_STATE_NOT_AUTHENTICATED + IMAP_STATE_AUTHENTICATED + IMAP_STATE_SELECTED + IMAP_STATE_LOGOUT,
		argumentsAllowed: 0,
		responseFunc: function(imap, tag) {
			imap.push("* CAPABILITY "+imap.capabilities+"\r\n");
			imap.sendOK(tag, "CAPABILITY completed");
		}
	},
	"NOOP" : {
		allowedStates : IMAP_STATE_NOT_AUTHENTICATED + IMAP_STATE_AUTHENTICATED + IMAP_STATE_SELECTED + IMAP_STATE_LOGOUT,
		argumentsAllowed: 0
	},
	"LOGOUT" : {
		allowedStates : IMAP_STATE_NOT_AUTHENTICATED + IMAP_STATE_AUTHENTICATED + IMAP_STATE_SELECTED + IMAP_STATE_LOGOUT,
		argumentsAllowed: 0,
		responseFunc: function(imap, tag) {
console.log(" !! 1");
			imap.push("* BYE IMAP4rev1 Server logging out\r\n");
console.log(" !! 2");
			imap.sendOK(tag, "LOGOUT completed");
console.log(" !! 3");
			imap.disconnect();
console.log(" !! 4");
		}
	},
	"STARTTLS" : {
		allowedStates : IMAP_STATE_NOT_AUTHENTICATED,
		argumentsAllowed: 0,
		responseFunc: function(imap, tag) {
			imap.startTLS(tag);
		}
	},
	"AUTHENTICATE" : {
		allowedStates : IMAP_STATE_NOT_AUTHENTICATED,
		argumentsAllowed: 1,
		responseFunc: function(imap, tag, args) {
			console.log("AUTHENTICATE args:",args);
			imap.sendNO(tag, "Do not know any AUTHENTICATE mechanism");
		}
	},
	"LOGIN" : { // Default we accept everything
		allowedStates : IMAP_STATE_NOT_AUTHENTICATED,
		argumentsAllowed: 2,
		responseFunc: function(imap, tag, args) {
			imap.sendOK(tag, "LOGIN completed");
		}
	}
}

function imapProtocol(options, socket, showGreeting) {
	if (!(this instanceof imapProtocol))
		return new imapProtocol(options, socket);

	Transform.call(this, options);
	this._receivingString = true;
	this._receivingOctets = false;
	this._string = '';
	this._octets = [];
	this._crSeen = false;
	this._lfSeen = false;
	this._tags = {};
	this._state = IMAP_STATE_NOT_AUTHENTICATED;
	this._supportTLS = false;
	this._capabilities = ["IMAP4rev1","AUTH=PLAIN"];
	this._loginDisabled = false;

	this._authenticated = false;

	this._socket = socket;

	var self = this;
	Object.defineProperty(this, "capabilities", {
		get: function() { 
			var result = '';
			for (var i in self._capabilities) {
				if (result == '') {
					result += self._capabilities[i];
				}
				else {
					result += ' ' + self._capabilities[i];
				}
			}
			return result; 
		}
	});

	this._socket.on('end', function() {
		console.log('server disconnected');
		self.close();
	});

	this._socket.pipe(this);
	this.pipe(this._socket);
	if (showGreeting) this.showGreeting();
}

imapProtocol.prototype.setCommand = function(command, options) {
	IMAP_COMMANDS[command] = options;
}

imapProtocol.prototype.startTLS = function(tag) {
	if (!this._supportTLS) {
		this.emitBAD(tag,"STARTTLS not supported.\r\n");
		return;
	}

	this._socket.unpipe(this);
	this.unpipe(this._socket);

	this._securePair = require("tls").createSecurePair(this._sslContext, true, false, false);
	
	this._securePair.encrypted.pipe(this._socket);
	this._socket.pipe(this._securePair.encrypted);

	var self = this;
	this._securePair.on('error', function() {
		self._socket.write(tag+" NO Error staring secure connection\r\n");
	});

	this._securePair.on('secure', function() {

		self._removeSTARTTLS();
		self._removeLOGINDISABLED();

		self._securePair.cleartext.pipe(self);
		self.pipe(self._securePair.cleartext);
	});

	this._socket.on('end', function() {
		console.log('server disconnected');
		self.close();
	});

	this._socket.write(tag+" OK Begin TLS negotiation now\r\n");
}

// For options see http://nodejs.org/api/crypto.html#crypto_crypto_createcredentials_details
imapProtocol.prototype.enableTLS = function(options) {

	try {
		this._sslContext = require('crypto').createCredentials(options);
	}
	catch(err) {
		throw "Error creating credentials. Err:"+err;
	}

	if (this._supportTLS) {
		this.disableTLS();
	}

	this._supportTLS = true;
	this._capabilities.push("STARTTLS");

	if (!this._loginDisabled) {
		this._loginDisabled = true;
		this._capabilities.push("LOGINDISABLED");
	}
}

imapProtocol.prototype._removeSTARTTLS = function() {
	this._supportTLS = false;
	var index = 0;
	while ((index < this._capabilities.length) && (this._capabilities[index] != "STARTTLS")) {
		index++;
	}

	if (index < this._capabilities.length) {
		this._capabilities.splice(index, 1);
	}
}

imapProtocol.prototype._removeLOGINDISABLED = function() {
	this._loginDisabled = false;
	index = 0;
	while ((index < this._capabilities.length) && (this._capabilities[index] != "LOGINDISABLED")) {
		index++;
	}

	if (index < this._capabilities.length) {
		this._capabilities.splice(index, 1);
	}
}

imapProtocol.prototype.disableTLS = function() {
	if (!this._supportTLS) return;

	this._removeSTARTTLS();

	if (this._loginDisabled) {
		this._removeLOGINDISABLED();
	}
}

imapProtocol.prototype.showGreeting = function() {
	this._socket.write('* OK IMAP4rev1 server ready\r\n');
}

imapProtocol.prototype.removeTag = function(tag) {
	if (tag !== undefined) {
		delete this._tags[tag];
	}
}

imapProtocol.prototype.sendOK = function(tag, text) {
	this.push((tag || "*")+" OK "+text+"\r\n");

	this.removeTag(tag);
}

imapProtocol.prototype.sendBAD = function(tag, text) {
	this.push((tag || "*")+" BAD "+text+"\r\n");

	this.removeTag(tag);
}

imapProtocol.prototype.sendNO = function(tag, text) {
	this.push((tag || "*")+" NO "+text+"\r\n");

	this.removeTag(tag);
}

imapProtocol.prototype.emitOK = function(tag, command, args) {
console.log("emitOK: %s %s", tag, command);
	this.emit('imapOk', tag, command, args);
}

imapProtocol.prototype.emitBAD = function(tag, string) {
console.log("emitBAD: %s %s", tag, string);
	this.emit('imapBad', tag, string);
}

imapProtocol.prototype.emitNO = function(string) {
console.log("emitNO: %s", string);
	this.emit('imapNo', string);
}

imapProtocol.prototype._processString = function(string, state, cb) {
	// Split string
console.log("_processString: string:", string);
	var stringParts = string.split(" ");

	if (stringParts.length < 2) {
		this.emitBAD('*', "WTF!!!");
		if (cb) cb();
		return;
	}

	var tag = stringParts[0];

	// See if we know this tag already;
	var tagSeen = (this._tags[tag] !== undefined);

	if (tagSeen) {
		this.emitBAD(tag, "Tag '"+tag+"' already seen before.");
		if (cb) cb();
		return;
	}

	this._tags[tag] = true;

	var command = stringParts[1].toUpperCase();
	if (!IMAP_COMMANDS[command]) {
		this.emitBAD(tag, "Unknown command '"+stringParts[1]+"'");
		if (cb) cb(tag);
		return;
	}

	if (!(IMAP_COMMANDS[command].allowedStates & state)) {
		this.emitBAD(tag, "Command '"+command+"' not allowed in this state '"+stateToString(state)+"'.");
		if (cb) cb(tag);
		return;
	}

	var agrumentCount = stringParts.length - 2;
	if (agrumentCount > IMAP_COMMANDS[command].argumentsAllowed) {
		this.emitBAD(tag, "To many arguments specified for command '"+command+"'. Only '"+IMAP_COMMANDS[command].argumentsAllowed+"' arguments allowed.");
		if (cb) cb(tag);
		return;
	}

console.log("_processString: command:", command);
	stringParts.splice(0, 2);
	if (IMAP_COMMANDS[command]["responseFunc"]) {
		IMAP_COMMANDS[command].responseFunc(this, tag, stringParts);
	}
	else {
		this.emitOK(tag, command, stringParts);
	}
	if (cb) cb(tag);

}

imapProtocol.prototype.close = function() {
console.log("close()");
	if (this._socket === undefined) return;

	this._socket.unpipe();
	this._socket = undefined;
	this._authenticated = false;

	if (this._securePair) {
		this._securePair.cleartext.unpipe(this);
		this.unpipe(this._securePair.cleartext);
	}
}

imapProtocol.prototype.disconnect = function() {
	if (this._socket === undefined) return;

	var self = this;
	this.end(function(){
		if (self._securePair) {
			self._securePair.cleartext.end(function(){
				self._securePair.encrypted.end(function(){
					self._socket.end(function(){
						self.close();
					});
				});
			});
		}
		else {
			self._socket.end(function(){
				self.close();
			});
		}
	});

}

imapProtocol.prototype._transform = function(chunk, encoding, done) {
	for (var i = 0; i < chunk.length; i++) {

		if (this._receivingString) {
			if (chunk[i] === 10) {
				if ((this._crSeen) && (!this._lfSeen)) {
					this._lfSeen = true;
					var self = this;
					this._processString(this._string, this._state, function(tag){
						self._lfSeen = false;
						self._crSeen = false;
						self._string = '';
					});
				}
				else {
					this.emitBAD('*', 'Received LF (0x0A) byte which I did not expect.');
					return;
				}
			}
			else if (chunk[i] === 13) {
				if (this._crSeen) {
					this.emitBAD('*', 'Received CR (0x0D) byte and previous byte was also a CR. Not expected.');
					return;
				}
				else {
					this._crSeen = true;
				}
			}
			else if (this._crSeen) {
				this.emitBAD('*', 'Expected a LF (0x0A) byte after a CR byte but received another byte.');
				return;
			}
			else {
				this._string = this._string + String.fromCharCode(chunk[i]);
			}
		}
		else {
			this._receivingCommand = true;
			this._octets.push(chunk[i]);
		}
	}

	done();
};

module.exports = imapProtocol;

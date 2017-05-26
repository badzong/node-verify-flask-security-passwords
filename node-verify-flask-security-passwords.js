var crypto = require('crypto');
var pbkdf2_sha512 = require('pbkdf2-sha512');

function b64trimmed(buf) {
	return buf.toString('base64').replace(/=*$/, '').replace('+', '.');
}

function b64decode(str) {
	// . in Base64?
	str = str.replace('.', '+');
	if (str.length % 4) {
		str += '='.repeat(4 - str.length % 4);
	}
	return new Buffer(str, 'base64'); 
}

function get_hmac(secret, password) {
	var hmac = crypto.createHmac('sha512', secret).update(password).digest('base64');

	return hmac;
}

function get_hash(password, salt, rounds) {

	// FIXME: KeyLenBytes is hardcoded
	var h = b64trimmed(pbkdf2_sha512(password, salt, rounds, 64));
	var joined_hash = ['', 'pbkdf2-sha512', rounds, b64trimmed(salt), h].join('$');

	return joined_hash;
}

function verify_hash(password, stored_hash) {
	var scheme = stored_hash.split('$')[1];
	var rounds = stored_hash.split('$')[2];
	var salt = stored_hash.split('$')[3];

	// FIXME: Maybe throw an exception
	if (scheme !== 'pbkdf2-sha512') {
		return false;
	}

	var h = get_hash(password, b64decode(salt), rounds);

	return h === stored_hash;
}

function new_hash(password, rounds) {

	// FIXME: Salt size is hardcoded
	var salt = crypto.randomBytes(16);

	return get_hash(password, salt, rounds);
}

var password = 'Example Password';

// General usage for regular pbkdf2-sha512 hashes:
var h = new_hash(password, 20000);
console.log('HASH ' + h);
console.log('VERIFY ' + verify_hash(password, h));

// Usage for passwords generated with flask_security:
var SECURITY_PASSWORD_SALT = 'Put some random bytes here...'; // Used by flask security

var password_hmac = get_hmac(SECURITY_PASSWORD_SALT, password);
var h = new_hash(password_hmac, 20000);
console.log('HASH ' + h);
console.log('VERIFY ' + verify_hash(password_hmac, h));

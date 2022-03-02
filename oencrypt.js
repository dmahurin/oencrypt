'use strict';

const crypto = typeof(window) !== 'undefined' ? window.crypto : require('crypto');

function fill_options(options) {
	if(options.iter === undefined) { options.iter = 10000; }
	if(options.salt_magic === undefined) { options.salt_magic = 'Salted__'; }
	if(options.derive_it === undefined) { options.derive_it = true; }
	if(options.base64 === undefined) { options.base64 = false; }
	if(options.cipher === undefined) { options.cipher = 'aes-256-ctr'; }

	return options;
}

function string_to_buffer(s) {
	if(typeof Buffer !== 'undefined') {
		return Buffer.from(s, 'binary');
	} else {
		return Uint8Array.from(s, c => c.charCodeAt())
	}
}

function buffer_to_base64(buff) {
	if(typeof Buffer !== 'undefined') {
		return Buffer.from(buff).toString('base64') + "\n";
	} else  {
		return(btoa(String.fromCharCode.apply(null, buff)));
	}
}

function base64_to_buffer(buff) {
	if(typeof Buffer !== 'undefined') {
		return Buffer.from(buff.toString('utf8'), 'base64');
	} else {
  		return(Uint8Array.from(atob(buff).toString('utf8'), c => c.charCodeAt()));
	}
}

function hex_to_buffer (s) {
	return new Uint8Array(s.match(/../g).map(n => parseInt(n, 16)));
}

const get_password_key = (password) =>
	crypto.subtle.importKey("raw", (new TextEncoder()).encode(password), "PBKDF2", false, [
		"deriveBits",
	]);

const derive_bits = (password_key, salt, options) =>
	crypto.subtle.deriveBits({
		name: "PBKDF2",
		salt: salt,
		iterations: options.iter,
		hash: { name: "SHA-256" },
	},
		password_key,
		options.derive_it ? 384 : 256
	);

const derive_key = (key, keyUsage, options) =>
	crypto.subtle.importKey(
		"raw",
		key,
		{ name: options.cipher == 'aes-256-ctr' ? "AES-CTR" : "AES-CBC" },
		true,
		keyUsage
	);

async function encrypt(data, options) {
	options = fill_options(options);

	data = string_to_buffer(data);
	const salt = options.salt !== undefined ? hexstring_to_array(options.salt.padStart(16, "0")).slice(0,8) : crypto.getRandomValues(new Uint8Array(8));
	var iv = crypto.getRandomValues(new Uint8Array(16));
	const password_key = await get_password_key(options.password);
 
	const aes_key_bits = await derive_bits(password_key, salt, options);

	const aes_key = await derive_key(aes_key_bits.slice(0, 32), ["encrypt"], options);
	if(options.derive_it) iv = aes_key_bits.slice(32, 32 + 16);
	data = await crypto.subtle.encrypt({
		name: options.cipher == "aes-256-ctr" ? "AES-CTR" : "AES-CBC",
		counter: iv,
		iv: iv,
		length: 128
	},
		aes_key,
		data
	);

	data = new Uint8Array(data);
	const prefix = (new TextEncoder()).encode(options.salt_magic);
	var dataout = new Uint8Array(
		prefix.byteLength + salt.byteLength + data.byteLength + (options.derive_it ? 0 : iv.byteLength)
	);
	var offset = 0;
	dataout.set(prefix, 0); offset += prefix.byteLength;
	dataout.set(salt, offset); offset += salt.byteLength;
	if(!options.derive_it) { dataout.set(iv, offset); offset += iv.byteLength; }
	dataout.set(data, offset);

	if(options.base64) dataout = buffer_to_base64(dataout);
	return dataout;
}

async function decrypt(data, options) {
	options = fill_options(options);

	if(options.base64) data = base64_to_buffer(data);
	else if(typeof(data) == 'string') data = string_to_buffer(data) ;

	var offset = 0;
	var salt = data.slice(0, 8);
	if(options.salt_magic !== '' && (new TextDecoder()).decode(salt) === options.salt_magic) {
		offset += 8;
		salt = data.slice(offset, offset + 8);
	}
	offset += 8;
	var iv;

	if(!options.derive_it) {
		iv = data.slice(offset, offset + 16);
		offset += 16;
	}
	data = data.slice(offset);
	const password_key = await get_password_key(options.password);
	const aes_key_bits = await derive_bits(password_key, salt, options);
	const aes_key = await derive_key(aes_key_bits.slice(0, 32), ["decrypt"], options);
	if(options.derive_it) { iv = aes_key_bits.slice(32, 32 + 16); }
	data = await crypto.subtle.decrypt({
		name: options.cipher == "aes-256-ctr" ? "AES-CTR" : "AES-CBC",
		counter: iv,
		iv: iv,
		length: 128
	},
		aes_key,
		data
	);
	return data;
}

if(typeof(exports) !== 'undefined') {
	exports.encrypt = encrypt;
	exports.decrypt = decrypt;
}

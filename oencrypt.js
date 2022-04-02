'use strict';

(function(exports) {

const crypto = typeof(window) !== 'undefined' ? window.crypto : require('crypto');

function fill_options(options) {
	if(typeof options.key == 'string') { options.key = base64_to_buffer(options.key); }
	if(typeof options.salt == 'string') { options.salt = hex_to_buffer(options.salt.padStart(16, "0")).slice(0,8); }

	if(options.key !== undefined && options.key_salt === undefined) {
		options.key_salt = options.key.slice(0,8);
		options.key = options.key.slice(8);
	}

	if(options.iter === undefined) { options.iter = 10000; }
	if(options.salt_magic === undefined) { options.salt_magic = 'Salted__'; }
	if(options.derive_it === undefined) { options.derive_it = true; }
	if(options.base64 === undefined) { options.base64 = false; }
	if(options.cipher === undefined) { options.cipher = 'aes-256-ctr'; }

	return options;
}

function buffer_to_string(b) {
	return new TextDecoder().decode(b);
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
		return Buffer.from(buff).toString('base64');
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

function buffer_to_hex (buff) {
	return  new Uint8Array(buff).reduce((out, n) => (out + ('0' + n.toString(16)).slice(-2)),'');
}

const get_password_key = (password) =>
	crypto.subtle.importKey("raw", (new TextEncoder()).encode(password), "PBKDF2", false, [
		"deriveBits",
	]);

const get_hkdf_key = (key) =>
	crypto.subtle.importKey("raw", key, "HKDF", false, [
		"deriveBits",
	]);

const derive_bits = (password_key, salt, options, length) =>
	crypto.subtle.deriveBits({
		name: "PBKDF2",
		salt: salt,
		iterations: options.iter,
		hash: { name: "SHA-256" },
	},
		password_key,
		length !== undefined ? length : (options.derive_it ? 384 : 256)
	);

const derive_hkdf_bits = (password_key, salt, options, length) =>
	crypto.subtle.deriveBits({
		name: "HKDF",
		salt: salt,
		info: new Uint8Array(),
		iterations: options.iter,
		hash: { name: "SHA-256" },
	},
		password_key,
		length !== undefined ? length : (options.derive_it ? 384 : 256)
	);

const derive_key = (key, keyUsage, options, cipher) =>
	crypto.subtle.importKey(
		"raw",
		key,
		{ name: cipher !== undefined ? cipher : (options.cipher == 'aes-256-ctr' ? "AES-CTR" : "AES-CBC") },
		true,
		keyUsage
	);

function buffer_to_bigint(buffer) {
    let result = 0n;
    let base = 1n;
    new Uint8Array(buffer).reverse().forEach(function (n) {
        result = result + base * BigInt(n);
        base <<= 8n;
    });
    return result;
}

function bigint_to_buffer(n, size) {
	
    let result = new Uint8Array(size !== undefined ? size : 48);
    let i = 0;
    while (n > 0n) {
        result[i] = Number(n % 256n);
        n >>= 8n;
        i += 1;
    }
    return result.reverse();
}

async function lock_key(key, salt, password, options) {
	const password_key = await get_password_key(password);
	if(options.key_is_offset) {
		const password_key_bits = await derive_bits(password_key, salt, options, 256);
		return bigint_to_buffer((buffer_to_bigint(key) - buffer_to_bigint(password_key_bits) + (2n ** 256n)) % (2n ** 256n));
	} else {
		const password_key_bits = await derive_bits(password_key, salt, options, 384);
		const aes_key = await derive_key(password_key_bits.slice(0, 32), ["encrypt"], options, 'AES-CTR');
		const iv = password_key_bits.slice(32, 32 + 16);
		return new Uint8Array(await crypto.subtle.encrypt({name: "AES-CTR", counter: iv, iv: iv, length: 128}, aes_key, key));

	}
}

async function unlock_key(key, salt, password, options) {
	if(options.key_is_offset) {
		// key offset and added to the password pbkdf2
		const password_key = await get_password_key(password);
		const password_key_n = buffer_to_bigint(await derive_bits(password_key, salt, options, 256));
		return bigint_to_buffer((buffer_to_bigint(key) + password_key_n) % (2n ** 256n), 32);
	} else {
		// key is encrypted with iv and key derived from password pdkdf2 
		const password_key = await get_password_key(password);
		const password_key_bits = await derive_bits(password_key, salt, options, 384);
		const key_aes_key = await derive_key(password_key_bits.slice(0, 32), ["decrypt"], options, 'AES-CTR');
		const key_iv = password_key_bits.slice(32, 32 + 16);
		return await crypto.subtle.decrypt({name: "AES-CTR", counter: key_iv, iv: key_iv, length: 128}, key_aes_key, key);
	}
}

async function gen_key(options) {
	options = fill_options(options);
	var salt;
	var key;
	if(options.key === undefined) {
		salt = crypto.getRandomValues(new Uint8Array(8));
		key = crypto.getRandomValues(new Uint8Array(32));
	} else {
		salt = crypto.getRandomValues(new Uint8Array(8));
		key = await unlock_key(options.key, options.key_salt, options.password, options);
	}
	var new_key = await lock_key(key, salt, options.new_password, options);
	if(options.key !== undefined) {
		var s = 'validate';
		var e = await encrypt(s, options);
		options.key = new_key;
		options.key_salt = salt;
		options.password = options.new_password;
		if(s != buffer_to_string(await decrypt(e, options))) {
			throw("key/password check failed");
		}
	}
	var salt_key = new Uint8Array(salt.length + new_key.length);
	salt_key.set(salt);
	salt_key.set(new_key, salt.length);
	return salt_key;
}

async function encrypt(data, options) {
	options = fill_options(options);

	if(typeof data == 'string') { data = string_to_buffer(data); }

	const salt = options.salt !== undefined ? hex_to_buffer(options.salt.padStart(16, "0")).slice(0,8) : crypto.getRandomValues(new Uint8Array(8));

	var aes_key_bits;
	if( options.key === undefined) {
		const password_key = await get_password_key(options.password);
		aes_key_bits = await derive_bits(password_key, salt, options);
	} else {
		const hkdf_key = await get_hkdf_key(await unlock_key(options.key, options.key_salt, options.password, options));
		aes_key_bits = await derive_hkdf_bits(hkdf_key, salt, options);
	}

	const aes_key = await derive_key(aes_key_bits.slice(0, 32), ["encrypt"], options);

	var iv;

	if(!options.derive_it) { iv = crypto.getRandomValues(new Uint8Array(16)); }
	else if(iv === undefined) { iv = aes_key_bits.slice(32, 32 + 16);}

	if(options.counter_offset !== undefined) {
		iv = new Uint8Array(iv);
		iv = bigint_to_buffer(buffer_to_bigint(iv) + BigInt(options.counter_offset),16);
	}

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

	if(options.base64) dataout = buffer_to_base64(dataout) + "\n";
	return dataout;
}

function get_info(data, options) {
	options = fill_options(options);

	if(typeof data == 'string') { data = string_to_buffer(data); }

	var offset = 0;
	var salt = data.slice(0, 8);
	if(options.salt_magic !== '' && (new TextDecoder()).decode(salt) === options.salt_magic) {
		offset += 8;
		salt = data.slice(offset, offset + 8);
	}
	offset += 8;

	return { 'salt': salt, 'data_offset': offset, 'block_size': 16};
}

async function decrypt(data, options) {
	options = fill_options(options);

	if(options.base64) data = base64_to_buffer(data);
	else if(typeof(data) == 'string') data = string_to_buffer(data) ;

	var offset = 0;
	var salt;
	if(options.no_file_salt) {
		salt = options.salt;
	} else {
		salt = data.slice(0, 8);
		if(options.salt_magic !== '' && (new TextDecoder()).decode(salt) === options.salt_magic) {
			offset += 8;
			salt = data.slice(offset, offset + 8);
		}
		offset += 8;
	}
	var iv;

	var aes_key_bits;
	if( options.key === undefined) {
		const password_key = await get_password_key(options.password);
		aes_key_bits = await derive_bits(password_key, salt, options);
	} else {
		const hkdf_key = await get_hkdf_key(await unlock_key(options.key, options.key_salt, options.password, options));
		aes_key_bits = await derive_hkdf_bits(hkdf_key, salt, options);
	}

	if(!options.derive_it) {
		iv = data.slice(offset, offset + 16);
		offset += 16;
	} else {
		iv = aes_key_bits.slice(32, 32 + 16);
	}
	data = data.slice(offset);

	const aes_key = await derive_key(aes_key_bits.slice(0, 32), ["decrypt"], options);

	if(options.counter_offset !== undefined) {
		iv = bigint_to_buffer(buffer_to_bigint(iv) + BigInt(options.counter_offset),16);
	}

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

async function oencrypt_fetch(url, fetch_options, oencrypt_options) {
	if(oencrypt_options === undefined) { return fetch(url, fetch_options); }

	var trim_start;
	var trim_end;
	if(fetch_options !== undefined && fetch_options.headers !== undefined && fetch_options.headers.range !== undefined) {
		var bytes=fetch_options.headers.range.split('=')[1].split('-');
		var start = parseInt(bytes[0]);
		var end = parseInt(bytes[1]);
		fetch_options = Object.assign({}, fetch_options);
		fetch_options.headers = Object.assign({}, fetch_options.headers);
		fetch_options.headers.range = 'bytes=0-32';
		var file_info = get_info(await((await fetch(url, fetch_options)).arrayBuffer()), oencrypt_options);

		var bstart = Math.floor(start / file_info.block_size);
		var oencrypt_options = Object.assign({}, oencrypt_options);
		oencrypt_options.counter_offset = bstart;
		oencrypt_options.salt = file_info.salt;
		oencrypt_options.no_file_salt = true;

		var offset_start = file_info.data_offset + bstart * file_info.block_size;
		var offset_end = file_info.data_offset + file_info.block_size * Math.ceil(end / file_info.block_size);

		fetch_options.headers.range = 'bytes=' + offset_start.toString() + '-' + offset_end.toString();

		trim_start = start - (bstart * file_info.block_size);
		trim_end = trim_start + end - start;
	}

	var response = await fetch(url, fetch_options);
	var data = await response.arrayBuffer();
	data = await decrypt(data, oencrypt_options);
	if(trim_end !== undefined) {
		data = data.slice(trim_start, trim_end);
	}
	return new Response(data);
}

if(exports === undefined && typeof(window) !== 'undefined' && typeof(document) !== 'undefined') {
	var scripts = document.getElementsByTagName("script");
	var currentScript = document.currentScript || scripts[scripts.length-1];
	var name;
	if(currentScript.hasAttribute('data-name')) {
		name = currentScript.getAttribute('data-name');
	} else if (currentScript.src != "") {
		name = currentScript.src; name = name.substring(name.lastIndexOf('/') + 1); name = name.substring(0, name.indexOf('.'));
	} else {
		name = "oencrypt";
	}
	window[name] = {};
	exports = window[name];
}

exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.gen_key = gen_key;
exports.get_info = get_info;
exports.fetch = oencrypt_fetch;
exports.buffer_to_hex = buffer_to_hex;
exports.hex_to_buffer = hex_to_buffer;
exports.buffer_to_base64 = buffer_to_base64;
exports.base64_to_buffer = base64_to_buffer;
exports.buffer_to_string = buffer_to_string;

})(typeof(exports) !== 'undefined' ? exports: undefined);

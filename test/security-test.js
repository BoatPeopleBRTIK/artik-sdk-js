/* Global Includes */
var testCase = require('mocha').describe;
var pre = require('mocha').before;
var preEach = require('mocha').beforeEach;
var post = require('mocha').after;
var postEach = require('mocha').afterEach;
var assertions = require('mocha').it;
var step = require('mocha-steps').step;
var assert = require('chai').assert;
var validator = require('validator');
var exec = require('child_process').execSync;
var artik = require('../src');
var fs = require('fs');

/* Test Specific Includes */
var security = {};
var pem_cert = "-----BEGIN CERTIFICATE-----\n" +
	"MIICBjCCAaygAwIBAgIQWLB3huXHE8gw1wJF7K6X3DAKBggqhkjOPQQDAjBjMQsw\n" +
	"CQYDVQQGEwJLUjEkMCIGA1UEChMbU2Ftc3VuZyBTZW1pY29uZHVjdG9yIEFSVElL\n" +
	"MRYwFAYDVQQLEw1BUlRJSyBSb290IENBMRYwFAYDVQQDEw1BUlRJSyBSb290IENB\n" +
	"MB4XDTE3MDIyNDE4MTIyMloXDTMyMDIyNDE4MTIyMlowYzELMAkGA1UEBhMCS1Ix\n" +
	"JDAiBgNVBAoTG1NhbXN1bmcgU2VtaWNvbmR1Y3RvciBBUlRJSzEWMBQGA1UECxMN\n" +
	"QVJUSUsgUm9vdCBDQTEWMBQGA1UEAxMNQVJUSUsgUm9vdCBDQTBZMBMGByqGSM49\n" +
	"AgEGCCqGSM49AwEHA0IABDFxz+e+hsmEuj+0ikoh01TZp6B7AUUFHvz08rStVvfe\n" +
	"9n2XoiQsJJycZ51Ex9JM1XtsjYvg5j5zBNqC9syA7v6jQjBAMA4GA1UdDwEB/wQE\n" +
	"AwIBBjAdBgNVHQ4EFgQUotPhsbXrQoIX7ngaetQqFlK+FJcwDwYDVR0TAQH/BAUw\n" +
	"AwEB/zAKBggqhkjOPQQDAgNIADBFAiEAvS7IdSkE4Flk4S0hPeTYJvPyKH96tR+v\n" +
	"DHw5gMUmRdECICcgp06TVZSeXOAILvWYqnU/y5kjEV3HViY81+4isMlv\n" +
	"-----END CERTIFICATE-----\n";

var rsa_sample_key = new Buffer([
	0x30, 0x82, 0x02, 0x5B, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xC1, 0x62, 0xAF, 0x64, 0x69,
	0xEB, 0x4A, 0x2E, 0x37, 0x98, 0xA1, 0x3B, 0x1D, 0xA8, 0xD7, 0xFD, 0xA8, 0xDC, 0xB4, 0x31, 0xCE,
	0xD2, 0xB9, 0x48, 0x29, 0x21, 0x92, 0xC7, 0xE5, 0x8D, 0xA7, 0xCD, 0x15, 0xEA, 0xB9, 0x41, 0x87,
	0xAA, 0xB9, 0x08, 0x07, 0x69, 0x3A, 0x28, 0xC7, 0x28, 0x28, 0xE9, 0x3C, 0x85, 0x61, 0x13, 0xAC,
	0xBB, 0x01, 0x35, 0xE8, 0xC5, 0xF3, 0x91, 0x4C, 0x2C, 0x3D, 0xE1, 0xD5, 0xF8, 0x4B, 0xA0, 0x28,
	0xE2, 0x4A, 0x6B, 0x07, 0xBF, 0x4D, 0xDD, 0x5F, 0x3F, 0xDC, 0x1C, 0x9A, 0xF5, 0xCD, 0xDC, 0x7B,
	0xAD, 0xB5, 0x8C, 0x15, 0x4A, 0x77, 0xEC, 0x0F, 0x91, 0x0C, 0xEF, 0x57, 0x85, 0x82, 0xE3, 0x9A,
	0x1A, 0x46, 0x6B, 0x67, 0xA7, 0x3C, 0xEB, 0xA7, 0xDF, 0x60, 0xB5, 0xDA, 0xAB, 0x9B, 0xEF, 0xA0,
	0xCB, 0xBD, 0x0E, 0x82, 0x32, 0x15, 0x44, 0xB9, 0xBC, 0x5F, 0x05, 0x02, 0x03, 0x01, 0x00, 0x01,
	0x02, 0x81, 0x80, 0x1D, 0x0D, 0xAC, 0x78, 0x13, 0x89, 0xAB, 0xED, 0x61, 0xA0, 0xE6, 0xA8, 0x30,
	0xFE, 0x8A, 0xE4, 0xAB, 0x17, 0xED, 0x62, 0x86, 0x46, 0x16, 0x5C, 0x07, 0x01, 0xEA, 0x41, 0x69,
	0xF5, 0x6C, 0x3E, 0x5D, 0x8A, 0x94, 0x26, 0x8A, 0x31, 0x55, 0xF7, 0x24, 0xD5, 0xE4, 0x4C, 0xF8,
	0x0E, 0xCA, 0x86, 0xAF, 0xF7, 0x01, 0xEC, 0xA8, 0xC8, 0xB7, 0x97, 0xD7, 0xCE, 0xD5, 0x97, 0x00,
	0xB0, 0xAC, 0xE3, 0x1B, 0xD1, 0xAD, 0x98, 0xEC, 0x7C, 0x44, 0x96, 0xD2, 0xDD, 0x0C, 0x85, 0x22,
	0x07, 0xF4, 0xCC, 0x7A, 0x38, 0x82, 0x18, 0x79, 0xC8, 0x71, 0x15, 0x67, 0xB6, 0xAB, 0x07, 0xB9,
	0xC7, 0x95, 0xE7, 0x0D, 0x4A, 0xE9, 0x8E, 0x6A, 0x78, 0xB4, 0xCB, 0x47, 0xB8, 0xC1, 0x35, 0x0E,
	0xB3, 0xD0, 0xB9, 0x64, 0xCF, 0xFF, 0x08, 0xDB, 0x86, 0xB2, 0x05, 0x7D, 0xB6, 0x11, 0xE8, 0x35,
	0xBA, 0x92, 0xC9, 0x02, 0x41, 0x00, 0xF4, 0x67, 0xC2, 0xC8, 0x3F, 0xF2, 0x68, 0xDD, 0xFA, 0x21,
	0xE5, 0xCD, 0x8F, 0xFA, 0xFA, 0xFE, 0x42, 0xBA, 0x93, 0x42, 0x7A, 0x72, 0x5C, 0x54, 0xC3, 0xEE,
	0x98, 0x4C, 0x7F, 0x60, 0xAB, 0x08, 0x96, 0xDC, 0x3D, 0xDC, 0xB7, 0xDC, 0x2E, 0xB5, 0xC3, 0xB9,
	0xA0, 0x5A, 0x12, 0xAE, 0x61, 0xFD, 0x86, 0x7C, 0xAC, 0x0C, 0x26, 0xD8, 0xC5, 0x86, 0x41, 0x5C,
	0xF6, 0x10, 0xA0, 0xFA, 0x3F, 0xA7, 0x02, 0x41, 0x00, 0xCA, 0x8F, 0x4D, 0x3C, 0x1D, 0x02, 0xC8,
	0x0A, 0xCE, 0x2D, 0x5C, 0x5B, 0x5A, 0x3D, 0x29, 0x63, 0x6D, 0x5E, 0xBC, 0xBB, 0xE9, 0x99, 0x7F,
	0xDB, 0x4E, 0xC1, 0xC6, 0x99, 0xC5, 0x24, 0xCB, 0x64, 0xFA, 0xBF, 0x3E, 0x70, 0xB4, 0x66, 0x91,
	0x7E, 0xEC, 0x0D, 0x69, 0x74, 0xEE, 0xC4, 0x1E, 0xC5, 0xE9, 0xC0, 0xE8, 0x46, 0x36, 0x19, 0x82,
	0xE3, 0xBA, 0xC9, 0x2B, 0xEF, 0xB9, 0xA0, 0xE1, 0x73, 0x02, 0x40, 0x1F, 0xEB, 0x39, 0x2E, 0x0B,
	0xE3, 0xED, 0xBC, 0x27, 0xC1, 0xAB, 0x90, 0x78, 0x20, 0x50, 0x0D, 0x4A, 0xCB, 0xB1, 0x15, 0xBA,
	0x86, 0x1A, 0xF6, 0xDB, 0x0B, 0xDB, 0x0A, 0x0A, 0x8C, 0xA6, 0x69, 0x9D, 0xC2, 0x2F, 0xB6, 0x16,
	0xB1, 0x03, 0xCC, 0xAB, 0x3E, 0x1F, 0xEA, 0x03, 0x8C, 0x90, 0xB1, 0x9A, 0x91, 0xC7, 0xAA, 0x62,
	0x9C, 0x66, 0xD7, 0x8C, 0xCB, 0xC6, 0x3B, 0x0F, 0xBA, 0xFE, 0xFB, 0x02, 0x40, 0x38, 0x70, 0xC7,
	0x8F, 0x89, 0x71, 0xDD, 0xF5, 0x8C, 0xCF, 0x7C, 0xDD, 0x83, 0x7E, 0x69, 0x4A, 0xE8, 0x0D, 0xAE,
	0xBF, 0x19, 0x6F, 0x08, 0xFE, 0x3D, 0xAA, 0xA6, 0xC0, 0xEF, 0xFA, 0xB9, 0xA5, 0xD0, 0x6C, 0x7B,
	0x64, 0x82, 0x0F, 0xD6, 0x58, 0xAC, 0x43, 0x6C, 0x70, 0x05, 0x9B, 0xA6, 0x0B, 0x75, 0x7F, 0xA7,
	0xF8, 0xF0, 0x58, 0x19, 0x6D, 0x84, 0xFD, 0x4A, 0xFD, 0xC8, 0x16, 0x78, 0xDB, 0x02, 0x40, 0x4C,
	0x50, 0x6F, 0xC9, 0x9E, 0x54, 0xCF, 0xD5, 0x01, 0xAA, 0x8E, 0xBB, 0x49, 0xB5, 0x8D, 0x41, 0x8B,
	0xF1, 0xE3, 0xFA, 0xF8, 0x3D, 0x32, 0xA0, 0x61, 0xA2, 0x88, 0x3C, 0x7E, 0x7E, 0x6F, 0xCA, 0x9C,
	0xBC, 0x2C, 0x8A, 0x68, 0xFB, 0x1B, 0x87, 0x54, 0x0E, 0xED, 0x58, 0x4B, 0x5D, 0x92, 0xEA, 0x52,
	0xBF, 0xF7, 0x89, 0x41, 0xE9, 0xC1, 0x54, 0x31, 0xEA, 0x92, 0x96, 0xF2, 0x43, 0x01, 0xBD
]);

var ecc_pair = new Buffer([
	0x30, 0x78, 0x02, 0x01, 0x01, 0x04, 0x20, 0x1e, 0x20, 0xd3, 0xa6, 0xaa, 0x38, 0xf6, 0xf1, 0x65,
	0x19, 0xb8, 0xae, 0x31, 0x86, 0x7a, 0x47, 0x3b, 0xaf, 0x5e, 0x54, 0x93, 0xb1, 0x46, 0xba, 0x8d,
	0x39, 0x25, 0xa9, 0xe4, 0xd2, 0x41, 0x66, 0xa0, 0x0b, 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02,
	0x08, 0x01, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x1a, 0xbc, 0xb3, 0x24, 0xa4, 0x1e,
	0x89, 0x79, 0x6e, 0xbe, 0x75, 0x7f, 0x78, 0xa7, 0x32, 0x21, 0xae, 0x7b, 0xb5, 0xe4, 0xa4, 0x4d,
	0x07, 0x44, 0x0e, 0x07, 0x5a, 0x77, 0x3d, 0xb3, 0xd8, 0xfc, 0x65, 0x02, 0xfc, 0xd7, 0x1a, 0x3c,
	0xcb, 0x9a, 0x4e, 0x34, 0xde, 0x32, 0xe8, 0x3e, 0x2e, 0xda, 0x09, 0xe0, 0x5f, 0x24, 0x7b, 0x86,
	0x83, 0x08, 0xc3, 0xf6, 0x7f, 0xe3, 0x81, 0xbb, 0xda, 0x62
]);

var sample_key = new Buffer([
	0x30, 0x78, 0x02, 0x01, 0x01, 0x04, 0x20, 0x53, 0x02, 0x02, 0xF3, 0x1A,
	0x24, 0x2E, 0x1B, 0xCA, 0xE8, 0x2B, 0xAB, 0xF2, 0x86, 0x25, 0x59, 0x36,
	0xE5, 0x20, 0x6C, 0x39, 0xAC, 0x1C, 0x3D, 0xBD, 0x6B, 0x59, 0x29, 0xD0,
	0xC2, 0xA2, 0xB3, 0xA0, 0x0B, 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02,
	0x08, 0x01, 0x01, 0x07, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x2B, 0x10,
	0x61, 0x1F, 0xFC, 0xAA, 0x9C, 0xEC, 0xE3, 0xD9, 0x87, 0x05, 0x49, 0x3E,
	0x7E, 0xCD, 0xC8, 0xCC, 0xDA, 0xA2, 0x92, 0xBE, 0x28, 0x71, 0x8E, 0x81,
	0xAB, 0x8B, 0x22, 0xCB, 0xFE, 0x46, 0xA7, 0x31, 0xE7, 0x36, 0xAB, 0xD6,
	0x12, 0x9E, 0x05, 0x1C, 0x1E, 0xEB, 0xA8, 0x11, 0x56, 0x92, 0x6A, 0xC6,
	0xB1, 0x85, 0x4D, 0x41, 0x43, 0x75, 0x7B, 0xE8, 0x6E, 0x83, 0x2C, 0xF5,
	0xCC, 0x6B
]);

var hash = new Buffer([
	0xdc, 0x71, 0x78, 0xb3, 0xad, 0xb8, 0x90, 0xad, 0x47, 0x7e, 0x8b, 0xa0,
	0x0c, 0x70, 0x11, 0x93, 0xa7, 0x8e, 0xe7, 0xb8, 0xf6, 0xb2, 0x7e, 0xa2,
	0x67, 0x0d, 0xc5, 0x0b, 0xfe, 0xbe, 0xef, 0xc9
]);

var expected_hash = new Buffer([
	0xdc, 0x71, 0x78, 0xb3, 0xad, 0xb8, 0x90, 0xad, 0x47, 0x7e, 0x8b, 0xa0,
	0x0c, 0x70, 0x11, 0x93, 0xa7, 0x8e, 0xe7, 0xb8, 0xf6, 0xb2, 0x7e, 0xa2,
	0x67, 0x0d, 0xc5, 0x0b, 0xfe, 0xbe, 0xef, 0xc9
]);

var aes_input  = new Buffer([
	1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6
]);

/* Test Case Module */
testCase('Test JS security API', function() {

	pre(function(done) {
		this.timeout(50000);
		try {
			security = new artik.security.Security();
			done();
		} catch (err) {
			console.log("[Exception] : " + err.message);
		}
	});

	testCase('#Authentification Test', function() {

		step('#get_ec_pub_key_from_cert: Get "EC pub key" of the certificate.', function(done) {

			this.timeout(10000);

			try {
				var ec_pub_key = security.get_ec_pubkey_from_cert(pem_cert);
				assert.isString(ec_pub_key, "Invalid return type of the variable : 'Key'.\n");
				console.log("EC Pub Key of certificate : ");
				console.log(ec_pub_key);
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#get_random_bytes(): Generate random bytes for an array of 32 bytes.', function(done) {

			this.timeout(10000);

			try {
				var random = security.get_random_bytes(32);
				assert.equal(random.length, 32, "Invalid buffer returned due to the invalid size wichi is not equal to 32 for : 'Random'.\n");
				console.log("Bytes : ");
				for (var i = 0; i < random.length; ++i) {
					process.stdout.write(" " + random.readUInt8(i));
				}
				process.stdout.write("\n");
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#get_certificate: Get the certificate from the Secure Element.', function(done) {

			this.timeout(10000);

			try {
				certificate = security.get_certificate('ARTIK/0', 'ARTIK_SECURITY_CERT_TYPE_PEM');
				console.log("Certificate : ");
				console.log(certificate.toString());
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}

		});

		step('#get_certificate_sn(): Get the serial number of the certificate from the Secure Element.', function(done) {

			this.timeout(10000);

			try {
				var sn = security.get_certificate_sn(pem_cert);
				assert.isNotNull(sn, "Invalid return type of the variable : 'sn'.\n");
				console.log("Serial Number : ");
				console.log(sn);
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#get_certificate_pem_chain: Get root and intermediate certificates from the Secure Element.', function(done) {

			this.timeout(10000);

			try {
				var certificates = security.get_certificate_pem_chain('ARTIK/0');

				for (var i = 0; i < certificates.length; i++) {
					assert.isArray(certificates, "Invalid return type of the variable : 'certificates'.\n");
					console.log("Cert #" + i + "\n" + certificates[i]);
				}
				done();

			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});

		step('#set_certificate: Set certificate from the Secure Element.', function(done) {

			this.timeout(10000);

			try {
				var res = security.set_certificate('SSDEF/0', pem_cert);
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});

		step('#remove_certificate: Remove certificate from the Secure Element.', function(done) {

			this.timeout(10000);

			try {
				var res = security.remove_certificate('SSDEF/0');
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});
	});

	testCase('#Hash Test', function() {
		step('#get_hash: Get the hash of the input message.', function(done) {

			this.timeout(10000);
			var hash_algorithm = "sha256";

			try {
				var hash = security.get_hash(hash_algorithm, sample_key);
				console.log("Hash of the input message: \n" + hash.toString('hex'));

				if (Buffer.compare(expected_hash, hash) == 0) {
					console.log("Hash and expected_hash are identical. OK");
					done();
				} else {
					console.log("Hash and expected_hash are different result  not OK");
				}
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});
	});

	testCase('#HMAC Test', function() {

		var hmac_algorithm = "hmac";
		var input_hmac = new Buffer.alloc(300, 0);

		step('#set_key: Set a HMAC key.', function(done) {

			this.timeout(10000);

			try {
				var res = security.set_key(hmac_algorithm, 'SSDEF/0', input_hmac);
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#get_hmac: Get HMAC from input data.', function(done) {

			this.timeout(10000);
			var see_hash_mode = "sha1";

			try {
				var hmac = security.get_hmac(see_hash_mode, 'SSDEF/0', input_hmac);

				console.log("HMAC of the input data: \n" + hmac.toString('hex'));
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#remove_key: Remove a HMAC key.', function(done) {

			this.timeout(10000);

			try {
				var res = security.remove_key(hmac_algorithm, 'SSDEF/0');
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});
	});

	testCase('#RSA Test', function() {

		var rsa_sig;
		var rsa_algorithm = "rsa1024";
		var hash_algorithm = "sha1";
		var hash_rsa = new Buffer.alloc(300, 0x35);
		var rsa_signature_algorithm = "rsassa_1024_pkcs1_v1_5_sha160";

		step('#set_key: Set a RSA key.', function(done) {

			this.timeout(10000);

			try {
				var res = security.set_key(rsa_algorithm, 'SSDEF/0', rsa_sample_key);
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#get_hash: Get the hash of the input message.', function(done) {

			this.timeout(10000);

			try {
				res_hash = security.get_hash(hash_algorithm, hash_rsa);
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#get_rsa_signature: Get RSA get_rsa_signature from input data.', function(done) {

			this.timeout(10000);

			try {
				rsa_sig = security.get_rsa_signature(rsa_signature_algorithm, 'SSDEF/0', res_hash, 0);
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});

		step('#verify_rsa_signature: Verify RSA signature for input hash.', function(done) {

			this.timeout(10000);

			try {
				var res = security.verify_rsa_signature(rsa_signature_algorithm, 'SSDEF/0', res_hash, 0, rsa_sig);
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});

		step('#remove_key: Remove a RSA key.', function(done) {

			this.timeout(10000);

			try {
				var res = security.remove_key(rsa_algorithm, 'SSDEF/0');
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});
	});

	testCase('#ECDSA Test', function() {

		var ecdsa_sig;
		var ecdsa_key_algorithm = "ecc_brainpool_p256r1";
		var hash_ecdsa = new Buffer.alloc(32, 0);

		step('#set_key: Set a ECDSA key.', function(done) {

			this.timeout(10000);

			try {
				var res = security.set_key(ecdsa_key_algorithm, 'SSDEF/0', ecc_pair);
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#get_ecdsa_signature: Get ECDSA get_ecdsa_signature from input data.', function(done) {

			this.timeout(10000);
			try {
				ecdsa_sig = security.get_ecdsa_signature(ecdsa_key_algorithm, 'SSDEF/0', hash_ecdsa);
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}

		});

		step('#verify_ecdsa_signature: Verify ECDSA signature for input hash.', function(done) {

			this.timeout(10000);
			try {
				var res = security.verify_ecdsa_signature(ecdsa_key_algorithm, 'SSDEF/0', hash_ecdsa, ecdsa_sig);
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});

		step('#remove_key: Remove a ECDSA key.', function(done) {

			this.timeout(10000);

			try {
				var res = security.remove_key(ecdsa_key_algorithm, 'SSDEF/0');
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});
	});

	testCase('# Key Manager Test', function() {
		var sample_key_algorithm = "ecc_brainpool";
		var generate_key_algorithm = "rsa1024";

		step('#set_key: Set a "key" in secure element.', function(done) {

			this.timeout(10000);

			try {
				var res = security.set_key(sample_key_algorithm, 'SSDEF/0', sample_key);
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#remove_key: Remove a SAMPLE_KEY.', function(done) {

			this.timeout(10000);

			try {
				var res = security.remove_key(sample_key_algorithm, 'SSDEF/0');
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});

		step('#generate_key: Generate a key.', function(done) {

			this.timeout(10000);
			try {
				var res = security.generate_key(generate_key_algorithm, 'SSDEF/0');
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#get_publickey: Get public key from an asymmetric key.', function(done) {

			this.timeout(10000);
			try {
				var publickey = security.get_publickey(generate_key_algorithm, 'SSDEF/0');
				console.log("Publickey from asymmetric key:\n" + publickey.toString('hex'));
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#remove_key: Remove a key.', function(done) {

			this.timeout(10000);
			try {
				var res = security.remove_key(generate_key_algorithm, 'SSDEF/0');
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});
	});

	testCase('#Secure Storage Test: WRITE/READ/REMOVE small data into secure storage', function() {

		var buffer = Buffer.alloc(512);

		step('#get_random_bytes(): Generate random bytes for an array of 512 bytes.', function(done) {

			this.timeout(10000);

			try {
				buffer = security.get_random_bytes(512);
				assert.equal(buffer.length, 512, "Invalid buffer returned due to the invalid size wichi is not equal to 512 for : 'Random'.\n");
				console.log(buffer);
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#write_secure_storage(): Write a small data into secure storage.', function(done) {

			this.timeout(10000);

			try {
				var res = security.write_secure_storage('SSDEF/0', 0, buffer);
				console.log(res);
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#read_secure_storage(): Read a data from secure storage.', function(done) {

			this.timeout(10000);

			try {
				var read_buf = security.read_secure_storage('SSDEF/0', 0, 512);
				console.log(read_buf);
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#remove_secure_storage(): Remove a data from secure storage.', function(done) {

			this.timeout(10000);

			try {
				var res = security.remove_secure_storage('SSDEF/0');
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});
	});

	testCase('#AES Encryption decryption Test', function() {

		var aes_enc_data;
		var aes_enc_mode = "aes_ecb_nopad";
		var iv = Buffer.alloc(8, 0);
		var aes_key_algorithm = "aes128";

		step('#set_key: Set a AES key.', function(done) {

			this.timeout(10000);

			try {
				var res = security.set_key(aes_key_algorithm, 'SSDEF/0', aes_input);
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#aes_encryption(): Encrypt a input message using AES.', function(done) {

			this.timeout(10000);

			try {
				aes_enc_data = security.aes_encryption(aes_enc_mode, 'SSDEF/0', iv, aes_input);
				console.log(aes_enc_data.toString('hex'));

				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}

		});

		step('#aes_decryption(): Decrypt a input message using AES.', function(done) {

			this.timeout(10000);

			try {
				var aes_dec_data = security.aes_decryption(aes_enc_mode, 'SSDEF/0', iv, aes_enc_data);
				console.log(aes_dec_data.toString('hex'));
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#remove_key: Remove a AES key.', function(done) {

			this.timeout(10000);

			try {
				var res = security.remove_key(aes_key_algorithm, 'SSDEF/0');
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});
	});

	testCase('#RSA Encryption decryption Test', function() {
		var rsa_enc_data;
		var rsa_key_algorithm = "rsa1024"
		var rsa_enc_mode = "rsaes_1024_pkcs1_v1_5";

		step('#Set_key: Set a RSA key.', function(done) {
			this.timeout(10000);

			try {
				var res = security.set_key(rsa_key_algorithm, 'SSDEF/0', rsa_sample_key);
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#rsa_encryption(): Encrypt a input message using RSAES.', function(done) {

			this.timeout(10000);

			try {
				rsa_enc_data = security.rsa_encryption(rsa_enc_mode, 'SSDEF/0', rsa_sample_key);
				console.log(rsa_enc_data.toString('hex'));
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#rsa_decryption(): Decrypt a input message using RSAES.', function(done) {

			this.timeout(10000);

			try {
				var rsa_dec_data = security.rsa_decryption(rsa_enc_mode, 'SSDEF/0', rsa_enc_data);
				console.log(rsa_dec_data.toString('hex'));
				done();
			} catch (err) {
				console.log("[Exception] : " + err.message);
				done(err);
			}
		});

		step('#remove_key: Remove a RSA key.', function(done) {

			this.timeout(10000);

			try {
				var res = security.remove_key(rsa_key_algorithm, 'SSDEF/0');
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});
	});

	testCase('#Convert pem to der Test', function() {
		step('#convert_pem_to_der: Convert a certificate or a key from PEM format to DER format.', function(done) {

			this.timeout(10000);

			try {
				var der_data = security.convert_pem_to_der(pem_cert);
				console.log(der_data);
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});
	});

	testCase('#DHM params Test', function() {

		var dh_algorithm = "dh_1024";
		var pubkey;

		step('#generate_dhm_params: Generate DH key pair and get public key.', function(done) {

			this.timeout(10000);

			try {
				var pubkey = security.generate_dhm_params(dh_algorithm, 'SSDEF/0');
				console.log(pubkey);
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});

		step('#remove_key: Remove a dh key.', function(done) {
			try {
				var res = security.remove_key(dh_algorithm, 'SSDEF/0');
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});

		step('#set_dhm_params: Generate DH key pair and get public key using dh parameter.', function(done) {

			var dh_params = new Buffer([
				0x30, 0x81, 0x87, 0x02, 0x81, 0x81, 0x00, 0xcb, 0x00, 0x32, 0x75, 0x58, 0xf1, 0xd4, 0x4b, 0xe8,
				0xf6, 0x27, 0x47, 0x69, 0xdc, 0x63, 0xe6, 0x1f, 0xc9, 0xe7, 0xb6, 0xbd, 0x1e, 0xaf, 0xed, 0xfe,
				0xd8, 0x43, 0x34, 0xa8, 0x4a, 0x6a, 0xb8, 0x16, 0x1c, 0x22, 0xc4, 0x95, 0x80, 0x21, 0x63, 0x0e,
				0xac, 0xff, 0x26, 0x84, 0xd6, 0x28, 0x53, 0x2f, 0xf2, 0x2b, 0xab, 0x98, 0x3a, 0x97, 0xdc, 0xe5,
				0x0a, 0x56, 0xc0, 0x36, 0x4f, 0x67, 0xc0, 0x86, 0x6a, 0x70, 0x70, 0x21, 0x89, 0x88, 0xad, 0xef,
				0xaa, 0x00, 0x3b, 0x57, 0x52, 0x7e, 0xcf, 0x59, 0x42, 0x87, 0x04, 0x62, 0x4a, 0x33, 0xe0, 0xda,
				0xf3, 0xcc, 0x3d, 0x6b, 0xe7, 0xd4, 0xc6, 0xc3, 0xa8, 0xd8, 0xd1, 0x9b, 0x1a, 0xb7, 0xa3, 0x7f,
				0x48, 0xf3, 0x03, 0xcc, 0x7c, 0x78, 0xb0, 0x2c, 0x6a, 0xa2, 0x97, 0x7c, 0xf1, 0xee, 0x7d, 0x10,
				0x24, 0x56, 0xbd, 0x87, 0x69, 0xf5, 0x0b, 0x02, 0x01, 0x02
			]);

			this.timeout(10000);

			try {
				pubkey = security.set_dhm_params('SSDEF/0', dh_params);
				console.log(pubkey);
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});

		step('#compute_dhm_params: Compute secret key from DH key and public key.', function(done) {

			this.timeout(10000);

			try {
				var secret = security.compute_dhm_params('SSDEF/0', pubkey);
				console.log(secret);
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});

		step('#remove_key: Remove a dh key.', function(done) {

			this.timeout(10000);

			try {
				var res = security.remove_key(dh_algorithm, 'SSDEF/0');
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});
	});

	testCase('#ECDH params Test', function() {
		var ecdh_algorithm = "ecc_brainpool_p256r1";
		var pubkey;

		step('#generate_ecdh_params: Generate ECDH key.', function(done) {

			this.timeout(10000);

			try {
				pubkey = security.generate_ecdh_params(ecdh_algorithm, 'SSDEF/0');
				console.log(pubkey);
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});

		step('#compute_ecdh_params: Compute secret key from ECDH key and public key..', function(done) {

			this.timeout(10000);

			try {
				var secret = security.compute_ecdh_params('SSDEF/0', pubkey);
				console.log(secret);
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});

		step('#remove_key: Remove a ecdh key.', function(done) {

			this.timeout(10000);

			try {
				var res = security.remove_key(ecdh_algorithm, 'SSDEF/0');
				done();
			} catch (err) {
				assert(!err, "[Exception] : " + err.message);
				done(err);
			}
		});
	});
});
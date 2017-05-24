"use strict";

///////////////////////////////////////////////////////////////////////////////////
// Developer notes
///////////////////////////////////////////////////////////////////////////////////
// Exceptions:
// ===========
// When Crypto operation fail, it produce exception. It also produce exception if
// password is wrong. So every exception does not have to be an error.
///////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////
// Constructor / Class definition
///////////////////////////////////////////////////////////////////////////////////

/**
 * @class
 * @classdesc Crypter class
 */
function Crypter() {
    this.crypto = window.crypto || window.msCrypto; // for IE 11

    if (this.crypto == null) {
        throw new Error("Crypto API is not supported in this browser");
    }

    this.subtle = this.crypto.subtle;

    if (this.subtle == null) {
        throw new Error("Crypto API is not supported in this browser");
    }
};


///////////////////////////////////////////////////////////////////////////////////
// Properties
///////////////////////////////////////////////////////////////////////////////////

Crypter.prototype.crypto = null;
Crypter.prototype.subtle = null;


///////////////////////////////////////////////////////////////////////////////////
// Methods
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Provides complex decrytion of ciphertext
 * @param {dictionary} algorithm Ciphername, iv, tag and others
 * @param {CryptoKey} key Crypto key
 * @param {string} secret Secret in hex string
 * @returns {Promise} Promise contains plaintext
 */
Crypter.prototype.Decrypt = function (algorithm, key, secret) {
    var self = this;

    var ciphername = algorithm.name;

    return new Promise(function (resolve, reject) {
        if (ciphername == "AES-GCM") {
            self.DecrypAesGcm(algorithm.iv, algorithm.tag, secret, key).then(function (plaintext) {
                resolve(plaintext);
            }).catch(function (error) {
                reject(error);
            });
        } else if (ciphername == "RSA-OAEP") {
            self.DecrypRsaOaep(secret, key).then(function (plaintext) {
                resolve(plaintext);
            }).catch(function (error) {
                reject(error);
            });
        } else {
            reject("[CRYPTER] Algorithm " + ciphername + "is not supported.");
        }
    });
};

/**
 * @description Provides key derivation
 * @param {array} algorithm Key derivation algorithm
 * @param {string} password Password
 * @returns {Promise} Promise contains cryptoKey
 */
Crypter.prototype.DeriveKey = function (algortithm, password) {
    var self = this;

    return new Promise(function (resolve, reject) {
        resolve();
    });
}

/**
 * @description Provides hash function
 * @param {array} algorithm Key derivation algorithm
 * @param {string} plaintext Plaintext
 * @returns {Promise} Promise contains cryptoKey
 */
Crypter.prototype.Hash = function (algortithm, plaintext) {
    var self = this;

    return new Promise(function (resolve, reject) {
        resolve();
    });
}

/**
 * @description Provides decryption of AES-GCM algorithm
 * @param {string} iv Init vector in hex string
 * @param {number} tag Tag length
 * @param {string} secret Secret in hex string
 * @param {CryptoKey} key CryptoKey for AES-GCM
 * @returns {Promise} Promise contains decrypted plaintext
 */
Crypter.prototype.DecrypAesGcm = function (iv, tag, secret, key) {
    // Where the tag actualy is? Tag is added on end of the ciphertext.
    // So it looks like: ciphertext + tag (and this is it - no magic)

    var self = this;

    const ivBuffered = self.HexStrToByteArray(iv);
    const secretBufferd = self.HexStrToByteArray(secret);

    const alg = { name: 'AES-GCM', iv: ivBuffered, tagLength: tag };

    return new Promise(function (resolve, reject) {
        self.subtle.decrypt(alg, key, secretBufferd).then(function (plainBuffer) {
            try {
                resolve(new TextDecoder().decode(plainBuffer));
            } catch (error) {
                resolve(self.ArrayBufferToString(plainBuffer));
            }
        }).catch(function (error) {
            console.log("[CRYPTER] Exception: ");
            console.log(error);
            reject(error);
        });
    });
}

/**
 * @description Provides decryption of RSA-OAEP algorithm
 * @param {string} secret Secret in hex string
 * @param {CryptoKey} key CryptoKey for RSA-OAEP
 * @returns {Promise} Promise contains decrypted plaintext
 */
Crypter.prototype.DecrypRsaOaep = function (secret, key) {
    var self = this;

    const alg = { name: 'RSA-OAEP' };
    const secretBufferd = self.HexStrToByteArray(secret);

    return new Promise(function (resolve, reject) {
        self.subtle.decrypt(alg, key, secretBufferd).then(function (plainBuffer) {
            try {
                resolve(new TextDecoder().decode(plainBuffer));
            } catch (error) {
                resolve(self.ArrayBufferToString(plainBuffer));
            }
        }).catch(function (error) {
            console.log("[CRYPTER] Exception: ");
            console.log(error);
            reject(error);
        });
    });
}

/**
 * @description Provides SHA-256 hash
 * @param {string} plaintext Input plaintext
 * @returns {Promise} Promise contains hash
 */
Crypter.prototype.Sha256 = function (plaintext) {
    var self = this;

    return new Promise(function (resolve, reject) {

        var plaintextUtf8 = null;

        try {
            plaintextUtf8 = new TextEncoder().encode(plaintext);
        } catch (error) {
            plaintextUtf8 = self.StrToByteArray(plaintext);
        }

        //const plaintextUtf8 = new TextEncoder().encode(plaintext);

        self.subtle.digest('SHA-256', plaintextUtf8).then(function (hash) {
            resolve(hash);
        }).catch(function (error) {
            reject(error);
        });
    });
};

/**
 * @description Provides SHA-512 hash
 * @param {string} plaintext Input plaintext
 * @returns {Promise} Promise contains hash
 */
Crypter.prototype.Sha512 = function (plaintext) {
    var self = this;

    return new Promise(function (resolve, reject) {

        var plaintextUtf8 = null;

        try {
            plaintextUtf8 = new TextEncoder().encode(plaintext);
        } catch (error) {
            plaintextUtf8 = self.StrToByteArray(plaintext);
        }

        //const plaintextUtf8 = new TextEncoder().encode(plaintext);

        self.subtle.digest('SHA-512', plaintextUtf8).then(function (hash) {
            resolve(hash);
        }).catch(function (error) {
            reject(error);
        });
    });
};

/**
 * @description Provides PBKDF2 key derivation (not working now)
 * @returns {Promise} Promise contains CryptoKey
 */
Crypter.prototype.Pbkdf2Key = function (password, salt, cipher) {
    var self = this;

    return new Promise(function (resolve, reject) {
        // Import password as new key
        self.subtle.importKey(
            "raw",                              // Import type
            self.StrToByteArray(password),      // Raw password
            { name: "PBKDF2" },                 // Key type
            false,                              // If is extractable
            ["deriveKey", "deriveBits"]         // Future usage
        ).then(function (key) {
            // Derive key for specified crypto algo
            self.subtle.deriveKey(
                {
                    "name": "PBKDF2",                   // Key type
                    salt: self.HexStrToByteArray(salt), // Salt
                    iterations: 1000,                   // Iterations
                    hash: "SHA-256",                    // Hash type
                },
                key,                        // Key
                {
                    name: cipher,           // Future use crypto algo
                    length: 256,            // Future crypto algo length
                },
                false,                      // If is extractabe
                ["encrypt", "decrypt"]      // Future usage
            ).then(function (key) {
                resolve(key);
            }).catch(function (err) {
                reject(err);
            });
        }).catch(function (err) {
            console.error(err);
        });
    });
};

/**
 * @description Creates crypto key from SHA-256 hash (for cipher with 256 bit long key)
 * @param {string} password Plaintext password
 * @param {string} ciphername Specification of output key cipher type
 * @returns {Promise} Promise contains CryptoKey
 */
Crypter.prototype.Sha256Key = function (password, ciphername) {
    var self = this;

    var pwdUtf8 = "";

    try {
        pwdUtf8 = new TextEncoder().encode(password);
    } catch (error) {
        pwdUtf8 = self.StrToByteArray(password);
    }

    //const pwdUtf8 = new TextEncoder().encode(password);
    const alg = { name: ciphername };

    return new Promise(function (resolve, reject) {
        self.subtle.digest('SHA-256', pwdUtf8).then(function (pwdHash) {
            self.subtle.importKey('raw', pwdHash, alg, false, ['encrypt', 'decrypt']).then(function (key) {
                resolve(key);
            }).catch(function (error) {
                reject(error);
            });
        }).catch(function (error) {
            reject(error);
        });
    });
};

/**
 * @description Creates crypto key from raw hex key (for cipher with 256 bit long key)
 * @param {string} rawKey Raw key in hex string
 * @param {string} ciphername Specification of output key cipher type
 * @returns {Promise} Promise contains CryptoKey
 */
Crypter.prototype.RawKey = function (rawKey, ciphername) {
    var self = this;
    
    const alg = { name: ciphername };

    return new Promise(function (resolve, reject) {
        self.subtle.importKey('raw', self.HexStrToByteArray(rawKey), alg, false, ['encrypt', 'decrypt']).then(function (key) {
            resolve(key);
        }).catch(function (error) {
            reject(error);
        });
    });
}

/**
 * @description Creates crypto key from PKCS#8 format
 * @param {string} pkcs8Key PKCS#8 key
 * @param {string} ciphername Specification of output key cipher type
 * @returns {Promise} Promise contains CryptoKey
 */
Crypter.prototype.Pkcs8Key = function (pemPrivateKey, ciphername) {
    var self = this;

    return new Promise(function (resolve, reject) {
        self.subtle.importKey(
            "pkcs8",
            self.PemToByteArray(pemPrivateKey),
            {
                name: ciphername,
                hash: { name: "SHA-256" } // or SHA-512
            },
            true,
            ["decrypt"]
        ).then(function (key) {
            resolve(key);
        }).catch(function (error) {
            reject(error);
        });
    });
}

/**
 * @description Provides conversion from ByteArray to Hex string (source: MDN documantation)
 * @param {ByteArray} buffer Input ByteArray
 * @returns {string} Hex string
 */
Crypter.prototype.ArrayBufferToHexString = function (buffer) {
    var hexCodes = [];
    var view = new DataView(buffer);

    for (var i = 0; i < view.byteLength; i += 4) {
        // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
        var value = view.getUint32(i)
        // toString(16) will give the hex representation of the number without padding
        var stringValue = value.toString(16)
        // We use concatenation and slice for padding
        var padding = '00000000'
        var paddedValue = (padding + stringValue).slice(-padding.length)
        hexCodes.push(paddedValue);
    }

    // Join all the hex strings into one
    return (hexCodes.join("")).toLocaleUpperCase();
};

/**
 * @description Provides conversion from ByteArray to Hex string
 * @param {ByteArray} buffer Input ByteArray
 * @returns {string} String
 */
Crypter.prototype.ArrayBufferToString = function (buffer) {
    return String.fromCharCode.apply(null, new Uint8Array(buffer));
};

/**
 * @description Provides conversion from Hex string to Uint8Array (ByteArray)
 * @param {string} hex String hex value
 * @returns {Uint8Array}
 */
Crypter.prototype.HexStrToByteArray = function (hex) {
    var bufferLength = Math.floor(hex.length / 2);
    var byteArray = new Uint8Array(bufferLength);

    if (Math.floor(hex.length % 2) == 0) {
        for (var i = 0, y = 0; i < hex.length; i += 2, y++) {
            var strHexTuple = hex.substr(i, 2)
            byteArray[y] = parseInt(strHexTuple, 16);
        }
    } else {
        throw new Error("Hexadecimal string length error!");
    }

    return byteArray;
};

/**
 * @description Provides conversion from String to Uint8Array (ByteArray)
 * @param {string} str String value
 * @returns {Uint8Array}
 */
Crypter.prototype.StrToByteArray = function (str) {
    var bufferLength = Math.floor(str.length);
    var byteArray = new Uint8Array(bufferLength);

    for (var i = 0; i < str.length; i++) {
        byteArray[i] = str.charCodeAt(i);
    }

    return byteArray;
};

/**
 * @description Provides conversion from String encoded in Base64 to Uint8Array (ByteArray)
 * @param {string} base64String Input Base64String
 * @returns {Uint8Array}
 */
Crypter.prototype.Base64ToByteArray = function (base64String) {
    var byteString = window.atob(base64String);
    var byteArray = new Uint8Array(byteString.length);

    for (var i = 0; i < byteString.length; i++) {
        byteArray[i] = byteString.charCodeAt(i);
    }
    
    return byteArray;
}

/**
 * @description Provides conversion (unpacking) from PEM to PKCS8 DER format
 * @param {string} pem PEM certificate (private key)
 * @returns {Uint8Array}
 */
Crypter.prototype.PemToByteArray = function (pem) {
    // Remove new lines
    var b64Lines = pem.replace(/\r?\n|\r/g, "");

    // Remove header
    var b64Prefix = b64Lines.replace('-----BEGIN PRIVATE KEY-----', '');

    // Remove footer
    var b64Final = b64Prefix.replace('-----END PRIVATE KEY-----', '');

    return this.Base64ToByteArray(b64Final);
}

// Browserify export
module.exports = Crypter;

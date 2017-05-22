(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.J3A = f()}})(function(){var define,module,exports;return (function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
"use strict";

///////////////////////////////////////////////////////////////////////////////////
// Constructor / Class definition
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Some description...
 */

function Acl() {};

///////////////////////////////////////////////////////////////////////////////////
// Properties
///////////////////////////////////////////////////////////////////////////////////

Acl.prototype.resources = new Array();

///////////////////////////////////////////////////////////////////////////////////
// Methods
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Load acl resources from array to class structure
 * @param {Array} acl
 */
Acl.prototype.LoadAcl = function (acl) {
    for (var i = 0; i < acl.length; i++) {
        var resource = new Object();
        resource.resource_id = acl[i]["resource-id"];
        resource.resource_uri = acl[i]["resource-uri"];
        resource.access = acl[i]["access"];
        resource.permission = acl[i]["permission"];
        resource.secret = acl[i]["secret"];
        this.resources.push(resource);
    }
};

/**
 * @description Returns secret of specified resource
 * @param {string} id Resource ID (hex string)
 * @returns {string} Encrypted secret (hex string)
 */
Acl.prototype.GetAclResourceSecretById = function (id) {
    for (var i = 0; i < this.resources.length; i++) {
        if (this.resources[i].resource_id == id) {
            return this.resources[i].secret;
        }
    }
    return null;
};

/**
 * @description Returns permission of specified resource
 * @param {string} id Resource ID (hex string)
 * @returns {Array} List of allowed roles 
 */
Acl.prototype.GetAclResourcePermissionById = function (id) {
    for (var i = 0; i < this.resources.length; i++) {
        if (this.resources[i].resource_id == id) {
            return this.resources[i].permission;
        }
    }
};

// Browserify export
module.exports = Acl;

},{}],2:[function(require,module,exports){
"use strict";

///////////////////////////////////////////////////////////////////////////////////
// Constructor / Class definition
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Config class
 */

function Config() {};

///////////////////////////////////////////////////////////////////////////////////
// Properties
///////////////////////////////////////////////////////////////////////////////////

Config.prototype.siteName = "Unknown";
Config.prototype.uri = null;
Config.prototype.allowCache = "false";
Config.prototype.autoLogout = "true";
Config.prototype.deniedInfoElement = null;
Config.prototype.deniedInfoPage = null;
Config.prototype.filePermGroups = null;
Config.prototype.permGroups = null;
Config.prototype.uriAcl = null;
Config.prototype.uriBase = null;
Config.prototype.uriResources = null;
Config.prototype.uriRoles = null;
Config.prototype.uriVersion = null;
Config.prototype.uriUsers = null;
Config.prototype.algorithmPublicKeyEncryption = null;
Config.prototype.algorithmPrivateKeyEncryption = null;
Config.prototype.algorithmDigest = null;
Config.prototype.algorithmSign = null;
Config.prototype.algorithmKeyDerivation = null;

///////////////////////////////////////////////////////////////////////////////////
// Methods
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Loads config from config.json
 * @param {Array} config
 */
Config.prototype.LoadConfig = function (config) {
    if ("site-name" in config) {
        this.siteName = config["site-name"];
    } else {
        throw new Error("Config: Missing 'site-name'.");
    }

    if ("allow-cache" in config) {
        this.allowCache = config["allow-cache"];
    }

    if ("auto-logout" in config) {
        this.autoLogout = config["auto-logout"];
    }

    if ("denied-info-element" in config) {
        this.deniedInfoElement = config["denied-info-element"];
    } else {
        throw new Error("Config: Missing 'denied-info-element'.");
    }

    if ("denied-info-page" in config) {
        this.deniedInfoPage = config["denied-info-page"];
    } else {
        throw new Error("Config: Missing 'denied-info-page'.");
    }

    if ("file-perm-groups" in config) {
        this.filePermGroups = config["file-perm-groups"];
    }

    if ("perm-groups" in config) {
        this.permGroups = config["perm-groups"];
    }

    if ("uri-base" in config) {
        this.uriBase = config["uri-base"];
    } else {
        throw new Error("Config: Missing 'uri-base'.");
    }

    if ("uri-acl" in config) {
        this.uriAcl = config["uri-acl"];
    } else {
        throw new Error("Config: Missing 'uri-acl'.");
    }

    if ("uri-resources-dir" in config) {
        this.uriResources = config["uri-resources-dir"];
    } else {
        throw new Error("Config: Missing 'uri-resources-dir'.");
    }

    if ("uri-roles" in config) {
        this.uriRoles = config["uri-roles"];
    } else {
        throw new Error("Config: Missing 'uri-roles'.");
    }

    if ("uri-version" in config) {
        this.uriVersion = config["uri-version"];
    } else {
        throw new Error("Config: Missing 'uri-version'.");
    }

    if ("uri-users-dir" in config) {
        this.uriUsers = config["uri-users-dir"];
    } else {
        throw new Error("Config: Missing 'uri-users-dir'.");
    }

    if ("algorithms" in config) {
        if ("public-key-encryption" in config["algorithms"]) {
            this.algorithmPublicKeyEncryption = config["algorithms"]["public-key-encryption"];
        } else {
            throw new Error("Config: Missing 'public-key-encryption' in 'algorithms'.");
        }

        if ("private-key-encryption" in config["algorithms"]) {
            this.algorithmPrivateKeyEncryption = config["algorithms"]["private-key-encryption"];
        } else {
            throw new Error("Config: Missing 'private-key-encryption' in 'algorithms'.");
        }

        if ("digest" in config["algorithms"]) {
            this.algorithmDigest = config["algorithms"]["digest"];
        } else {
            throw new Error("Config: Missing 'digest' in 'algorithms'.");
        }

        if ("sign" in config["algorithms"]) {
            this.algorithmSign = config["algorithms"]["sign"];
        } else {
            throw new Error("Config: Missing 'sign' in 'algorithms'.");
        }

        if ("public-key-encryption" in config["algorithms"]) {
            this.algorithmKeyDerivation = config["algorithms"]["key-derivation"];
        } else {
            throw new Error("Config: Missing 'key-derivation' in 'algorithms'.");
        }
    } else {
        throw new Error("Config: Missing 'algorithms'.");
    }
};

/**
 * @description Returns base URI
 * @returns {string}
 */
Config.prototype.GetUriBase = function () {
    var slash = this.uriBase.substr(this.uriBase.length - 1);

    if (slash == "/") {
        return this.uriBase;
    } else if (slash == "\\") {
        return this.uriBase;
    } else {
        return this.uriBase + "/";
    }
};

/**
 * @description Returns ACL URI
 * @returns {string}
 */
Config.prototype.GetUriAcl = function () {
    return this.GetUriBase() + this.uriAcl;
};

/**
 * @description Returns Roles URI
 * @returns {string}
 */
Config.prototype.GetUriRoles = function () {
    return this.GetUriBase() + this.uriRoles;
};

/**
 * @description Returns uri of version.json file
 * @returns {string}
 */
Config.prototype.GetUriVersion = function () {
    return this.GetUriBase() + this.uriVersion;
};

/**
 * @decsription Returns Users dir URI
 * @returns {string}
 */
Config.prototype.GetUriUsers = function () {
    var slash = this.uriUsers.substr(this.uriUsers.length - 1);
    if (slash == "/") {
        return this.uriUsers;
    } else if (slash == "\\") {
        return this.uriUsers;
    } else {
        return this.uriUsers + "/";
    }
};

/**
 * @decsription Returns Resources dir URI
 * @returns {string}
 */
Config.prototype.GetUriResources = function () {
    var slash = this.uriResources.substr(this.uriResources.length - 1);
    if (slash == "/") {
        return this.uriResources;
    } else if (slash == "\\") {
        return this.uriResources;
    } else {
        return this.uriResources + "/";
    }
};

/**
 * @description Returns denied info page URI specified by username
 * @returns {string}
 */
Config.prototype.GetUriDeniedInfoPage = function () {
    return this.GetUriBase() + this.deniedInfoPage;
};

/**
 * @description Returns denied info element URI specified by username
 * @returns {string}
 */
Config.prototype.GetUriDeniedInfoElement = function () {
    return this.GetUriBase() + this.deniedInfoElement;
};

/**
 * @description Returns User json file URI specified by username
 * @returns {string}
 */
Config.prototype.GetUriUserByUsername = function (username) {
    return this.GetUriBase() + this.GetUriUsers() + username + ".json";
};

/**
 * @description Returns User json file URI specified by username
 * @returns {string}
 */
Config.prototype.GetUriResourceById = function (resourceId) {
    return this.GetUriBase() + this.GetUriResources() + resourceId + ".json";
};

// Browserify export
module.exports = Config;

},{}],3:[function(require,module,exports){
"use strict";

///////////////////////////////////////////////////////////////////////////////////
// Developer notes
///////////////////////////////////////////////////////////////////////////////////
// Chaos of crypto keys:
// =====================
// We using many kinds of cryptokeys. Because of that, we have to know where to use
// this one cryptokey and where the other. There is some description of cryptokes.
// 
// RESOURCE     --> encrypted --> key stored in ACL file (ACL resource)
// ACL RESOURCE --> encrypted --> key stored in ROLES file in specific role/roles
// ROLE         --> encrypted --> key stored in every USER file with this role
// USER         --> encrypted --> key is derivation of input password
// 
// We hope, that this is quite clear. Here is terminology:
//      Resource - encrypted part of web page
//      Acl resource - definition of resource which contains cryptokey
///////////////////////////////////////////////////////////////////////////////////

// Import modules

var Crypter = require('./crypter.js');
var Worker = require('./worker.js');
var Seed = require('./seed.js');
var Acl = require('./acl.js');
var Config = require('./config.js');
var Roles = require('./roles.js');

// Import jQuery library
//var jQuery = require('jquery');
// jQuery still has too many KB, we should use jquery/dist/jquery.min.js to reduce it.
// In a second way, we can you their map file for minimize output file.
// In a third way, we can customize our jQuery lib and insert it into lib/js (or somethig else) and use it
// Or we can use ddd-jquery, but it is pretty old one.

// There is a high probalibility that web is already using jQuery, so we use this one. It means,
// that we don't have to import big jQuery.


///////////////////////////////////////////////////////////////////////////////////
// Constructor / Class definition
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description asdfas fasdf asdfasdf
 * @property {Acl} acl asdfasdf
 * @property {Config} config asdfasd fasdf
 */
function Core() {
    if (!window.jQuery) {
        throw new Error("J3A: jQuery library is required! Import jQuery first! Newest verstion recommended.");
    }
};

///////////////////////////////////////////////////////////////////////////////////
// Properties
///////////////////////////////////////////////////////////////////////////////////

Core.prototype.acl = null;
Core.prototype.config = null;
Core.prototype.version = null;
Core.prototype.crypter = null;
Core.prototype.roles = null;
Core.prototype.seed = null;
Core.prototype.worker = null;

Core.prototype.devMode = false;
Core.prototype.prefix = null;

//Core.prototype.ready = false;
//Core.prototype.done = false;
//Core.prototype.database = "jtadb";


///////////////////////////////////////////////////////////////////////////////////
// Methods
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Initialization of Core class (loads config and acl)
 * @param {string} uriConfig URL of main configuration file
 */
Core.prototype.Init = function (uriConfig) {
    var newVersion = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
    var prefix = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : "";

    var self = this;

    this.prefix = prefix + "_";

    return new Promise(function (resolve, reject) {
        if (self.devMode) {
            console.log("[CORE] Starting initialization");
        }

        var config = window.localStorage.getItem(self.prefix + 'config');
        var acl = window.localStorage.getItem(self.prefix + 'acl');
        var roles = window.localStorage.getItem(self.prefix + 'roles');
        var version = window.localStorage.getItem(self.prefix + 'version');

        self.crypter = new Crypter();
        self.worker = new Worker();
        self.seed = new Seed(self.prefix);

        // Disallow jQuery cache --> it producing too many... errors
        jQuery.ajaxSetup({ cache: false });

        if (config == null || acl == null || roles == null || self.devMode == true || newVersion == true) {
            // Download config.json and acl.json
            if (self.devMode) {
                console.log("[CORE] Downloading config.json, acl.json and roles.json from site");
            }

            // Download config.json
            var jqxhrConfig = jQuery.getJSON(uriConfig, function (response) {
                config = response;
                self.config = new Config();
                self.config.LoadConfig(response);
            }).fail(function (error) {
                if (self.devMode) {
                    console.log("[CORE] Can't donwload 'config.json' file.");
                }
                reject(error);
            });

            // Download acl.json and roles.json after cofign download is complete
            jqxhrConfig.done(function () {

                var jqxhrVersion = jQuery.getJSON(self.config.GetUriVersion(), function (response) {
                    version = response;
                    self.version = version["page-version"];
                }).fail(function (error) {
                    if (self.devMode) {
                        console.log("[CORE] Can't donwload 'version.json' file.");
                    }
                    reject(error);
                });

                var jqxhrAcl = jQuery.getJSON(self.config.GetUriAcl(), function (response) {
                    acl = response;
                    self.acl = new Acl();
                    self.acl.LoadAcl(response);
                }).fail(function (error) {
                    if (self.devMode) {
                        console.log("[CORE] Can't donwload 'acl.json' file.");
                    }
                    reject(error);
                });

                var jqxhrRoles = jQuery.getJSON(self.config.GetUriRoles(), function (response) {
                    roles = response;
                    self.roles = new Roles();
                    self.roles.LoadRoles(response);
                }).fail(function (error) {
                    if (self.devMode) {
                        console.log("[CORE] Can't donwload 'roles.json' file.");
                    }
                    reject(error);
                });

                // Check and set cache after all downloads are complete
                jQuery.when(jqxhrAcl, jqxhrRoles, jqxhrVersion).done(function () {
                    // If cache is allowed, then add config and acl to cache
                    if (self.config.allowCache == "true") {
                        window.localStorage.setItem(self.prefix + 'version', self.version);
                        window.localStorage.setItem(self.prefix + 'config', JSON.stringify(config));
                        window.localStorage.setItem(self.prefix + 'acl', JSON.stringify(acl));
                        window.localStorage.setItem(self.prefix + 'roles', JSON.stringify(roles));
                    }

                    // Provide auto logout
                    //self.AutoLogout();

                    resolve("complete");
                });
            });
        } else {
            var newPageVersion = null;

            // Loads config and acl from cache
            if (self.devMode) {
                console.log("[CORE] Loading config, acl and roles from cache");
            }

            self.config = new Config();
            self.config.LoadConfig(JSON.parse(config));

            self.acl = new Acl();
            self.acl.LoadAcl(JSON.parse(acl));

            self.roles = new Roles();
            self.roles.LoadRoles(JSON.parse(roles));

            //self.AutoLogout();

            // Download version file
            var jqxhrVersion = jQuery.getJSON(self.config.GetUriVersion(), function (response) {
                newPageVersion = response["page-version"];
            }).fail(function (error) {
                if (self.devMode) {
                    console.log("[CORE] Can't donwload 'version.json' file.");
                }
                reject(error);
            });

            // Check version
            jQuery.when(jqxhrVersion).done(function () {
                if (newPageVersion != version) {
                    self.Init(uriConfig, true, self.prefix).then(function () {
                        resolve("complete");
                    });
                } else {
                    resolve("complete");
                }
            });
        }
    });
};

/**
 * @description Check user authorization and process web page
 * @returns {Promise}
 */
Core.prototype.RunPostProcessing = function () {
    var self = this;

    return new Promise(function (resolve, reject) {
        // No encrypted elements found - exit
        if (self.worker.LoadElements() == 0) {
            resolve("success");
        }

        // Define elements evaluation
        var evaluateElements = function evaluateElements(elements, index) {
            return new Promise(function (resolve, reject) {
                if (self.IsAuthorized(elements[index].resourceId, self.GetUser())) {
                    // Show encrypted element content
                    self.seed.GetElementById(elements[index].resourceId).then(function (element) {
                        self.worker.ReplaceElement(elements[index].resourceId, element);

                        if (index + 1 < elements.length) {
                            evaluateElements(elements, index + 1);
                            resolve("success");
                        } else {
                            resolve("success");
                        }

                        resolve("success");
                    }).catch(function (error) {
                        reject(error);
                    });
                } else {
                    // Page request denied! Proceed On Denied Action!
                    var oda = elements[index].oda;

                    if (oda == "R") {
                        window.location.href = self.config.GetUriDeniedInfoPage(); // Redirect has highest priority!
                    } else if (oda == "W") {
                        self.worker.ReplaceByWarningElement(elements[index].resourceId, self.config.GetUriDeniedInfoElement());
                    } else if (oda == "H") {
                        // Do nothing
                    } else {
                        // Unknown ODA, then redirect
                        if (self.devMode) {
                            console.log("[CORE] Warning! Unknown ODA!");
                        }
                        window.location.href = self.config.GetUriDeniedInfoPage();
                    }

                    if (index + 1 < elements.length) {
                        evaluateElements(elements, index + 1);
                        resolve("denied");
                    } else {
                        resolve("denied");
                    }
                }
            });
        };

        // Start element evaluation
        evaluateElements(self.worker.GetElements(), 0).then(function () {
            resolve();
        }).catch(function (error) {
            reject(error);
        });
    });
};

/**
 * @description Enables developer mode
 */
Core.prototype.EnableDevMode = function () {
    this.devMode = true;
};

/**
 * @description Provides login via password
 * @param {string} username Username from form
 * @param {string} password Password from form
 * @param {boolen} sli Stay logged in param
 * @returns {Promise} Return one of these success/failure
 */
Core.prototype.Login = function (username, password, sli) {
    var self = this;

    // From now on we working with promises (async downloading files)
    return new Promise(function (resolve, reject) {

        // Check config definition
        if (self.config == null) {
            if (self.devMode) {
                console.log("[CORE] Config is null, something is wrong.");
            }
            reject("failure");
        }

        // At first clear previous session
        self.PartialLogout();

        // Check params and set default values
        username = typeof username !== 'undefined' ? username : null;
        password = typeof password !== 'undefined' ? password : null;
        sli = typeof sli !== 'undefined' ? sli : false;

        // Precheck of username and password
        if (username == null || password == null) {
            if (self.devMode) {
                console.log("[CORE] Username or password is wrong...");
            }
            reject("failure");
        }

        // Get URL of user JSON database
        var uriUser = self.config.GetUriUserByUsername(username);

        // Get JSON file
        var jqxhrUser = jQuery.getJSON(uriUser, function (response) {
            // Determine cipher and get other values
            var ciphername = response["secret-algorithm"]["name"];
            var algorithm = {};
            var secret = response["secret"];
            var roles = response["roles"];

            // Get specific values for specific ciphers
            if (ciphername == "AES-GCM") {
                algorithm = {
                    name: response["secret-algorithm"]["name"],
                    iv: response["secret-algorithm"]["iv"],
                    tag: response["secret-algorithm"]["tag"]
                };
            } else {
                if (self.devMode) {
                    console.log("[CORE] Algorithm " + ciphername + "is not supported.");
                }
                reject("failure");
            }

            // We have got two types of passwords, standard text password or certificate
            if (response["key-type"] == "password") {
                // Text password operation
                self.crypter.Sha256Key(password, ciphername).then(function (key) {
                    self.crypter.Decrypt(algorithm, key, secret).then(function (plaintext) {
                        // What is a plaintext? Plaintext contains cryptokeys and
                        // algorithms from Roles. Roles contains cryptokeys from
                        // ACL resources.

                        var rolesSecrets = JSON.parse(plaintext);
                        self.GetResources(rolesSecrets).then(function (resources) {

                            // Save user token and username
                            self.crypter.Sha256(username + new Date().toDateString()).then(function (result) {
                                var logoutToken = self.crypter.ArrayBufferToHexString(result);
                                self.SaveCredentials(username, roles, logoutToken);

                                resolve("success"); // This is  the end of login process...
                            });
                        }).catch(function (error) {
                            if (self.devMode) {
                                console.log("[CORE] Exception: ");console.log(error);
                            }
                            reject("failure");
                        });
                    }).catch(function (error) {
                        if (self.devMode) {
                            console.log("[CORE] Exception: ");console.log(error);
                        }
                        reject("failure");
                    });
                }).catch(function (error) {
                    if (self.devMode) {
                        console.log("[CORE] Exception: ");console.log(error);
                    }
                    reject("failure");
                });
            } else {
                if (self.devMode) {
                    console.log("[CORE] Exception: Key is asymetric-key type");console.log(error);
                }
                reject("failure");
            }
        }).fail(function (error) {
            if (self.devMode) {
                console.log("[CORE] jQuery error:");console.log(error);
            }
            reject("failure");
        });
    });
};

/**
 * @description Provides login via certificate (PEM)
 * @param {string} username Username from form
 * @param {string} cert Certificate location from form
 * @param {boolean} sli Stay logged in param
 * @returns {Promise} Return one of these success/failure
 */
Core.prototype.LoginByPrivateKey = function (username, certificate, sli) {
    // This could be quite confusing part too. Here we using public-key algorithm
    // for encrypting secret --> secret is private-key, which is used for roles
    // secret encryption. Got it?

    // ROLES --> encrypted with AES-GCM --> AES-KEY
    // AES-KEY --> encrypted with RSA-OAEP --> we need private-key to decrypt it

    var self = this;

    return new Promise(function (resolve, reject) {
        // Check config definition
        if (self.config == null) {
            if (self.devMode) {
                console.log("[CORE] Config is null, something is wrong.");
            }
            reject("failure");
        }

        // At first clear previous session
        self.PartialLogout();

        // Check params and set default values
        username = typeof username !== 'undefined' ? username : null;
        certificate = typeof certificate !== 'undefined' ? certificate : null;
        sli = typeof sli !== 'undefined' ? sli : false;

        // Precheck of username and password
        if (username == null || certificate == null) {
            if (self.devMode) {
                console.log("[CORE] Username or password is wrong...");
            }
            reject("failure");
        }

        // Get URL of user JSON database
        var uriUser = self.config.GetUriUserByUsername(username);

        // Get JSON file
        var jqxhrUser = jQuery.getJSON(uriUser, function (response) {
            if (response["key-type"] == "certificate") {

                // Determine cipher and get other values
                var ciphername = response["secret-algorithm"]["name"]; // symetric ciphername
                var algorithm = {}; // used symetric algorithm
                var secret = response["secret"]; // roles secret
                var roles = response["roles"];

                var keySecret = response["key-secret"]; // ciphertext encrypted by public-key
                var keyAlgorithm = response["key-algorithm"]["name"]; // used asymetric algorithm

                // Get specific values for specific ciphers
                if (ciphername == "AES-GCM") {
                    algorithm = {
                        name: response["secret-algorithm"]["name"],
                        iv: response["secret-algorithm"]["iv"],
                        tag: response["secret-algorithm"]["tag"]
                    };
                } else {
                    if (self.devMode) {
                        console.log("[CORE] Algorithm " + ciphername + "is not supported.");
                    }
                    reject("failure");
                }

                // Import PCKS8 Key (PEM file format)
                self.crypter.Pkcs8Key(certificate, keyAlgorithm).then(function (key) {

                    var publicKeyAlgorithm = { name: keyAlgorithm };

                    // Decrypt secret encrypted by public-key cipher (RSA-OAEP)
                    self.crypter.Decrypt(publicKeyAlgorithm, key, keySecret).then(function (secretKey) {

                        // Now we have got a symetric secret-key so we can continue just like in stadard login procedure

                        self.crypter.RawKey(secretKey, ciphername).then(function (key) {
                            self.crypter.Decrypt(algorithm, key, secret).then(function (plaintext) {
                                // What is a plaintext? Plaintext containt cryptokeys and
                                // algorithms from Roles. Roles contains cryptokeys from
                                // ACL resources.

                                var rolesSecrets = JSON.parse(plaintext);
                                self.GetResources(rolesSecrets).then(function (resources) {

                                    // Save user token and username
                                    self.crypter.Sha256(username + new Date().toDateString()).then(function (result) {
                                        var logoutToken = self.crypter.ArrayBufferToHexString(result);
                                        self.SaveCredentials(username, roles, logoutToken);

                                        resolve("success"); // This is  the end of login process...
                                    });
                                }).catch(function (error) {
                                    if (self.devMode) {
                                        console.log("[CORE] Exception: ");console.log(error);
                                    }
                                    reject("failure");
                                });
                            }).catch(function (error) {
                                if (self.devMode) {
                                    console.log("[CORE] Exception: ");console.log(error);
                                }
                                reject("failure");
                            });
                        }).catch(function (error) {
                            if (self.devMode) {
                                console.log("[CORE] Exception: ");console.log(error);
                            }
                            reject("failure");
                        });
                    }).catch(function (error) {
                        if (self.devMode) {
                            console.log("[CORE] Exception: ");console.log(error);
                        }
                        reject("failure");
                    });
                }).catch(function (error) {
                    if (self.devMode) {
                        console.log("[CORE] Exception: ");console.log(error);
                    }
                    reject("failure");
                });
            } else {
                if (self.devMode) {
                    console.log("[CORE] Exception: Key is symetric-key type");console.log(error);
                }
                reject("failure");
            }
        }).fail(function (error) {
            if (self.devMode) {
                console.log("[CORE] jQuery error:");console.log(error);
            }
            reject("failure");
        });
    });
};

/**
 * @description Destroy database and remove all user data
 */
Core.prototype.Logout = function () {
    var self = this;

    this.ClearCredentials();
    Seed.ClearDatabase();
};

/**
 * @description Clear all records from DB (do not remove Database it self) and remove all user data
 */
Core.prototype.PartialLogout = function () {
    var self = this;

    this.ClearCredentials();
    this.seed.ClearRecords();
};

/**
 * @description Provides auto logout
 * @deprecated Since 1.0.1 This is not working properly
 */
Core.prototype.AutoLogout = function () {
    var self = this;

    // Provide auto logout
    if (this.config.autoLogout == "true") {
        // Source: W3Schools
        var name = "logoutToken=";var cookieFound = false;
        var decodedCookie = decodeURIComponent(document.cookie);
        var ca = decodedCookie.split(';');
        for (var i = 0; i < ca.length; i++) {
            var c = ca[i];
            while (c.charAt(0) == ' ') {
                c = c.substring(1);
            }

            if (c.indexOf("logoutToken=") == 0) {
                // If cookie value is not same as value in localStorage, then it's probably injected cookie, so logout.
                if (c.substring("logoutToken=".length, c.length) != window.localStorage.getItem(self.prefix + 'user_logoutToken')) {
                    this.PartialLogout();
                } else {
                    cookieFound = true;
                }
            }
        }

        // If cookie was not found, then logout (browser was previously closed)
        if (cookieFound != true) {
            this.PartialLogout();
        }
    }
};

/**
 * @description Returns current logged user, otherwise returns null
 * @returns {Array}
 */
Core.prototype.GetUser = function () {
    var self = this;

    var username = window.localStorage.getItem(this.prefix + 'user_username');
    var roles = JSON.parse(window.localStorage.getItem(this.prefix + 'user_roles'));

    if (username == null) {
        return null;
    } else {
        return { username: username, roles: roles };
    }
};

/**
 * @description [static] Returns true if someone is logged in, otherwise returns false (fast inline function)
 * @param {string} prefix Prefix which is used for initialization
 * @returns {boolen}
 */
Core.Logged = function () {
    var prefix = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "";

    var username = window.localStorage.getItem(prefix + '_' + 'user_username');

    if (username == null) {
        return false;
    } else {
        return true;
    }
};

/**
 * @description [static] Returns true if user has specified role, otherwire returns false (fast inline function)7
 * @param {string} prefix Prefix which is used for initialization
 * @param {string} roleName
 * @returns {boolean}
 */
Core.InRole = function () {
    var prefix = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "";
    var roleName = arguments[1];

    var roles = window.localStorage.getItem(prefix + '_' + 'user_roles');

    if (roles == null) {
        return false;
    }

    roles = JSON.parse(roles);
    for (var i = 0; i < roles.length; i++) {
        if (roles[i] == roleName) {
            return true;
        }
    }

    return false;
};

/**
 * @description Returns true if user is authorized, otherwise returns false
 * @param {string} resourceId Web page element resource ID (hex string)
 * @param {Dict} user User object {username: name, roles: [...]}
 * @returns {boolean}
 */
Core.prototype.IsAuthorized = function (resourceId, user) {
    var self = this;
    var resourcePermission = this.acl.GetAclResourcePermissionById(resourceId);

    if (user == null) {
        return false;
    }

    var getCompleteInheritance = function getCompleteInheritance(roleName, ilist) {
        // Get complete inheritance by recursion
        var newInher = false;

        var role = self.roles.GetRoleByName(roleName);
        for (var i = 0; i < role.inherits.length; i++) {
            if (!(role.inherits[i] in ilist)) {
                newInher = true;
                ilist.push(role.inherits[i]);
            }

            if (newInher == true) {
                newInher = false;
                ilist = getCompleteInheritance(role.inherits[i], ilist);
            }
        }

        if (!(roleName in ilist)) {
            ilist.push(roleName);
        }

        return ilist;
    };

    var completeInheritance = [];
    for (var i = 0; i < user.roles.length; i++) {
        completeInheritance = completeInheritance.concat(getCompleteInheritance(user.roles[i], []));
    }

    for (var i = 0; i < resourcePermission.length; i++) {
        for (var j = 0; j < completeInheritance.length; j++) {
            if (resourcePermission[i] == completeInheritance[j]) {
                return true;
            }
        }
    }

    return false;
};

/**
 * @description Returns base URL - main page / index.html (defined in config.json)
 * @returns {string}
 */
Core.prototype.GetBaseUrl = function () {
    var self = this;

    return this.config.GetUriBase();
};

/**
 * @description Save user credentials to local storage
 * @param {string} username
 * @param {Array} roles
 * @param {string} logoutToken
 */
Core.prototype.SaveCredentials = function (username, roles, logoutToken) {
    var self = this;

    window.localStorage.setItem(self.prefix + 'user_username', username);
    window.localStorage.setItem(self.prefix + 'user_roles', JSON.stringify(roles));
    window.localStorage.setItem(self.prefix + 'user_logoutToken', logoutToken);

    if (self.config.autoLogout == "true") {
        document.cookie = self.prefix + "logoutToken=" + logoutToken;
    }
};

/**
 * @description Removes all credentials in local storage
 */
Core.prototype.ClearCredentials = function () {
    var self = this;

    window.localStorage.removeItem(self.prefix + 'user_username');
    window.localStorage.removeItem(self.prefix + 'user_roles');
    window.localStorage.removeItem(self.prefix + 'user_logoutToken');

    document.cookie = self.prefix + "logoutToken=";
};

/**
 * @description Method provides few complex operations. In the end, all decrypted resources are stored in DB.
 * @param {Array} rolesCryptoKeys
 * @returns {Promise} success/failure
 */
Core.prototype.GetResources = function (rolesCryptoKeys) {
    var self = this;

    return new Promise(function (resolve, reject) {
        // Decrypt roles
        self.DecryptRoles(rolesCryptoKeys, 0).then(function (aclCryptoKeys) {
            // Decrypt acl
            self.DecryptAclResources(aclCryptoKeys, 0).then(function (resourcesCryptoKeys) {
                var dlResourcesCryptoKeys = self.RemoveDuplicateResources(resourcesCryptoKeys);
                var dlResourcesIds = self.ExtractIds(dlResourcesCryptoKeys);

                // Download resources
                self.DownloadResources(dlResourcesIds).then(function (encryptedResources) {
                    // Decrypt resources
                    self.DecryptResources(dlResourcesCryptoKeys, encryptedResources).then(function (decryptedElements) {
                        self.seed.Insert(decryptedElements);
                        resolve("success");
                    }).catch(function (error) {
                        reject(error);
                    });
                }).catch(function (error) {
                    reject(error);
                });
            }).catch(function (error) {
                reject(error);
            });
        }).catch(function (error) {
            reject(error);
        });
    });
};

/**
 * @description Method decrypt cryptokeys stored in roles file (each role has its own cryptokeys)
 * @param {Array} rolesCryptoKeys
 * @param {int} index
 * @returns {Promise} Array of ACL CryptoKeys
 */
Core.prototype.DecryptRoles = function (rolesCryptoKeys) {
    var index = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 0;

    var self = this;

    return new Promise(function (resolve, reject) {
        // Get encrypted keys of ACL resources
        var secret = self.roles.GetRoleSecretByName(rolesCryptoKeys[index].role);

        var role = rolesCryptoKeys[index].role;
        var algorithm = rolesCryptoKeys[index].secret.algorithm;
        var rawKey = rolesCryptoKeys[index].secret.key;

        // Import key
        self.crypter.RawKey(rawKey, algorithm.name).then(function (key) {
            // Decrypt cryptokeys of ACL resources
            self.crypter.Decrypt(algorithm, key, secret).then(function (result) {
                // Continue with recursion or end it
                if (index + 1 != rolesCryptoKeys.length) {
                    // Continue
                    self.DecryptRoles(rolesCryptoKeys, index + 1).then(function (prevResults) {
                        prevResults.push(JSON.parse(result));
                        resolve(prevResults);
                    });
                } else {
                    // End recursion
                    resolve(JSON.parse(result));
                }
            }).catch(function (error) {
                console.log("[CORE] Roles decryption error:");console.log(error);
                reject("failure");
            });
        }).catch(function (error) {
            console.log("[CORE] roles key import error:");console.log(error);
            reject("failure");
        });
    });
};

/**
 * @description Method decrypt cryptokeys stored in acl file (each acl resource has its own cryptokeys)
 * @param {Array} aclCryptoKeys
 * @param {int} index
 * @returns {Promise} Array of resources CryptoKeys
 */
Core.prototype.DecryptAclResources = function (aclCryptoKeys) {
    var index = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 0;

    var self = this;

    return new Promise(function (resolve, reject) {
        // Get encrypted keys of ACL resources
        var secret = self.acl.GetAclResourceSecretById(aclCryptoKeys[index].resource_id);

        var resource_id = aclCryptoKeys[index].resource_id;
        var algorithm = aclCryptoKeys[index].secret.algorithm;
        var rawKey = aclCryptoKeys[index].secret.key;

        // Import key
        self.crypter.RawKey(rawKey, algorithm.name).then(function (key) {
            // Decrypt cryptokeys of ACL resources
            self.crypter.Decrypt(algorithm, key, secret).then(function (result) {
                // Convert to JSON
                var convResult = JSON.parse(result);
                // Add resource identifier to result (cryptokeys and algo)
                convResult.resource_id = resource_id;

                // Continue with recursion or end it
                if (index + 1 != aclCryptoKeys.length) {
                    // Continue
                    self.DecryptAclResources(aclCryptoKeys, index + 1).then(function (prevResults) {
                        prevResults.push(convResult);
                        resolve(prevResults);
                    });
                } else {
                    // End recursion
                    resolve([convResult]);
                }
            }).catch(function (error) {
                if (self.devMode) {
                    console.log("[CORE] ACL resource decryption error:");console.log(error);
                }
                reject("failure");
            });
        }).catch(function (error) {
            if (self.devMode) {
                console.log("[CORE] ACL resources key import error:");console.log(error);
            }
            reject("failure");
        });
    });
};

/**
 * @description Method decrypt web page content stored resource file
 * @param {Array} resourcesCryptoKeys
 * @param {int} index
 * @returns {Promise} Array of resources --> { "id": res_id, "content": content }
 */
Core.prototype.DecryptResources = function (resourcesCryptoKeys, encryptedResources) {
    var index = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 0;

    var self = this;

    return new Promise(function (resolve, reject) {
        var secret = self.GetEncryptedResourceById(encryptedResources, resourcesCryptoKeys[index].resource_id);

        var resource_id = resourcesCryptoKeys[index].resource_id;
        var algorithm = resourcesCryptoKeys[index].algorithm;
        var rawKey = resourcesCryptoKeys[index].key;

        // Import key
        self.crypter.RawKey(rawKey, algorithm.name).then(function (key) {
            // Decrypt cryptokeys of ACL resources
            self.crypter.Decrypt(algorithm, key, secret).then(function (result) {
                // Convert to JSON
                var encryptedElement = Object();
                encryptedElement.resource_id = resource_id;
                encryptedElement.content = result;

                // Continue with recursion or end it
                if (index + 1 != resourcesCryptoKeys.length) {
                    // Continue
                    self.DecryptResources(resourcesCryptoKeys, encryptedResources, index + 1).then(function (prevResults) {
                        prevResults.push(encryptedElement);
                        resolve(prevResults);
                    });
                } else {
                    // End recursion
                    resolve([encryptedElement]);
                }
            }).catch(function (error) {
                if (self.devMode) {
                    console.log("[CORE] Resource decryption error:");console.log(error);
                }
                reject("failure");
            });
        }).catch(function (error) {
            if (self.devMode) {
                console.log("[CORE] Resource key import error:");console.log(error);
            }
            reject("failure");
        });
    });
};

/**
 * @description Method dowload all relevant resources
 * @param {Array} resourcesIds
 * @returns {Array}
 */
Core.prototype.DownloadResources = function (resourcesIds) {
    var index = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 0;

    // This function using recursion for async dowload all resources.
    // The question is why. First, it is simple, easy and smart.
    // Second, I really don't know if there is better solution,
    // because if I am correct, jQuery this issue solving simillary.

    var self = this;

    return new Promise(function (resolve, reject) {
        var resourceUri = self.config.GetUriResourceById(resourcesIds[index]);

        jQuery.getJSON(resourceUri, function (resource) {
            // Continue with recursion or end it
            if (index + 1 != resourcesIds.length) {
                // Continue
                self.DownloadResources(resourcesIds, index + 1).then(function (prevResources) {
                    resource.resource_id = resourcesIds[index]; // Add resource ID to result structure
                    prevResources.push(resource);
                    resolve(prevResources);
                });
            } else {
                // End recursion
                resource.resource_id = resourcesIds[index]; // Add resource ID to result structure
                resolve([resource]); // First item
            }
        }).fail(function (error) {
            reject(error);
        });
    });
};

/**
 * @description Extracts ID from input structure
 * @param {Array} structuredArray
 * @returns {Array} Contains resources IDs
 */
Core.prototype.ExtractIds = function (structuredArray) {
    var self = this;

    var ids = [];

    for (var i = 0; i < structuredArray.length; i++) {
        ids.push(structuredArray[i].resource_id);
    }

    return ids;
};

/**
 * @description Remove duplicate records in resouces array
 * @param {Array} resources
 * @returns {Array}
 */
Core.prototype.RemoveDuplicateResources = function (resources) {
    var self = this;

    // Duplicate less resources
    var dlResources = [];

    for (var i = 0; i < resources.length; i++) {
        // Occurrence
        var occ = false;

        for (var j = 0; j < dlResources.length; j++) {
            if (resources[i].resource_id == dlResources[j].resource_id) {
                occ = true;
            }
        }

        // If dlResources not contain resource, then add this resource
        if (occ == false) {
            dlResources.push(resources[i]);
        }
    }

    return dlResources;
};

/**
 * @description Returns resource specified by ID
 * @param {Array} resouces
 * @returns {string} Encrypted resource (secret)
 */
Core.prototype.GetEncryptedResourceById = function (resources, id) {
    var self = this;

    for (var i = 0; i < resources.length; i++) {
        if (resources[i].resource_id == id) {
            return resources[i].ciphertext;
        }
    }

    return null;
};

// Browserify export
module.exports = Core;

},{"./acl.js":1,"./config.js":2,"./crypter.js":4,"./roles.js":5,"./seed.js":6,"./worker.js":7}],4:[function(require,module,exports){
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
 * @description Some description...
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
};

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
};

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

    var ivBuffered = self.HexStrToByteArray(iv);
    var secretBufferd = self.HexStrToByteArray(secret);

    var alg = { name: 'AES-GCM', iv: ivBuffered, tagLength: tag };

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
};

/**
 * @description Provides decryption of RSA-OAEP algorithm
 * @param {string} secret Secret in hex string
 * @param {CryptoKey} key CryptoKey for RSA-OAEP
 * @returns {Promise} Promise contains decrypted plaintext
 */
Crypter.prototype.DecrypRsaOaep = function (secret, key) {
    var self = this;

    var alg = { name: 'RSA-OAEP' };
    var secretBufferd = self.HexStrToByteArray(secret);

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
};

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
            plaintextUtf8 = new TextEncoder().encode(password);
        } catch (error) {
            plaintextUtf8 = self.StrToByteArray(password);
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
            plaintextUtf8 = new TextEncoder().encode(password);
        } catch (error) {
            plaintextUtf8 = self.StrToByteArray(password);
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
        self.subtle.importKey("raw", // Import type
        self.StrToByteArray(password), // Raw password
        { name: "PBKDF2" }, // Key type
        false, // If is extractable
        ["deriveKey", "deriveBits"] // Future usage
        ).then(function (key) {
            // Derive key for specified crypto algo
            self.subtle.deriveKey({
                "name": "PBKDF2", // Key type
                salt: self.HexStrToByteArray(salt), // Salt
                iterations: 1000, // Iterations
                hash: "SHA-256" }, key, // Key
            {
                name: cipher, // Future use crypto algo
                length: 256 }, false, // If is extractabe
            ["encrypt", "decrypt"] // Future usage
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
    var alg = { name: ciphername };

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

    var alg = { name: ciphername };

    return new Promise(function (resolve, reject) {
        self.subtle.importKey('raw', self.HexStrToByteArray(rawKey), alg, false, ['encrypt', 'decrypt']).then(function (key) {
            resolve(key);
        }).catch(function (error) {
            reject(error);
        });
    });
};

/**
 * @description Creates crypto key from PKCS#8 format
 * @param {string} pkcs8Key PKCS#8 key
 * @param {string} ciphername Specification of output key cipher type
 * @returns {Promise} Promise contains CryptoKey
 */
Crypter.prototype.Pkcs8Key = function (pemPrivateKey, ciphername) {
    var self = this;

    return new Promise(function (resolve, reject) {
        self.subtle.importKey("pkcs8", self.PemToByteArray(pemPrivateKey), {
            name: ciphername,
            hash: { name: "SHA-256" } // or SHA-512
        }, true, ["decrypt"]).then(function (key) {
            resolve(key);
        }).catch(function (error) {
            reject(error);
        });
    });
};

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
        var value = view.getUint32(i);
        // toString(16) will give the hex representation of the number without padding
        var stringValue = value.toString(16);
        // We use concatenation and slice for padding
        var padding = '00000000';
        var paddedValue = (padding + stringValue).slice(-padding.length);
        hexCodes.push(paddedValue);
    }

    // Join all the hex strings into one
    return hexCodes.join("").toLocaleUpperCase();
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
            var strHexTuple = hex.substr(i, 2);
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
};

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
};

// Browserify export
module.exports = Crypter;

},{}],5:[function(require,module,exports){
"use strict";

///////////////////////////////////////////////////////////////////////////////////
// Constructor / Class definition
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Some description...
 * @property {Array} roles
 */

function Roles() {};

///////////////////////////////////////////////////////////////////////////////////
// Properties
///////////////////////////////////////////////////////////////////////////////////

Roles.prototype.roles = new Array();

///////////////////////////////////////////////////////////////////////////////////
// Methods
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Load roles from array to class structure
 * @param {Array} roles
 */
Roles.prototype.LoadRoles = function (roles) {
    for (var i = 0; i < roles.length; i++) {
        var role = new Object();
        role.name = roles[i]["role"];
        role.inherits = roles[i]["inherits"];
        role.secret = roles[i]["secret"];
        this.roles.push(role);
    }
};

/**
 * @description Return role object specified by name
 * @param {string} roleName
 * @returns {Dict}
 */
Roles.prototype.GetRoleByName = function (roleName) {
    for (var i = 0; i < this.roles.length; i++) {
        if (this.roles[i].name == roleName) {
            return this.roles[i];
        }
    }

    return null;
};

/**
 * @description Method getting role specified by role name
 * @param {string} role Role name
 * @returns {string} Role secret (hex value)
 */
Roles.prototype.GetRoleSecretByName = function (role) {
    for (var i = 0; i < this.roles.length; i++) {
        if (this.roles[i].name == role) {
            return this.roles[i].secret;
        }
    }

    return null;
};

/**
 * @description Returns array with role names
 * @returns {Array}
 */
Roles.prototype.GetRoleNames = function () {
    var roleNames = [];

    for (var role in this.roles) {
        roleNames.push(role.name);
    }

    return roleNames;
};

// Browserify export
module.exports = Roles;

},{}],6:[function(require,module,exports){
"use strict";

///////////////////////////////////////////////////////////////////////////////////
// Developer notes
///////////////////////////////////////////////////////////////////////////////////
// Database:
// =========
// Originaly, there was an IndexedDB API, but API was quite unstable. So new
// solution is simple usage of localStorage. It's fast, not asychronus and simple.
///////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////
// Constructor / Class definition
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Site Encrypted Elements Database
 */

function Seed(prefix) {
    this.prefix = prefix;
}

///////////////////////////////////////////////////////////////////////////////////
// Properties
///////////////////////////////////////////////////////////////////////////////////

Seed.prototype.records = [];
Seed.prototype.prefix = null;

///////////////////////////////////////////////////////////////////////////////////
// Methods
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Inserts data to database
 * @param {Array} records Array of record = {resource_id, content}
 */
Seed.prototype.Insert = function (records) {
    for (var i = 0; i < records.length; i++) {
        this.records.push(this.prefix + 'db_' + records[i].resource_id);
        window.localStorage.setItem(this.prefix + 'db_' + records[i].resource_id, records[i].content);
    }
};

/**
 * @description Find and return element specified by ID
 * @param {string} id
 * @return {Promise} Contains element content
 */
Seed.prototype.GetElementById = function (id) {
    var self = this;

    return new Promise(function (resolve, reject) {

        var search = self.prefix + 'db_' + id;
        var item = window.localStorage.getItem(search);

        if (item != null) {
            resolve(item);
        } else {
            reject("Not found.");
        }
    });
};

/**
 * @description Removes all records - not whole DB
 */
Seed.prototype.ClearRecords = function () {
    for (var i = 0; i < this.records.length; i++) {
        window.localStorage.removeItem(this.records[i]);
    }
};

/**
 * @description Clear database (inline function)
 * @param {string} database Database name
 * @returns {Promise}
 */
Seed.ClearDatabase = function () {
    var self = this;

    return new Promise(function (resolve, reject) {

        for (var i = 0; i < self.records.length; i++) {
            window.localStorage.removeItem(self.records[i]);
        }

        resolve("success");
    });
};

// Browserify export
module.exports = Seed;

///////////////////////////////////////////////////////////////////////////////////
// Old deprecated and unstable code
///////////////////////////////////////////////////////////////////////////////////

/*
function Seed(database) {
    if (!window.indexedDB) {
        throw new Error("Indexed databse API is not supported in this browser");
    }

    // Try open database
    var request = window.indexedDB.open(database);

    request.onerror = function (event) {
        console.log(event);
        throw new Error("[SEED] Unexpected error.");
    };

    var self = this;

    // If database was not created, then create new one
    request.onupgradeneeded = function (event) {
        self.database = event.target.result;
        self.objectStore = self.database.createObjectStore("EncryptedElements", { keyPath: "resource_id" });
    };

    // Everything is ok, so set database
    request.onsuccess = function (event) {
        self.database = event.target.result;
    };
}

Seed.prototype.database = null;
Seed.prototype.objectStore = null;

Seed.prototype.records = [];

Seed.prototype.Insert = function (records) {
    if (this.database == null) {
        throw new Error("[SEED] Database is not loaded!");
    }

    // Store values in the newly created objectStore.
    var eeObjectStore = this.database.transaction("EncryptedElements", "readwrite").objectStore("EncryptedElements");
    for (var i = 0; i < records.length; i++) {
        eeObjectStore.add(records[i]);
    }
}

Seed.prototype.GetElementById = function (id) {
    var self = this;

    return new Promise(function (resolve, reject) {
        var eeObjectStore = self.database.transaction(["EncryptedElements"]).objectStore("EncryptedElements");
        var request = eeObjectStore.get(id);

        // Check on error
        request.onerror = function (event) {
            console.log("[SEED] Record retrieval error!");
            reject(event);
        };

        // Return content
        request.onsuccess = function (event) {
            resolve(request.result.content);
        };
    });
}

Seed.prototype.ClearRecords = function () {
    var eeObjectStore = self.database.transaction(["EncryptedElements"], "readwrite").objectStore("EncryptedElements");
    eeObjectStore.clear();
}

Seed.ClearDatabase = function (database) {
    var self = this;

    return new Promise(function (resolve, reject) {
        var request = indexedDB.deleteDatabase(database);

        request.onerror = function () {
            console.log("Couldn't delete database");
            reject("failure")
        };

        request.onblocked = function () {
            console.log("Couldn't delete database due to the operation being blocked");
            reject("failure");
        };

        resolve("success");
    });
}
*/

},{}],7:[function(require,module,exports){
"use strict";

///////////////////////////////////////////////////////////////////////////////////
// Constructor / Class definition
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Worker class processing DOM elements
 */

function Worker() {}

///////////////////////////////////////////////////////////////////////////////////
// Properties
///////////////////////////////////////////////////////////////////////////////////

Worker.prototype.ees = null; // encrypted elements, ee == [{resourceId = id, oda = oda}, ...]


///////////////////////////////////////////////////////////////////////////////////
// Methods
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Loads all encrypted elements on current page
 * @returns {integer} Count of encrypted elements in page
 */
Worker.prototype.LoadElements = function () {
    var ees = jQuery("encrypted-element");

    this.ees = [];

    for (var i = 0; i < ees.length; i++) {
        var ee = Object();
        ee.resourceId = ees[i].getAttribute("resource-id");
        ee.oda = ees[i].getAttribute("oda");

        this.ees.push(ee);
    }

    return ees.length;
};

/**
 * @desription Returns loaded elemetns
 * @returns {Array} Array of encrypted elements
 */
Worker.prototype.GetElements = function () {
    return this.ees;
};

/**
 * @description Returns element by id (element content) or null if elements is not found
 * @param {string} id Elements id
 * @returns {string}
 */
Worker.prototype.GetElementByResourceId = function (id) {
    var ees = jQuery("encrypted-element");

    for (var i = 0; i < ees.length; i++) {
        if (id == ees[i].getAttribute("resource-id")) {
            return ees[i];
        }
    }

    return null;
};

/**
 * @description Element content is replaced by new one
 * @param {string} id Element ID
 * @param {string} content Encrypted content
 */
Worker.prototype.ReplaceElement = function (id, content) {
    var element = this.GetElementByResourceId(id);
    jQuery(element).replaceWith(content);
};

/**
 * @description Element content is replaced by access denied warning
 * @param {string} id Element ID
 * @param {string} url Warning layout url
 */
Worker.prototype.ReplaceByWarningElement = function (id, url) {
    var element = this.GetElementByResourceId(id);
    jQuery(element).load(url);
};

// Browserify export
module.exports = Worker;

},{}]},{},[3])(3)
});
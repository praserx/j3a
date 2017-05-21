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
            this.algorithmSign = config["algorithms"]["sign"]
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
}

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
}

/**
 * @description Returns denied info element URI specified by username
 * @returns {string}
 */
Config.prototype.GetUriDeniedInfoElement = function () {
    return this.GetUriBase() + this.deniedInfoElement;
}

/**
 * @description Returns User json file URI specified by username
 * @returns {string}
 */
Config.prototype.GetUriUserByUsername = function (username) {
    return (this.GetUriBase() + this.GetUriUsers() + username + ".json");
};

/**
 * @description Returns User json file URI specified by username
 * @returns {string}
 */
Config.prototype.GetUriResourceById = function (resourceId) {
    return (this.GetUriBase() + this.GetUriResources() + resourceId + ".json");
};

// Browserify export
module.exports = Config;
"use strict";

///////////////////////////////////////////////////////////////////////////////////
// Constructor / Class definition
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Some description...
 */
function Acl() {
};


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
}

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
}

// Browserify export
module.exports = Acl;


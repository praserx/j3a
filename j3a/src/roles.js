"use strict";

///////////////////////////////////////////////////////////////////////////////////
// Constructor / Class definition
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Some description...
 * @property {Array} roles
 */
function Roles() {
};


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
}

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
}

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
}

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
}

// Browserify export
module.exports = Roles;


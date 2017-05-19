"use strict";

///////////////////////////////////////////////////////////////////////////////////
// Constructor / Class definition
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description Worker class processing DOM elements
 */
function Worker() {
   
}

///////////////////////////////////////////////////////////////////////////////////
// Properties
///////////////////////////////////////////////////////////////////////////////////

Worker.prototype.ees = null;    // encrypted elements, ee == [{resourceId = id, oda = oda}, ...]


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
}

/**
 * @desription Returns loaded elemetns
 * @returns {Array} Array of encrypted elements
 */
Worker.prototype.GetElements = function () {
    return this.ees;
}

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
} 

/**
 * @description Element content is replaced by new one
 * @param {string} id Element ID
 * @param {string} content Encrypted content
 */
Worker.prototype.ReplaceElement = function (id, content) {
    var element = this.GetElementByResourceId(id);
    jQuery(element).replaceWith(content);
}

/**
 * @description Element content is replaced by access denied warning
 * @param {string} id Element ID
 * @param {string} url Warning layout url
 */
Worker.prototype.ReplaceByWarningElement = function (id, url) {
    var element = this.GetElementByResourceId(id);
    jQuery(element).load(url);
}

// Browserify export
module.exports = Worker;

"use strict";

///////////////////////////////////////////////////////////////////////////////////
// Constructor / Class definition
///////////////////////////////////////////////////////////////////////////////////

/**
 * @description 
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
 * @description 
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
 * @desription 
 * @returns {Array} Array of encrypted elements
 */
Worker.prototype.GetElements = function () {
    return this.ees;
}

/**
 * @description
 * @param
 * @returns
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
 * @description
 * @param
 * @param
 */
Worker.prototype.ReplaceElement = function (id, content) {
    var element = this.GetElementByResourceId(id);
    jQuery(element).replaceWith(content);
}

/**
 *
 */
Worker.prototype.ReplaceByWarningElement = function (id, url) {
    var element = this.GetElementByResourceId(id);
    jQuery(element).load(url);
}

// Browserify export
module.exports = Worker;

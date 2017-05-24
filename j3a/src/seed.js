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
 * @class
 * @classdesc Site Encrypted Elements Database
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
        window.localStorage.setItem(this.prefix + 'db_' + records[i].resource_id, records[i].content)
    }
}

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
}

/**
 * @description Removes all records - not whole DB
 */
Seed.prototype.ClearRecords = function () {
    for (var i = 0; i < this.records.length; i++) {
        window.localStorage.removeItem(this.records[i]);
    }
}

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
}

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
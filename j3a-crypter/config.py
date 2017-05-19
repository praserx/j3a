import codecs
import io
import json
import os
import sys

from file_worker import FileWorker

class Config(object):
    """ Config file 
    
    Json config file properties:
    ============================
    {
        "site-name": "J3A Demo",
        "uri-base": "https://praserx.github.io/j3a/demo",           // Required
        "uri-boot": "security/boot.script.html",                    // Required
        "uri-acl": "security/acl.json",                             // Required
        "uri-roles": "security/roles.json",                         // Required
        "uri-version": "security/version.json",                     // Required
        "uri-users-dir": "security/users",                          // Required
        "uri-resources-dir": "security/resources",                  // Required
        "denied-info-element": "security/deniedWarning.html",       // Required
        "denied-info-page": "security/denied.html",                 // Required
        "allow-cache": "true",                                      // Recommended, default: true
        "auto-logout": "true",                                      // Not supported, default: false
        "algorithms": {                                             // Recommended
            "public-key-encryption": "RSA-OAEP",                    // Recommended, default: RSA-OAEP
            "private-key-encryption": "AES-GCM",                    // Recommneded, default: AES-GCM
            "digest": "SHA-512",                                    // Recommended, default: SHA-512
            "sign": "",                                             // Not supported
            "key-derivation": "PBKDF2"                              // Recommended, default: PBKDF2
        },
        "perm-groups": [],                                          // Not supported
        "file-perm-groups": []                                      // Not supported
    }
    """

    def __init__(self, file, base_dir):
        """ Init Config class """

        self.fileworker = FileWorker()
        
        # Main properties (required)
        self.uri_base = base_dir
        self.uri_boot = None
        self.uri_acl = None
        self.uri_roles = None
        self.uri_version = None
        self.uri_users_dir = None
        self.uri_resources_dir = None
        self.denied_info_element = None
        self.denied_info_page = None

        # Algorithm properties (recommended)
        self.public_key_encryption = None
        self.private_key_encryption = None
        self.digest = None
        self.sign = None
        self.key_derivation = None

        # Try open file with unkown encoding (BOM is problem)
        conf = self.fileworker.open_json_file(file)

        if conf == None:
            print("Error: Can't open or parse", file, "Please, check file format.")
            exit(100)

        # Check config file required properties
        if not ("uri-boot" in conf):
            print("Error: Bad config file structure! Missing: 'uri-boot'")
            exit(100)
        if not ("uri-acl" in conf):
            print("Error: Bad config file structure! Missing: 'uri-acl'")
            exit(100)
        if not ("uri-roles" in conf):
            print("Error: Bad config file structure! Missing: 'uri-roles'")
            exit(100)
        if not ("uri-version" in conf):
            print("Error: Bad config file structure! Missing: 'uri-version'")
            exit(100)
        if not ("uri-users-dir" in conf):
            print("Error: Bad config file structure! Missing: 'uri-users-dir'")
            exit(100)
        if not ("uri-resources-dir" in conf):
            print("Error: Bad config file structure! Missing: 'uri-resources-dir'")
            exit(100)
        if not ("denied-info-element" in conf):
            print("Error: Bad config file structure! Missing: 'denied-info-element'")
            exit(100)
        if not ("denied-info-page" in conf):
            print("Error: Bad config file structure! Missing: 'denied-info-page'")
            exit(100)

        # Set config file properties
        self.uri_boot = conf["uri-boot"]
        self.uri_acl = conf["uri-acl"]
        self.uri_roles = conf["uri-roles"]
        self.uri_version = conf["uri-version"]
        self.uri_users_dir = conf["uri-users-dir"]
        self.uri_resources_dir = conf["uri-resources-dir"]
        self.denied_info_element = conf["denied-info-element"]

        # Set algorithms
        if ("algorithms" in conf):
            if ("public-key-encryption" in conf["algorithms"]):
                self.public_key_encryption = conf["algorithms"]["public-key-encryption"]
            if ("private-key-encryption" in conf["algorithms"]):
                self.private_key_encryption = conf["algorithms"]["private-key-encryption"]
            if ("digest" in conf["algorithms"]):
                self.digest = conf["algorithms"]["digest"]
            if ("sign" in conf["algorithms"]):
                self.sign = conf["algorithms"]["sign"]
            if ("key-derivation" in conf["algorithms"]):
                self.key_derivation = conf["algorithms"]["key-derivation"]
    
    def check_config(self, prefix):
        """ Check config required properties """

        if (self.public_key_encryption == "") or (self.public_key_encryption == None):
            print(prefix, "'config.json'" + " 'public-key-encryption' in 'algoritms' is not defined.")
        if (self.private_key_encryption == "") or (self.private_key_encryption == None):
            print(prefix, "'config.json'" + " 'private-key-encryption' in 'algoritms' is not defined.")
        if (self.digest == "") or (self.digest == None):
            print(prefix, "'config.json'" + " 'digest' in 'algoritms' is not defined.")
        if (self.sign == "") or (self.sign == None):
            print(prefix, "'config.json'" + " 'sign' in 'algoritms' is not defined.")
        if (self.key_derivation == "") or (self.key_derivation == None):
            print(prefix, "'config.json'" + " 'key-derivation' in 'algoritms' is not defined.")

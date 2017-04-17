import codecs
import io
import json
import os
import sys

class Config(object):
    """ Config file """

    def __init__(self, file, base_dir):
        """ Init Config class """

        #TODO   add PERM-GROUPS support
        
        self.uri_base = base_dir
        self.uri_boot = None
        self.uri_acl = None
        self.uri_roles = None
        self.uri_version = None
        self.uri_users_dir = None
        self.uri_resources_dir = None
        self.denied_info_element = None

        self.public_key_encryption = None
        self.private_key_encryption = None
        self.digest = None
        self.sign = None
        self.key_derivation = None

        # Try open file with unkown encoding (BOM is problem)
        conf = self.try_open_as_utf8(file)
        if conf == None:
           conf = self.try_open_as_utf8_bom(file)

        if conf == None:
            print("Error: Can't open or parse", file,"Please, check file format.")
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

        if not ("public-key-encryption" in conf["algorithms"]):
            print("Error: Bad config file structure! Missing: 'algorithm': 'public-key-encryption'")
            exit(100)
        if not ("private-key-encryption" in conf["algorithms"]):
            print("Error: Bad config file structure! Missing: 'algorithm': 'private-key-encryption'")
            exit(100)
        if not ("digest" in conf["algorithms"]):
            print("Error: Bad config file structure! Missing: 'algorithm': 'digest'")
            exit(100)
        if not ("sign" in conf["algorithms"]):
            print("Error: Bad config file structure! Missing: 'algorithm': 'sign'")
            exit(100)
        if not ("key-derivation" in conf["algorithms"]):
            print("Error: Bad config file structure! Missing: 'algorithm': 'key-derivation'")
            exit(100)
        
        # Set config file properties
        self.uri_boot = conf["uri-boot"]
        self.uri_acl = conf["uri-acl"]
        self.uri_roles = conf["uri-roles"]
        self.uri_version = conf["uri-version"]
        self.uri_users_dir = conf["uri-users-dir"]
        self.uri_resources_dir = conf["uri-resources-dir"]
        self.denied_info_element = conf["denied-info-element"]

        self.public_key_encryption = conf["algorithms"]["public-key-encryption"]
        self.private_key_encryption = conf["algorithms"]["private-key-encryption"]
        self.digest = conf["algorithms"]["digest"]
        self.sign = conf["algorithms"]["sign"]
        self.key_derivation = conf["algorithms"]["key-derivation"]

    def try_open_as_utf8(self, file):
        """ Method tries open file in utf-8 encoding """
        try:
            config_json = json.load(codecs.open(file, 'r', 'utf-8'))
        except:
            return None
        
        return config_json

    def try_open_as_utf8_bom(self, file):
        """ Method tries open file in utf-8 bom encoding """
        try:
            config_json = json.load(codecs.open(file, 'r', 'utf-8-sig'))
        except:
            return None
        
        return config_json

    def check_config(self):
        """ Check config required properties """
        
        if self.uri_acl == "":
            print("Warning: " + "'config.json'" + " 'uri-acl' is not defined.")
        if self.uri_roles == "":
            print("Warning: " + "'config.json'" + " 'uri-roles' is not defined.")
        if self.uri_users_dir == "":
            print("Warning: " + "'config.json'" + " 'uri-users-dir' is not defined.")
        if self.uri_resources_dir == "":
            print("Warning: " + "'config.json'" + " 'uri-resources-dir' is not defined.")

        if self.public_key_encryption == "":
            print("Warning: " + "'config.json'" + " 'public-key-encryption' in 'algoritms' is not defined.")
        if self.private_key_encryption == "":
            print("Warning: " + "'config.json'" + " 'private-key-encryption' in 'algoritms' is not defined.")
        if self.digest == "":
            print("Warning: " + "'config.json'" + " 'digest' in 'algoritms' is not defined.")
        if self.sign == "":
            print("Warning: " + "'config.json'" + " 'sign' in 'algoritms' is not defined.")
        if self.key_derivation == "":
            print("Warning: " + "'config.json'" + " 'key-derivation' in 'algoritms' is not defined.")
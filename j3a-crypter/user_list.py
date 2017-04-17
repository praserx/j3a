import base64
import binascii
import codecs
import io
import json
import os
import re
import sys

from rolelist import RoleList
from user import User
from enc_user import EncryptedUser

class UserList(object):
    """ UserList class defined in roles.json """
    
    def __init__(self, dir, rolelist: RoleList):
        """ Init UserList class """
        
        self.list = []
        self.encrypted_list = []

        self.users_dir = dir

        # Index user database (.json files)
        for file in os.listdir(dir):
            
            # Only Json user files
            if file.endswith(".json"):
               
                # Try open file with unkown encoding (BOM is problem)
                user = self.try_open_as_utf8(os.path.join(dir + '/', file).replace("\\", "/"))
                if user == None:
                   user = self.try_open_as_utf8_bom(os.path.join(dir + '/', file).replace("\\", "/"))

                if user == None:
                    print("Error: Can't open or parse '"+ file +"'. Please, check file format.")
                    exit(100)

                self.add_user(user, rolelist)

    def try_open_as_utf8(self, file):
        """ Method tries open file in utf-8 encoding """
        
        try:
            config_file = codecs.open(file, 'r', 'utf-8')
            config_json = json.load(config_file)
        except:
            config_file.close()
            return None
        
        config_file.close()
        return config_json

    def try_open_as_utf8_bom(self, file):
        """ Method tries open file in utf-8 bom encoding """
        
        try:
            config_file = codecs.open(file, 'r', 'utf-8-sig')
            config_json = json.load(config_file)
        except:
            config_file.close()
            return None
        
        config_file.close()
        return config_json

    def add_user(self, user_json, rolelist: RoleList):
        """ Append Role object to list """

        if not ("username" in user_json):
            print("Error: File format error. Missing 'username' in json file.")
            exit(100)

        if not ("key-type" in user_json):
            print("Error: File format error. Missing 'key-type' in json file.")
            exit(100)

        if "key-type" == "password":
            if not ("password" in user_json):
                print("Error: File format error. 'key-type' is 'password' but 'password' is missing.")
                exit(100)

        if "key-type" == "pem-cert":
            if not ("pem-cert" in user_json):
                print("Error: File format error. 'key-type' is 'pem-cert' but 'pem-cert' is missing.")
                exit(100)

        if "key-type" == "pem-cert":
            print("Error: Sorry but public-key cryptography is not supported yet.")
            exit(200)
        
        user_roles = []

        for role in user_json["roles"]:
            user_roles.append(rolelist.get_role_by_name(role))

        if user_json["key-type"] == "password":
            self.list.append(User(user_json["username"], user_json["key-type"], user_json["password"], user_roles))
        elif user_json["key-type"] == "pem-cert":
            self.list.append(User(user_json["username"], user_json["key-type"], user_json["pem-cert"], user_roles))
        else:
            print("Error: Unknown error. Specified key type is not supported.")
            exit(100)

    def add_encrypted_user(self, enc_user):
        """ Add encrypted user to encrypted list """

        self.encrypted_list.append(enc_user)

    def add_rck_to_user(self, role, secret):
        """ Add role cryptokey to user """

        for user in self.get_all_users_in_role(role):
            if user.secret == None:
                user.secret = [{"role": role, "secret": secret}]
            else:
                user.secret.append({"role": role, "secret": secret})

    def get_user_by_name(self, username):
        """ Return user by username """

        for user in self.list:
            if username == user.username:
                return user
        
        return None

    def get_all_users_in_role(self, role):
        """ Return all users in specific role """

        users = []

        for user in self.list:
            for urole in user.roles:
                if role == urole.name:
                    users.append(user)

        return users

    def get_key_types(self):
        """ Return all key-types """

        key_types = []

        for user in self.list:
            if not (user.key_type in key_types):
                key_types.append(user.key_type)

        return key_types

    def save(self):
        """ Save users to files """

        for user in self.encrypted_list:
            file = codecs.open(self.users_dir + "/" + user.username + ".json", "w+", "utf-8")

            roles = []

            for role in user.roles:
                roles.append(role.name)

            json_output = {
                "username": user.username,
                "roles": roles,
                "salt": user.salt,
                "secret": user.secret,
                "secret-algorithm": user.algorithm,
                "key-type": self.get_user_by_name(user.username).key_type
            }
            json.dump(json_output, file)
            file.close()

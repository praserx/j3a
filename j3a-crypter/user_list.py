import base64
import binascii
import codecs
import io
import json
import os
import re
import sys

from file_worker import FileWorker
from role_list import RoleList
from user import User
from user_encrypted import EncryptedUser

class UserList(object):
    """ UserList class defined in roles.json """
    
    def __init__(self, dir, rolelist: RoleList):
        """ Init UserList class """

        self.fileworker = FileWorker()
        
        self.list = []
        self.encrypted_list = []

        self.users_dir = dir

        # Index user database (.json files)
        for file in os.listdir(dir):
            
            # Only Json user files
            if file.endswith(".json"):
               
                # Try open file with unkown encoding (BOM is problem)
                user = self.fileworker.open_json_file(os.path.join(dir + '/', file).replace("\\", "/"))

                if user == None:
                    print("Error: Can't open or parse '"+ file +"'. Please, check file format or file encoding.")
                    exit(100)

                self.add_user(user, rolelist)

    def add_user(self, user_json, rolelist: RoleList):
        """ Append Role object to list """

        if not ("username" in user_json):
            print("Error: File format error. Missing 'username' in json file.")
            exit(100)

        if ((not ("password" in user_json)) and (not ("certificate" in user_json))):
            print("Error: File format error. Missing 'password' or 'certificate' in json file.")
            exit(100)

        if (("password" in user_json) and ("certificate" in user_json)):
            print("Error: File format error. 'password' and 'certificate' found together. Choose only one auth type.")
            exit(100)
        
        user_roles = []

        if "roles" in user_json:
            for role in user_json["roles"]:
                user_roles.append(rolelist.get_role_by_name(role))

        if "password" in user_json:
            self.list.append(User(user_json["username"], "password", user_json["password"], user_roles))
        elif "certificate" in user_json:
            self.list.append(User(user_json["username"], "certificate", user_json["certificate"], user_roles))

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

            json_output = None

            if self.get_user_by_name(user.username).key_type == "password":
                json_output = {
                    "username": user.username,
                    "roles": roles,
                    "key-type": self.get_user_by_name(user.username).key_type,
                    "key-salt": user.salt,
                    "secret": user.secret,
                    "secret-algorithm": user.algorithm,
                }

            elif self.get_user_by_name(user.username).key_type == "certificate":
                json_output = {
                    "username": user.username,
                    "roles": roles,
                    "key-type": self.get_user_by_name(user.username).key_type,
                    "key-algorithm": user.key_algorithm,
                    "key-secret": user.key_secret,
                    "secret": user.secret,
                    "secret-algorithm": user.algorithm,
                }

            json.dump(json_output, file)
            file.close()

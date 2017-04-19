import base64
import binascii
import codecs
import io
import json
import os
import sys

from role import Role
from acl import Acl
from acl_resource import AclResource

class RoleList(object):
    """ Roles class defined in roles.json """
    
    def __init__(self, file):
        """ Init Roles class """
        
        self.list = []
        self.encrypted_list = []
        self.file = file

        # Try open file with unkown encoding (BOM is problem
        roles = self.try_open_as_utf8(file)
        if roles == None:
           roles = self.try_open_as_utf8_bom(file)

        if roles == None:
            print("Error: Can't open or parse '"+ file +"'. Please, check file format.")
            exit(100)

        for role in roles:
            self.add_role(role)

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

    def save(self):
        """ Save roles to file """

        file = codecs.open(self.file, "w+", "utf-8")

        json_output = []

        for role in self.encrypted_list:
            json_output.append(
                {
                    "role": role.name,
                    "inherits": role.inherits,
                    "secret": role.secret
                }
            )

        json.dump(json_output, file)

        file.close()

    def add_role(self, role_json):
        """ Append Role object to list """

        if not ("role" in role_json):
            print("Error: File format error. Missing 'role' in json array.")
            exit(100)

        if "inherits" in role_json:
            self.list.append(Role(role_json["role"], role_json["inherits"]))
        else:
            self.list.append(Role(role_json["role"]))

    def add_encrypted_role(self, role: Role):
        """ Append Role object with encrypted secret to list """

        self.encrypted_list.append(role)

    def add_ack_to_role(self, resource_id: str, permissions: str, secret):
        """ Set secret (unencrypted) to role """

        for permission in permissions:
            # Create secret item (resource)
            resource = {
                "resource_id": resource_id,
                "secret": secret
            }

            role = self.get_role_by_name(permission).secret.append(resource)

    def compute_heredity(self):
        """ Some roles has heredity, we have to copy some resources to ensure access """

        for role in self.list:
            for irole in self.get_complete_inheritance(role, []):
                oirole = self.get_role_by_name(irole) # irole object (role_src)
                self.duplicate_resources(role, oirole) # role = role_dest, oirole = role_src
                        
    def duplicate_resources(self, role_dest, role_src):
        """ Duplicate resources from one role to other """

        if role_src == None:
            return

        for role_src_resource in role_src.secret:
            
            rcs = False
            
            for role_dest_resource in role_dest.secret:
                if role_src_resource["resource_id"] == role_dest_resource["resource_id"]:
                    rcs = True

            if rcs == False:
                role_dest.secret.append(role_src_resource)

    def get_complete_inheritance(self, role: Role, ilist):
        """ Computes complete inheritance """

        new = False

        for irole in role.inherits:
            if not (irole in ilist):
                new = True
                ilist.append(irole)

            if new == True:
                new = False
                ilist = self.get_complete_inheritance(self.get_role_by_name(irole), ilist)

        return ilist

    def role_dependancy_check(self):
        """ Check role dependency (find unknown role names) """

        roles = []
        inher = []

        for role in self.list:
            roles.append(role.name)

        for role in self.list:
            inher.extend(role.inherits)

        for i in inher:
            if not (i in roles):
                return i

        return None

    def get_role_by_name(self, role_name):
        """ Return role by role name """

        for role in self.list:
            if role_name == role.name:
                return role
        
        return None
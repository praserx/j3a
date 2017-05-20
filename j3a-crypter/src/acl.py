import binascii
import codecs
import io
import json
import os
import sys

from acl_resource import AclResource

class Acl(object):
    """ ACL class defined in acl.json """

    def __init__(self, file):
        """ Init ACL class """

        self.resources = []
        self.encrypted_resources = []
        self.file = file

    def save(self):
        """ Save encrypted ACL to file """
        
        file = codecs.open(self.file, "w+", "utf-8")

        json_output = []

        for resource in self.encrypted_resources:
            json_output.append(
                {
                    "resource-id": resource.id,
                     "resource-uri": resource.uri,
                     "access": resource.access,
                     "permission": resource.permission,
                     "secret": resource.secret
                 }
            )

        json.dump(json_output, file)

        file.close()

    def add_resource(self, resource: AclResource):
        """ Add new Acl resource to DB """
        
        self.resources.append(resource)

    def add_encrypted_resource(self, encrypted_resource):
        """ Add new encrypted ACL resource to DB """
        
        self.encrypted_resources.append(encrypted_resource)

    def get_resource_by_id(self, id):
        """ Find resource by id and return AclResource """

        for resource in self.resources:
            if resource.id == id:
                return resource

        return None
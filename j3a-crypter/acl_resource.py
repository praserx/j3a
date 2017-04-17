class AclResource(object):
    """ ACL resource class defined in acl.json 
    
    Property access_info:
    {
        "permission": [],       # roles --> admin, user, ...
        "onDenied": "redirect"  # redirect/warning
    }

    Property secret:
    {
        "algorithm": dict,      # dictionary with required values
        "key": key_material     # key string
    }
    """

    def __init__(self, id, uri, access, permission = None, secret = None):
        """ Init ACL resource class """

        self.id = id
        self.uri = uri
        self.access = access
        self.permission = permission
        self.secret = secret
class User(object):
    """ User class """
    
    def __init__(self, username, key_type, key, roles: list, secret = None):
        """ Init User class """

        self.username = username
        self.key_type = key_type
        if self.key_type == "password":
            self.password = key
        elif self.key_type == "certificate":
            self.certificate = key    # key is actually path to key
        self.roles = roles
        self.secret = secret
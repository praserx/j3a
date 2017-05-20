class Role(object):
    """ Role class defined in roles.json """
    
    def __init__(self, role, inherits = [], secret = []):
        """ Init Role class """

        self.name = role
        self.inherits = inherits
        self.secret = secret

    def set_secret(self, secret: dict):
        """ Set secret to role """
        
        self.secret = secret
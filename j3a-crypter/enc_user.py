class EncryptedUser(object):
    """ EncryptedUser class """
    
    def __init__(self, username, roles, secret = None, algorithm = None, salt = None):
        """ Init User class """

        self.username = username
        self.salt = salt
        self.roles = roles
        self.secret = secret
        self.algorithm = algorithm
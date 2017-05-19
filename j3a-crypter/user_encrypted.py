class EncryptedUser(object):
    """ EncryptedUser class """
    
    def __init__(self, username, roles, secret = None, algorithm = None, salt = None):
        """ Init User class """

        self.username = username
        self.roles = roles
        self.salt = salt
        self.secret = secret
        self.algorithm = algorithm

        self.key_algorithm = None
        self.key_secret = None
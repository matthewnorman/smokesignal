from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives.asymmetric import padding

class Crypter(object):
    """
    A library that can, when given a key, encrypt and decrypt content.
    Basically a wrapper around cryptography

    """

    def __init__(self):
        super(Crypter, self).__init__()
        self.padding = asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None)


    def encrypt(self, public_key, content):
        """
        Basic wrapper. Given a key as an object, and a piece of content,
        encrypt it.

        """

        ciphertext = public_key.encrypt(content, self.padding)
        return ciphertext

    def decrypt(self, private_key, ciphertext):
        """
        Basic wrapper. Given a key as an object, return the actual content
        of a ciphertext.
        """

        result = private_key.decrypt(ciphertext, self.padding)
        return result
                                     

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import asymmetric

class Crypter(object):
    """
    A library that can, when given a key, encrypt and decrypt content.
    Basically a wrapper around cryptography

    """


    def encrypt(self, key, content):
        """
        Basic wrapper. Given a key as an object, and a piece of content,
        encrypt it.

        """

        padding = asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None)
        ciphertext = key.encrypt(content, padding)
        return ciphertext

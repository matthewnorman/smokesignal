from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import interfaces
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_pkcs8_private_key

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
                                     
    def load_private_key(self, filename, password=None):
        """
        Given a file, load a private key

        """

        with open(filename, 'r') as f:
            data = f.read()
        key = load_pem_pkcs8_private_key(data=data, password=password,
                                         backend=default_backend())

        if not isinstance(key, interfaces.RSAPrivateKey):
            raise TypeError

        return key
        

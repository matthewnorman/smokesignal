import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import interfaces
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_pkcs8_private_key
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Crypter(object):
    """
    A library that can, when given a key, encrypt and decrypt content.
    Basically a wrapper around cryptography

    """

    def __init__(self, key_size=32):
        super(Crypter, self).__init__()
        self.padding = asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None)
        self.key_size=key_size

    def encrypt(self, public_key, content):
        """
        My own entry point for actual use. Use a symmetric key of my own
        specification to do symmetric encryption.

        """
        key = os.urandom(self.key_size)
        algorithm = algorithms.AES(key=key)
        iv = os.urandom(algorithm.block_size/8)
        cipher = Cipher(algorithms.AES(key=key), mode=modes.CFB8(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(bytes(content)) + encryptor.finalize()
        encrypted_key = self.encrypt_rsa(public_key=public_key,
                                         content=key)

        return encrypted_key, iv, ciphertext

    def decrypt(self, private_key, encrypted_key, iv, ciphertext):
        """
        Given all three necessary inputs, decrypt the symmetric key,
        create the decryptor, and decrypt the content

        """
        key = self.decrypt_rsa(private_key=private_key,
                               ciphertext=encrypted_key)
        cipher = Cipher(algorithms.AES(key=key), mode=modes.CFB8(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        content = decryptor.update(ciphertext) + decryptor.finalize()
        return content

    def encrypt_fernet(self, public_key, content):
        """
        Fernet entrypoint, take a public key from a remote source, and use
        it to symmetrically encrypt content using an underlying symmetric
        key, which is then returned.

        This is for testing dual-mode symmetric-asymmetric encryption. It
        is far too weak for actual use.

        return signature should be: encrypted_key, encrypted_content
        """
        fernet_key = Fernet.generate_key()
        fernet_crypter = Fernet(key=fernet_key)
        encrypted_content = fernet_crypter.encrypt(bytes(content))
        encrypted_key = self.encrypt_rsa(public_key=public_key,
                                         content=fernet_key)
        return encrypted_key, encrypted_content

    def decrypt_fernet(self, private_key, encrypted_key, ciphertext):
        """
        Take a generated key that was encrypted via the crytography
        fernet mechanism and use to unpack the ciphertext.

        """

        key = self.decrypt_rsa(private_key=private_key,
                               ciphertext=encrypted_key)
        fernet_crypter = Fernet(key=key)
        return fernet_crypter.decrypt(ciphertext)
        


    def encrypt_rsa(self, public_key, content):
        """
        Basic wrapper. Given a key as an object, and a piece of content,
        encrypt it.

        """

        ciphertext = public_key.encrypt(content, self.padding)
        return ciphertext

    def decrypt_rsa(self, private_key, ciphertext):
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
        

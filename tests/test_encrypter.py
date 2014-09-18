import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from smokesignal import encrypter


def test_basic_encryption():
    """
    Generate a simple RSA key and make sure that you
    can encrypt and decrypt context

    """
    crypter = encrypter.Crypter()

    content = 'This is a short string'

    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048,
                                           backend=default_backend())

    public_key = private_key.public_key()
    ciphertext = crypter.encrypt_rsa(public_key=public_key, content=content)
    result = crypter.decrypt_rsa(private_key=private_key,
                                 ciphertext=ciphertext)
    assert content == result


def test_fernet_encryption():
    """
    A short test of dual-mode encryption

    """

    content = 'This is a short string'
    crypter = encrypter.Crypter()

    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048,
                                           backend=default_backend())

    public_key = private_key.public_key()

    key, text = crypter.encrypt_fernet(public_key=public_key,
                                       content=content)
    
    result = crypter.decrypt_fernet(private_key=private_key,
                                    encrypted_key=key, ciphertext=text)
    assert result == content

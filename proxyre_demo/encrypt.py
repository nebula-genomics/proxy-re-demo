import os

from umbral import curvebn, point, utils
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# nonce size must be 12 bytes for ChaCha
# key size must be 32 bytes for Chacha
KEY_SIZE = 32
NONCE_SIZE = 12


def encrypt(plaintext, associated_data=None):
    """
    Encrypts plaintext with ChaCha20. They key used is the HKDF hash of the
    byte representation of a random point on the chosen elliptic curve.
    Returns (private_key_point, ciphertext).
    """

    nonce = os.urandom(NONCE_SIZE)
    key_point = point.Point.gen_rand()
    key = utils.kdf(key_point, KEY_SIZE)

    ciphertext = ChaCha20Poly1305(key).encrypt(nonce,
                                               plaintext,
                                               associated_data)
    return key_point, nonce + ciphertext


def decrypt(ciphertext, key, associated_data=None):
    """
    Decrypts ciphertext.
    Returns plaintext.
    """

    # the key returned by encrypt() is a point obj, has to be hashed for ChaCha
    if isinstance(key, point.Point):
        key = utils.kdf(key, KEY_SIZE)

    nonce = ciphertext[:NONCE_SIZE]
    cipher_without_nonce = ciphertext[NONCE_SIZE:]
    plaintext = ChaCha20Poly1305(key).decrypt(
        nonce, cipher_without_nonce, associated_data
    )
    return plaintext


def el_gamal_encrypt(plaintext_point, public_key_point):
    """
    ElGamal encryption.
    """
    assert plaintext_point.curve == public_key_point.curve

    generator = plaintext_point.get_generator_from_curve()
    random_num = curvebn.CurveBN.gen_rand()
    cipher_1 = generator * random_num

    cipher_2 = plaintext_point + (public_key_point * random_num)

    return cipher_1, cipher_2


def el_gamal_decrypt(cipher, priv_key):
    """
    ElGamal decryption.
    """
    cipher_1, cipher_2 = cipher
    secret = cipher_1 * priv_key.bn_key
    message = cipher_2 - secret
    return message

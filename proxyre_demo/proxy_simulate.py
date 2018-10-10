import functools

from proxyre_demo import keys
from umbral import curvebn


def generate_collective_public_key(num_nodes=10):
    """
    Simulates collective public key construction from nodes.
    Returns (collective_pub_key_point, server_priv_keys).
    """

    priv_keys = []
    pub_keys = []
    for i in range(num_nodes):
        priv_key, pub_key = keys.gen_key_pair()
        priv_keys.append(priv_key)
        pub_keys.append(pub_key)

    collective_pub_key_point = functools.reduce(lambda x, y: x + y, pub_keys)
    return collective_pub_key_point, priv_keys


def re_encrypt(cipher, server_priv_keys, delegate_public_key):
    """
    Re-encrypts an el gamal encrypted ciphertext, i.e. a (c1, c2) pair.
    The resulting (re_c1, re_c2) pair will be decryptable with the
    delegate's private key.

    Returns (re_c1, re_c2).
    """

    generator = delegate_public_key.get_generator_from_curve()

    cipher_1, cipher_2 = cipher

    re_cipher_1 = []

    for server_index, priv_key in enumerate(server_priv_keys):
        # partial decryption
        cipher_2 -= cipher_1 * priv_key.bn_key

        # this server's term in the re-encrypted cipher_1 to be given to Bob
        random_num = curvebn.CurveBN.gen_rand()
        c1 = generator * random_num
        re_cipher_1.append(c1)

        # adding this server's term in the re-encrypted cipher_2 to be given to Bob
        cipher_2 += delegate_public_key * random_num

    re_cipher_1 = functools.reduce(lambda x, y: x + y, re_cipher_1)

    return re_cipher_1, cipher_2

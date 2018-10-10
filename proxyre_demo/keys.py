from umbral import keys


def gen_key_pair():
    """
    Generate a private/public key pair using default curve.
    Returns (priv_key, pub_key)
    """
    priv_key = keys.UmbralPrivateKey.gen_key()
    pub_key = priv_key.get_pubkey().point_key
    return priv_key, pub_key

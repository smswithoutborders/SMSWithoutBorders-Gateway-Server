
#!/usr/bin/env python3

import secrets

def generate_shared_key(keysize: int=256//8) -> str:
    """Generates a shared key.

    Args:
        keysize (int): size of key (in bits) to generate (defaults to 256).

    Returns:
        key (str): Generated key.
    """

    return secrets.token_hex(nbytes=keysize)

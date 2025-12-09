from __future__ import annotations

import string
import secrets
from typing import List


def _build_alphabet(
    use_lower: bool,
    use_upper: bool,
    use_digits: bool,
    use_symbols: bool,
) -> str:
    alphabet_parts: List[str] = []

    if use_lower:
        alphabet_parts.append(string.ascii_lowercase)
    if use_upper:
        alphabet_parts.append(string.ascii_uppercase)
    if use_digits:
        alphabet_parts.append(string.digits)
    if use_symbols:
        # Restricted but typical set of symbols for passwords
        alphabet_parts.append("!@#$%^&*()-_=+[]{};:,.?/")

    return "".join(alphabet_parts)


def generate_password(
    length: int = 16,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """
    Generate a random password using cryptographically secure randomness.

    The function uses the `secrets` module which is designed for generating
    cryptographically strong random values suitable for passwords and tokens,
    unlike the `random` module which is primarily intended for simulations
    and non-security-related tasks. [web:3][web:20]
    """
    if length <= 0:
        raise ValueError("Password length must be positive.")

    alphabet = _build_alphabet(use_lower, use_upper, use_digits, use_symbols)
    if not alphabet:
        raise ValueError("At least one character class must be enabled.")

    # Use secrets.choice for cryptographically secure selection. [web:3][web:20]
    return "".join(secrets.choice(alphabet) for _ in range(length))

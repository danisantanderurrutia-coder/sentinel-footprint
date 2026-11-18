"""
HaveIBeenPwned Integration with k-Anonymity.
Allows checking whether passwords or credentials have been compromised in data breaches
without EVER exposing the password or the full hash over the network.
"""
from __future__ import annotations
import hashlib
from typing import Tuple, Optional
import requests
from sentinel.core.config import settings

HIBP_RANGE_API = "https://api.pwnedpasswords.com/range/"


def check_password_leak_k_anonymity(password: str) -> Tuple[bool, int, str]:
    """
    Check if a password has been leaked using k-Anonymity:
    1. Computes the SHA-1 hash of the password.
    2. Sends only the first 5 characters (prefix) to HIBP API.
    3. Receives a list of matching hash suffixes and occurrence counts.
    4. Searches for the remaining 35 characters locally.
    
    Returns:
        (is_leaked, leak_count, sha1_hash_prefix)
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        url = f"{HIBP_RANGE_API}{prefix}"
        response = requests.get(
            url,
            headers={"User-Agent": settings.USER_AGENT, "Add-Padding": "true"},
            timeout=settings.DEFAULT_TIMEOUT
        )
        if response.status_code != 200:
            return False, 0, prefix

        # Parse suffixes and counts
        hashes = (line.split(":") for line in response.text.splitlines())
        for h_suffix, count_str in hashes:
            if h_suffix.strip() == suffix:
                return True, int(count_str.strip()), prefix

        return False, 0, prefix
    except requests.RequestException:
        return False, 0, prefix


def explain_k_anonymity() -> str:
    """Returns an educational explanation of how k-Anonymity protects privacy."""
    return """
### ¿Cómo protege tu privacidad el modelo k-Anonymity en HIBP?

1. **Tu contraseña nunca sale de tu equipo**: Sentinel calcula el hash criptográfico SHA-1 en local.
2. **Sólo se envían los primeros 5 caracteres hexadecimales del hash**: Existen $16^5 = 1.048.576$ prefijos posibles.
3. El servidor de HaveIBeenPwned responde con una lista de cientos de sufijos que coinciden con esos 5 caracteres.
4. **La búsqueda final se hace en tu ordenador**: Sentinel compara el resto de tu hash con la lista descargada. El servidor remoto jamás sabe qué contraseña o hash completo tienes.
"""

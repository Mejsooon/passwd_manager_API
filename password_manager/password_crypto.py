import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> str:

    # Generuje nowy klucz AES-256 i zwraca go jako tekst Base64.

    key = AESGCM.generate_key(bit_length=256)

    return base64.b64encode(key).decode("ascii")


def decode_key(key_text: str) -> bytes:

    # Zamienia klucz Base64 na bytes i sprawdza, czy ma poprawną długość.

    try:
        key = base64.b64decode(key_text, validate=True,)

        if len(key) != 32:
            raise ValueError

        return key

    except Exception as exc:
        raise ValueError(
            "Nieprawidłowy klucz AES-256."
        ) from exc


def encrypt_password(key: bytes,password: str,) -> dict[str, str]:

    # Szyfruje hasło przy użyciu AES-256-GCM - zwraca (nonce + ciphertext) w formacie Base64

    nonce = os.urandom(12)
    aes = AESGCM(key)

    ciphertext = aes.encrypt(nonce, password.encode("utf-8"), None,)

    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_password(key: bytes, nonce_text: str, ciphertext_text: str,) -> str:

    # Odszyfrowuje hasło przy użyciu AES-256-GCM.


    try:
        nonce = base64.b64decode(nonce_text, validate=True,)
        ciphertext = base64.b64decode( ciphertext_text, validate=True,)

        if len(nonce) != 12:
            raise ValueError

    except Exception as exc:
        raise ValueError(
            "Nieprawidłowy nonce lub ciphertext."
        ) from exc

    try:
        aes = AESGCM(key)
        plaintext = aes.decrypt(nonce, ciphertext, None,)

        return plaintext.decode("utf-8")

    except Exception as exc:
        raise ValueError(
            "Nie można odszyfrować hasła. "
            "Sprawdź klucz, nonce oraz ciphertext."
        ) from exc
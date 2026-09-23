from fastapi import FastAPI

from password_manager.schemas import EncryptRequest, DecryptRequest
from password_manager.password_crypto import (decode_key, encrypt_password, decrypt_password, generate_key)


app = FastAPI()

@app.get("/")
def home():
    return {
        "message": "Password Manager API"
    }

@app.post("/encrypt")
def encrypt(data: EncryptRequest):

    key = decode_key(data.key)

    result = encrypt_password(key, data.password)

    return result


@app.post("/decrypt")
def decrypt(data: DecryptRequest):

    key = decode_key(data.key)

    password = decrypt_password(key, data.nonce, data.ciphertext,)

    return {"password": password}


@app.get("/generate-key")
def generate_new_key():
    return { "key": generate_key() }
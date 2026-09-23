from pydantic import BaseModel

class EncryptRequest(BaseModel):
    key: str
    password: str

class DecryptRequest(BaseModel):
    key: str
    nonce: str
    ciphertext: str
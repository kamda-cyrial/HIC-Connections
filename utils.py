from pymongo import MongoClient
from dotenv import load_dotenv
import os
import hashlib
from ecdsa import SigningKey, SECP256k1


def get_db_handle():
    load_dotenv()
    client = MongoClient(os.getenv("MONGO_STRING"))
    db_handle = client[os.getenv("DB_NAME")]
    return db_handle, client


LOGIN_DATABASE = "Users"


def get_jwt_keys():
    load_dotenv()
    passphrase = os.environ.get("KEY_PASSPHRASE")
    if not passphrase:
        raise ValueError("KEY_PASSPHRASE environment variable not set")
    passphrase_hash = hashlib.sha256(passphrase.encode()).digest()

    sk = SigningKey.from_string(passphrase_hash, curve=SECP256k1)
    vk = sk.verifying_key

    return sk.to_pem().decode("utf-8"), vk.to_pem().decode("utf-8")

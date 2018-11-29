import uuid
from passlib.hash import pbkdf2_sha256


def generate_password_hash(password):
    return pbkdf2_sha256.encrypt(password, rounds=200000, salt_size=16)


def generate_token():
    return str(uuid.uuid4())




from passlib.context import CryptContext
from datetime import timedelta, datetime
import jwt
import uuid
from src.config import Config
import logging


password_context = CryptContext(
    schemes=["bcrypt"]
)

ACCESS_TOKEN_EXPIRE = 3600


def generate_password_hash(password: str) -> str:
    hash = password_context.hash(password)

    return hash


def verify_password(password: str, hash: str) -> bool:
    return password_context.verify(password, hash)


def create_access_token(user_data: dict, expire: timedelta = None, refresh: bool = False):
    payload = {}
    payload["user"] = user_data
    payload["exp"] = datetime.now() + (expire if expire is not  None else timedelta(seconds=ACCESS_TOKEN_EXPIRE))

    payload["jti"] = str(uuid.uuid4())
    payload["refresh"] = refresh
    token = jwt.encode(
        payload=payload,
        key=Config.JWT_SECRET,
        algorithm=Config.JWT_ALGORITHM,
    )

    return token


def decode_token(token: str) -> dict:
    try:
        token_data = jwt.decode(
            jwt=token,
            key=Config.JWT_SECRET,
            algorithms=Config.JWT_ALGORITHM,
        )
        return token_data
    except jwt.PyJWTError as e:
        logging.exception(e)
        return None




import os

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.types import Text, TypeDecorator

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        key = os.environ["CREDENTIAL_ENCRYPTION_KEY"]
        _fernet = Fernet(key.encode())
    return _fernet


class EncryptedString(TypeDecorator):
    """Cifra el valor con Fernet (AES) antes de guardarlo y lo descifra al leerlo.

    La clave maestra vive fuera de la base de datos (variable de entorno), asi que
    un volcado de la BD por si solo no expone credenciales. Los valores en texto
    plano guardados antes de activar el cifrado no son tokens Fernet validos: se
    devuelven tal cual en vez de fallar, para no romper datos existentes hasta que
    el script de migracion los vuelva a guardar (y por tanto cifrar).
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return _get_fernet().encrypt(value.encode()).decode()

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        try:
            return _get_fernet().decrypt(value.encode()).decode()
        except InvalidToken:
            return value

import sys
sys.path.append(".")
import base64
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def pad(data: bytes, data_block:int) -> bytes:
    """Добавляет нулевые байты до кратности 16."""
    padding_length = (data_block - (len(data) % data_block)) % data_block
    return data + (b'\x00' * padding_length)

def unpad(padded_data: bytes) -> bytes:
    """Удаляет нулевые байты из данных."""
    return padded_data.rstrip(b'\x00')

def hash(data: str) -> str:
    result = hashlib.sha512()
    result.update(data.encode())
    return result.hexdigest()

def encode_my(key: str, InitVector: str, message: str) -> list:
    data = message.encode()
    key = base64.b64decode(key.encode())
    InitVector_1 = base64.b64decode(InitVector.encode())
    data = pad(data, 16)

    # Шифрование с использованием AES в режиме CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(InitVector_1), backend=default_backend())
    encryptor = cipher.encryptor()
    result = encryptor.update(data) + encryptor.finalize()

    result = base64.b64encode(result).decode()
    result = result + InitVector
    result = base64.b64encode(result.encode()).decode()

    message_hash = hash(result)

    return [result, message_hash]




def decode_my(key: str, message: str, message_hash: str) -> str:
    message_hash_result = hash(message)
    if message_hash_result == message_hash:
        data = base64.b64decode(message.encode())
        key = base64.b64decode(key.encode())

        # Извлекаем InitVector и сообщение
        InitVector = data[-24:]  # Предполагаем, что длина InitVector равна 24 байтам
        message = data[:-24]  # Извлекаем сообщение без вектора

        message = base64.b64decode(message)  # Декодируем сообщение
        InitVector = base64.b64decode(InitVector)  # Декодируем InitVector

        # Проверка длины сообщения перед расшифровкой
        if len(message) % 16 != 0:
            raise ValueError("Длина сообщения не кратна 16 байтам, расшифровка невозможна.")

        # Дешифрование с использованием AES в режиме CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(InitVector), backend=default_backend())
        decryptor = cipher.decryptor()
        decoded_message = decryptor.update(message) + decryptor.finalize()
        decoded_message = unpad(decoded_message)

        return decoded_message.decode()
    else:
        raise Exception("Error, the hashes don't match. Presumably the message was spoofed. Please check the connection for MITM.")
